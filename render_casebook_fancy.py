#!/usr/bin/env python3
"""
render_casebook_fancy.py — lehack2024 operator casebook style
Phosphor-green CRT aesthetic · GitHub-dark palette · Mermaid attack graph
Kill-chain replay · Per-act findings · TTP matrix · Close stamp

Usage:
    python3 render_casebook_fancy.py [--engagement engagement/] [--out casebook_JackofAllHacks_fancy.html]
"""

import argparse, re, os, html, csv, textwrap
from datetime import datetime, timezone

# ── paths ─────────────────────────────────────────────────────────────────────
CASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ENG = os.path.join(CASE_DIR, "engagement")

def read(path, default=""):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except Exception:
        return default

def yaml_get(text, key, default="—"):
    m = re.search(rf'^{re.escape(key)}\s*:\s*["\']?(.*?)["\']?\s*$', text, re.MULTILINE)
    return m.group(1).strip() if m else default

# ── minimal markdown → html ───────────────────────────────────────────────────
def inline(t):
    t = html.escape(t)
    t = re.sub(r"`([^`]+)`", r'<code>\1</code>', t)
    t = re.sub(r"\*\*(.+?)\*\*", r'<strong>\1</strong>', t)
    t = re.sub(r"\*(.+?)\*",   r'<em>\1</em>', t)
    t = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2" target="_blank">\1</a>', t)
    return t

def md2html(text):
    lines = text.splitlines(); out = []; in_code = in_table = in_ul = in_ol = False
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.strip().startswith("```"):
            if not in_code:
                out.append('<pre class="term"><code>'); in_code = True
            else:
                out.append('</code></pre>'); in_code = False
            i += 1; continue
        if in_code:
            out.append(html.escape(ln)); i += 1; continue
        if in_table and not re.match(r"^\s*\|", ln):
            out.append("</tbody></table>"); in_table = False
        if in_ul and not re.match(r"^\s*[-*]\s", ln):
            out.append("</ul>"); in_ul = False
        if in_ol and not re.match(r"^\s*\d+\.\s", ln):
            out.append("</ol>"); in_ol = False
        if m := re.match(r"^(#{1,4})\s+(.*)", ln):
            n = len(m.group(1)); txt = inline(m.group(2))
            sid = re.sub(r"[^a-z0-9]+","-", m.group(2).lower()).strip("-")
            out.append(f"<h{n} id='{sid}'>{txt}</h{n}>"); i+=1; continue
        if re.match(r"^[-*_]{3,}\s*$", ln):
            out.append("<hr>"); i+=1; continue
        if ln.startswith(">"):
            out.append(f'<blockquote>{inline(ln.lstrip(">").strip())}</blockquote>'); i+=1; continue
        if re.match(r"^\s*\|", ln):
            if not in_table:
                cells = [c.strip() for c in ln.strip().strip("|").split("|")]
                out.append('<table class="md-table"><thead><tr>'+"".join(f"<th>{inline(c)}</th>" for c in cells)+"</tr></thead><tbody>")
                in_table = True; i+=1
                if i < len(lines) and re.match(r"^\s*\|[-| :]+\|\s*$", lines[i]): i+=1
            else:
                cells = [c.strip() for c in ln.strip().strip("|").split("|")]
                out.append("<tr>"+"".join(f"<td>{inline(c)}</td>" for c in cells)+"</tr>"); i+=1
            continue
        if m := re.match(r"^\s*[-*]\s+(.*)", ln):
            if not in_ul: out.append("<ul>"); in_ul = True
            out.append(f"<li>{inline(m.group(1))}</li>"); i+=1; continue
        if m := re.match(r"^\s*\d+\.\s+(.*)", ln):
            if not in_ol: out.append("<ol>"); in_ol = True
            out.append(f"<li>{inline(m.group(1))}</li>"); i+=1; continue
        if not ln.strip():
            out.append("<br>"); i+=1; continue
        out.append(f"<p>{inline(ln)}</p>"); i+=1
    if in_code:  out.append("</code></pre>")
    if in_table: out.append("</tbody></table>")
    if in_ul:    out.append("</ul>")
    if in_ol:    out.append("</ol>")
    return "\n".join(out)

# ── parse findings from report.md ─────────────────────────────────────────────
def parse_findings(report_md):
    findings = []
    blocks = re.split(r"^###\s+", report_md, flags=re.MULTILINE)
    for block in blocks[1:]:
        lines = block.strip().splitlines()
        title = lines[0].strip()
        fid_m = re.match(r"(F\d+)\s+[—-]\s+(.+)", title)
        if not fid_m: continue
        fid, ftitle = fid_m.group(1), fid_m.group(2).strip()
        body = "\n".join(lines[1:])
        rating  = (re.search(r"Rating:\s*(\S+)", body) or re.search(r"", body))
        rating  = rating.group(1) if rating else "HIGH"
        cvss    = (re.search(r"CVSSv4:\s*([\d.]+)", body) or type("",(), {"group": lambda s,n: "—"})())
        cvss    = cvss.group(1)
        cwe     = (re.search(r"CWE:\s*(\S+)", body) or type("",(), {"group": lambda s,n: "—"})())
        cwe     = cwe.group(1)
        mitre   = (re.search(r"MITRE:\s*(.+)", body) or type("",(), {"group": lambda s,n: "—"})())
        mitre   = mitre.group(1).strip()
        hosts   = (re.search(r"Hosts:\s*(.+)", body) or type("",(), {"group": lambda s,n: "—"})())
        hosts   = hosts.group(1).strip()
        status  = (re.search(r"Status:\s*(.+)", body) or type("",(), {"group": lambda s,n: "—"})())
        status  = status.group(1).strip()
        rem_m   = re.search(r"#### Remediation\n(.*?)(?=\n---|\Z)", body, re.DOTALL)
        remediation = rem_m.group(1).strip() if rem_m else ""
        # strip metadata lines from body for prose
        prose = re.sub(r"^(Rating|CVSSv4|CWE|MITRE|Hosts|Status):[^\n]*\n?", "", body, flags=re.MULTILINE)
        prose = re.sub(r"#### Remediation.*", "", prose, flags=re.DOTALL).strip()
        findings.append({"id":fid,"title":ftitle,"rating":rating,"cvss":cvss,
                         "cwe":cwe,"mitre":mitre,"hosts":hosts,"status":status,
                         "prose":prose,"remediation":remediation})
    return findings

def parse_timeline(tl_md):
    phases = []
    current = None
    for line in tl_md.splitlines():
        if m := re.match(r"^##\s+(.+)", line):
            current = {"name": m.group(1).strip(), "events": []}
            phases.append(current)
            continue
        if current and re.match(r"^\s*\|", line) and not re.match(r"^\s*\|[-| :]+\|\s*$", line):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if cells and cells[0].strip().lower() not in ("utc","time",""):
                current["events"].append(cells)
    return phases

def parse_hosts(hosts_csv):
    hosts = []
    try:
        reader = csv.DictReader(hosts_csv.splitlines())
        for row in reader:
            hosts.append(row)
    except Exception:
        pass
    return hosts

def parse_chains(report_md):
    m = re.search(r"## Attack Chains\n(.*?)(?=\n##|\Z)", report_md, re.DOTALL)
    if not m: return []
    text = m.group(1).strip()
    chains = []
    for block in re.split(r"\n### ", text):
        if not block.strip(): continue
        lines = block.strip().splitlines()
        title = lines[0].strip("# ").strip()
        body = "\n".join(lines[1:]).strip()
        status = "cleared" if "COMPLETE" in body else "partial"
        chains.append({"title": title, "body": body, "status": status})
    return chains

def parse_dead_ends(report_md):
    m = re.search(r"## Dead Ends\n(.*?)(?=\n##|\Z)", report_md, re.DOTALL)
    if not m: return []
    items = []
    for line in m.group(1).strip().splitlines():
        if line.strip().startswith("-"):
            items.append(line.strip("- ").strip())
    return items

def parse_strengths(report_md):
    m = re.search(r"## Summary of Strengths\n(.*?)(?=\n##|\Z)", report_md, re.DOTALL)
    if not m: return []
    items = []
    for line in m.group(1).strip().splitlines():
        if line.strip().startswith("-"):
            items.append(line.strip("- ").strip())
    return items

# ── severity helpers ──────────────────────────────────────────────────────────
SEV_COLOR = {"CRITICAL":"#ff3b3b","HIGH":"#ffb800","MEDIUM":"#c084fc",
             "LOW":"#58a6ff","INFO":"#8b949e"}
ROLE_COLOR = {"entry":"#58a6ff","DC":"#ff3b3b","pivot":"#ffb800",
              "victim":"#c084fc","cloud":"#00ff9c","member":"#8b949e"}

def sev_badge(rating):
    c = SEV_COLOR.get(rating.upper(), "#8b949e")
    return f'<span class="sev-badge" style="background:{c}20;color:{c};border:1px solid {c}40">{rating.upper()}</span>'

# ── MITRE tactics (derived from report) ──────────────────────────────────────
MITRE_DATA = [
    ("Initial Access","T1190","Exploit Public-Facing Application","CheckStatus.aspx OS command injection by 172.236.127.251"),
    ("Execution","T1569.002","Service Execution","rnSylwOz.exe launched via ADMIN$ remote service (Impacket)"),
    ("Execution","T1059.001","PowerShell","Attacker shells under injected explorer.exe"),
    ("Execution","T1059.003","Windows Command Shell","cmd.exe PID 15116/15080 spawned from injected explorer"),
    ("Execution","T1053.005","Scheduled Task/Job","OlgyLYbd task triggered sysAV.bat ransomware chain"),
    ("Persistence","T1136.002","Create Domain Account","LAF\\serviceaccount → Domain Admins at 20:03:05"),
    ("Persistence","T1547.012","Image File Execution Options","taskmgr.exe Debugger = aws_backup.exe on WS01"),
    ("Persistence","T1546.013","PowerShell Profile","DC02 PS profile shellcode (created 21:00:21)"),
    ("Privilege Escalation","T1574.009","Path Interception: Unquoted Path","SolarwindsTFTP unquoted path → SYSTEM"),
    ("Privilege Escalation","T1098","Account Manipulation","serviceaccount added to Domain Admins"),
    ("Defense Evasion","T1055","Process Injection","Beacon injected into explorer.exe PID 1332; SHA256 6ef6b52f…"),
    ("Defense Evasion","T1070.003","Clear Command History","LogDel.bat executed at 21:08:28"),
    ("Defense Evasion","T1112","Modify Registry","DisableRestrictedAdmin set on WS02 at 21:57:07"),
    ("Credential Access","T1003.001","LSASS Memory","abedgdaa.dmp (12.2 MB) via comsvcs on SVR01"),
    ("Credential Access","T1003.003","NTDS","VSS copy → ZIFylmKF.tmp; Impacket secretsdump services"),
    ("Credential Access","T1552.004","Private Keys","IMDS SSRF → iam_role_iisserver EC2 creds exfil"),
    ("Discovery","T1046","Network Service Discovery","Advanced IP Scanner 2.5.4594 on DC02 at 20:46:03"),
    ("Lateral Movement","T1021.002","Remote Services: SMB/Windows Admin Shares","Impacket psexec ADMIN$ to DC01/SVR01"),
    ("Lateral Movement","T1021.001","Remote Desktop Protocol","SVR01→DC02; RED1→WS01/WS02 as Donny/Dalton"),
    ("Collection","T1560.001","Archive Collected Data","msupdate.exe (Makecab) → Data.cab"),
    ("Exfiltration","T1048","Exfiltration Over Alternative Protocol","FileZilla SFTP to 172.236.127.251:22; 164 S3 GetObject"),
    ("Impact","T1486","Data Encrypted for Impact","IamBatman.exe .bWqQUx ransomware across all 5 hosts"),
    ("Impact","T1490","Inhibit System Recovery","vssadmin delete shadows /all /quiet before encryption"),
]

# ── kill-chain replay events ──────────────────────────────────────────────────
REPLAY_EVENTS = [
    ("18:38","IIS-SERV-PROD","recon","Attacker browses target · Firefox on Kali"),
    ("18:40","IIS-SERV-PROD","recon","First OS command injection: url=Google.com | whoami"),
    ("18:45","IIS-SERV-PROD","recon","Enumerates SolarwindsTFTP unquoted service path"),
    ("18:51","IIS-SERV-PROD","foothold","certutil downloads so.aspx webshell from C2"),
    ("18:52","IIS-SERV-PROD","foothold","certutil downloads iis.exe C2 beacon"),
    ("19:08","IIS-SERV-PROD","foothold","Webshell activated — curl/8.5.0 POST sessions begin"),
    ("19:38","IIS-SERV-PROD","foothold","SolarwindsTFTP hijack → SYSTEM on IIS"),
    ("19:59","LAF-SVR01","foothold","rnSylwOz.exe launched from ADMIN$ — C2 173.230.136.180:8443"),
    ("20:01","LAF-SVR01","lateral","explorer.exe injected · beacon established"),
    ("20:02","LAF-SVR01","cred","net user serviceaccount P@ssw0RD1! /add /domain"),
    ("20:03","LAF-DC01","pwn","serviceaccount → Domain Admins · DOMAIN OWNED"),
    ("20:03","LAF-SVR01","cred","LSASS dump → abedgdaa.dmp"),
    ("20:08","LAF-DC01","cred","Impacket smbexec · 5 random-name services installed"),
    ("20:09","LAF-DC01","cred","VSS copy ntds.dit → ZIFylmKF.tmp"),
    ("20:14","LAF-SVR01","lateral","RED1 RDP session opened on SVR01"),
    ("20:16","LAF-WS01","lateral","LAFAdmin Type-3 logon from SVR01"),
    ("20:20","LAF-SVR01","cred","msupdate.exe (Makecab) → Data.cab file collection"),
    ("20:35","LAF-WS01","lateral","RED1 RDP as Donny (Type 10) · interactive session"),
    ("20:37","LAF-WS01","lateral","aws_backup.exe dropped · IFEO persistence set"),
    ("20:46","LAF-DC02","lateral","Advanced IP Scanner downloaded · network scan"),
    ("21:00","LAF-DC02","lateral","PowerShell profile shellcode persistence installed"),
    ("21:08","LAF-SVR01","lateral","LogDel.bat — event log clearing"),
    ("21:42","AWS","pwn","GetCallerIdentity — AWS whoami with stolen EC2 creds"),
    ("21:49","AWS","pwn","164 × S3 GetObject — data exfiltration to 212.8.249.213"),
    ("21:57","LAF-WS02","lateral","DisableRestrictedAdmin set (PtH-over-RDP)"),
    ("22:06","LAF-DC02","lateral","SVR01 → DC02 outbound RDP"),
    ("22:08","LAF-WS02","pwn","FIRST ENCRYPTION — .bWqQUx · WS02 · ransomware begins"),
    ("22:09","LAF-WS01","pwn","vssadmin delete shadows · IamBatman.exe encrypt C:\\"),
    ("22:10","LAF-DC01","pwn","DC01 encrypted · domain controllers down"),
    ("22:30","LAF-SVR01","lateral","RED1 reconnects via RDP to SVR01"),
    ("22:46","LAF-SVR01","pwn","Memory captured — investigation begins"),
]

HOSTS_ALL = ["IIS-SERV-PROD","LAF-SVR01","LAF-DC01","LAF-DC02","LAF-WS01","LAF-WS02","AWS"]
PHASE_COLOR = {"recon":"#58a6ff","foothold":"#ffb800","cred":"#c084fc","lateral":"#c084fc","pwn":"#ff3b3b"}

# ── CSS ───────────────────────────────────────────────────────────────────────
CSS = r"""
@import url('https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,400;0,9..144,700;1,9..144,400&family=IBM+Plex+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap');

:root{
  --bg:#05070a;--bg1:#0b0f14;--panel:#0e1319;
  --green:#00ff9c;--red:#ff3b3b;--amber:#ffb800;
  --cyan:#58a6ff;--violet:#c084fc;--text:#e6edf3;--muted:#8b949e;
  --border:#21262d;
}
*{box-sizing:border-box;margin:0;padding:0}

body{
  font-family:'Inter',system-ui,sans-serif;
  background:var(--bg);color:var(--text);
  line-height:1.65;font-size:14px;
  min-height:100vh;
}

/* CRT scanlines */
body::after{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:1000;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.04) 2px,rgba(0,0,0,.04) 4px);
}
/* vignette */
body::before{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:999;
  background:radial-gradient(ellipse at 50% 50%,transparent 60%,rgba(0,0,0,.55) 100%);
}

a{color:var(--cyan);text-decoration:none}
a:hover{text-decoration:underline}
code{font-family:'IBM Plex Mono',monospace;font-size:.85em;
  background:#161b22;color:var(--green);padding:2px 6px;border-radius:3px}
strong{color:#f0f6fc}

/* ── HAMBURGER NAV ── */
#nav-toggle{
  position:fixed;top:18px;right:20px;z-index:500;
  background:var(--panel);border:1px solid var(--border);
  color:var(--green);font-family:'IBM Plex Mono',monospace;
  font-size:12px;padding:7px 14px;cursor:pointer;border-radius:3px;
  letter-spacing:.06em;
}
#nav-toggle:hover{background:#1c2128}
#nav-drawer{
  position:fixed;top:0;right:-320px;width:300px;height:100vh;
  background:var(--bg1);border-left:1px solid var(--border);
  z-index:600;transition:.3s ease;overflow-y:auto;padding:20px;
}
#nav-drawer.open{right:0}
#nav-close{
  position:absolute;top:16px;right:16px;background:none;border:none;
  color:var(--muted);font-size:18px;cursor:pointer;
}
#nav-drawer h3{font-family:'IBM Plex Mono',monospace;color:var(--green);
  font-size:11px;letter-spacing:.12em;text-transform:uppercase;margin-bottom:16px}
.nav-item{display:block;padding:7px 10px;color:var(--muted);font-size:13px;
  border-left:2px solid transparent;margin:2px 0;border-radius:0 3px 3px 0}
.nav-item:hover{color:var(--text);border-left-color:var(--green);
  background:#ffffff08;text-decoration:none}
.nav-num{font-family:'IBM Plex Mono',monospace;color:var(--green);
  font-size:10px;margin-right:8px}

/* ── HERO ── */
#hero{
  min-height:100vh;display:flex;flex-direction:column;
  justify-content:center;align-items:center;
  padding:60px 24px;text-align:center;
  background:linear-gradient(180deg,#05070a 0%,#0a0e14 100%);
  position:relative;
}
.hero-tag{
  font-family:'IBM Plex Mono',monospace;font-size:11px;
  letter-spacing:.2em;text-transform:uppercase;color:var(--green);
  margin-bottom:24px;
}
.hero-title{
  font-family:'Fraunces',serif;font-size:clamp(42px,7vw,88px);
  font-weight:700;line-height:1.05;letter-spacing:-.02em;
  color:var(--text);margin-bottom:8px;
}
.hero-title em{color:var(--green);font-style:normal;
  text-shadow:0 0 40px rgba(0,255,156,.35)}
.hero-sub{
  font-family:'IBM Plex Mono',monospace;font-size:13px;
  color:var(--muted);margin-bottom:48px;letter-spacing:.04em
}
.dossier{
  display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));
  gap:1px;background:var(--border);
  max-width:960px;width:100%;
  border:1px solid var(--border);border-radius:4px;overflow:hidden;
  margin-bottom:40px;
}
.dos-cell{background:var(--panel);padding:12px 16px;text-align:left}
.dos-cell .label{font-family:'IBM Plex Mono',monospace;font-size:9px;
  letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:4px}
.dos-cell .val{font-size:13px;color:var(--text);font-weight:500}
.dos-cell .val.green{color:var(--green)}
.dos-cell .val.red{color:var(--red)}
.dos-cell .val.amber{color:var(--amber)}
.scoreboard{
  display:flex;gap:0;border:1px solid var(--border);border-radius:4px;
  overflow:hidden;max-width:660px;width:100%
}
.score-cell{flex:1;padding:14px 10px;text-align:center;background:var(--panel)}
.score-cell+.score-cell{border-left:1px solid var(--border)}
.score-cell .s-num{font-family:'IBM Plex Mono',monospace;font-size:28px;
  font-weight:700;line-height:1}
.score-cell .s-lbl{font-size:10px;letter-spacing:.08em;
  text-transform:uppercase;color:var(--muted);margin-top:4px}
.stamp{
  font-family:'IBM Plex Mono',monospace;font-size:10px;
  letter-spacing:.18em;text-transform:uppercase;
  color:var(--green);border:1px solid var(--green);
  padding:4px 14px;margin-top:32px;opacity:.7;
}

/* ── SECTIONS ── */
.section{padding:80px 24px;max-width:1000px;margin:0 auto}
.sec-label{
  font-family:'IBM Plex Mono',monospace;font-size:10px;
  letter-spacing:.2em;text-transform:uppercase;color:var(--green);
  margin-bottom:8px;
}
.sec-label::before{content:'// ';opacity:.5}
.section h2{
  font-family:'Fraunces',serif;font-size:clamp(28px,4vw,44px);
  font-weight:700;color:var(--text);margin-bottom:32px;line-height:1.1
}
.divider{border:none;border-top:1px solid var(--border);margin:60px 0}

/* ── SEVERITY BANNER ── */
.sev-banner{
  display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));
  gap:12px;margin:32px 0;
}
.sev-cell{background:var(--panel);border:1px solid var(--border);
  border-radius:4px;padding:14px 16px}
.sev-cell .sv-label{font-size:10px;letter-spacing:.08em;
  text-transform:uppercase;color:var(--muted);margin-bottom:4px}
.sev-cell .sv-val{font-family:'IBM Plex Mono',monospace;font-size:16px;font-weight:600}
.sev-cell.red .sv-val{color:var(--red)}
.sev-cell.amber .sv-val{color:var(--amber)}
.sev-cell.green .sv-val{color:var(--green)}
.sev-cell.cyan .sv-val{color:var(--cyan)}
.sev-cell.violet .sv-val{color:var(--violet)}

/* ── ROOT CAUSES ── */
.root-causes{margin:24px 0}
.root-row{display:flex;gap:16px;padding:12px 0;border-bottom:1px solid var(--border)}
.root-row:last-child{border-bottom:none}
.root-ctrl{min-width:180px;font-weight:600;color:var(--text)}
.root-fail{color:var(--muted);font-size:13px}

/* ── ROADMAP ── */
.roadmap{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:24px 0}
.rm-card{background:var(--panel);border:1px solid var(--border);
  border-radius:4px;padding:16px}
.rm-card h4{font-family:'IBM Plex Mono',monospace;font-size:11px;
  letter-spacing:.1em;text-transform:uppercase;margin-bottom:10px}
.rm-card.p0 h4{color:var(--red)}
.rm-card.p1 h4{color:var(--amber)}
.rm-card.p2 h4{color:var(--cyan)}
.rm-card ul{list-style:none;padding:0}
.rm-card li{padding:4px 0;font-size:13px;color:var(--muted);
  border-bottom:1px solid #ffffff08}
.rm-card li::before{content:'› ';color:inherit}
.rm-card.p0 li::before{color:var(--red)}
.rm-card.p1 li::before{color:var(--amber)}
.rm-card.p2 li::before{color:var(--cyan)}

/* ── STORY STATS ── */
.story-stats{
  display:flex;gap:0;background:var(--panel);border:1px solid var(--border);
  border-radius:4px;overflow:hidden;margin:28px 0
}
.ss-cell{flex:1;padding:16px 12px;text-align:center}
.ss-cell+.ss-cell{border-left:1px solid var(--border)}
.ss-val{font-family:'IBM Plex Mono',monospace;font-size:22px;
  font-weight:700;color:var(--green)}
.ss-lbl{font-size:10px;letter-spacing:.08em;text-transform:uppercase;
  color:var(--muted);margin-top:4px}

/* ── TIMELINE ── */
.phase-block{margin:32px 0}
.phase-label{
  font-family:'IBM Plex Mono',monospace;font-size:10px;
  letter-spacing:.15em;text-transform:uppercase;
  color:var(--amber);margin-bottom:12px;padding-bottom:8px;
  border-bottom:1px solid var(--border)
}
.tl-table{width:100%;border-collapse:collapse}
.tl-table th{
  text-align:left;font-family:'IBM Plex Mono',monospace;
  font-size:10px;letter-spacing:.08em;text-transform:uppercase;
  color:var(--muted);padding:6px 12px;border-bottom:1px solid var(--border)
}
.tl-table td{padding:9px 12px;border-bottom:1px solid #ffffff06;font-size:13px;vertical-align:top}
.tl-table tr:hover td{background:#ffffff04}
.tl-time{font-family:'IBM Plex Mono',monospace;color:var(--amber);white-space:nowrap}
.tl-host{color:var(--cyan);font-weight:500;white-space:nowrap}

/* ── ATTACK GRAPH ── */
#sec-graph .section{padding-bottom:0}
.graph-wrap{
  background:var(--panel);border:1px solid var(--border);
  border-radius:4px;padding:24px;margin:24px 0;
  overflow-x:auto;min-height:300px
}
.mermaid{font-family:'IBM Plex Mono',monospace}

/* ── KILL-CHAIN REPLAY ── */
.replay-shell{
  background:var(--bg1);border:1px solid var(--border);
  border-radius:6px;overflow:hidden;margin:24px 0
}
.replay-header{
  background:#0d1117;border-bottom:1px solid var(--border);
  padding:10px 16px;display:flex;align-items:center;gap:8px
}
.replay-dot{width:12px;height:12px;border-radius:50%}
.replay-inner{display:grid;grid-template-columns:260px 1fr;min-height:320px}
.host-rail{
  background:var(--bg);border-right:1px solid var(--border);padding:16px 12px
}
.host-rail h4{font-family:'IBM Plex Mono',monospace;font-size:9px;
  letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:12px}
.host-chip{
  padding:7px 12px;border-radius:3px;margin:4px 0;font-size:12px;
  font-family:'IBM Plex Mono',monospace;background:#161b22;
  border:1px solid var(--border);color:var(--muted);
  transition:.4s;cursor:default;
}
.host-chip.active{color:var(--amber);border-color:var(--amber);
  background:#ffb80012;box-shadow:0 0 8px rgba(255,184,0,.2)}
.host-chip.pwned{color:var(--red);border-color:var(--red);
  background:#ff3b3b12;box-shadow:0 0 8px rgba(255,59,59,.2)}
.event-feed{padding:16px;overflow-y:auto;max-height:380px;font-size:12px}
.ev-row{
  display:flex;gap:12px;padding:7px 0;border-bottom:1px solid #ffffff06;
  opacity:.35;transition:.3s
}
.ev-row.fired{opacity:1}
.ev-row.current{opacity:1;background:#ffffff08;border-radius:3px;padding-left:6px}
.ev-dot{width:8px;height:8px;border-radius:50%;margin-top:3px;flex-shrink:0}
.ev-time{font-family:'IBM Plex Mono',monospace;color:var(--muted);white-space:nowrap}
.ev-host{color:var(--cyan);white-space:nowrap;font-weight:600}
.ev-desc{color:var(--text)}
.transport{
  background:#0d1117;border-top:1px solid var(--border);
  padding:12px 16px;display:flex;align-items:center;gap:12px
}
.tp-btn{
  background:var(--panel);border:1px solid var(--border);
  color:var(--text);padding:6px 14px;border-radius:3px;cursor:pointer;
  font-family:'IBM Plex Mono',monospace;font-size:13px
}
.tp-btn:hover{border-color:var(--green);color:var(--green)}
.tp-btn.active{background:#00ff9c18;border-color:var(--green);color:var(--green)}
.tp-speed{font-family:'IBM Plex Mono',monospace;font-size:11px;
  color:var(--muted);margin-left:4px}
.scrub-wrap{flex:1;position:relative;height:4px;background:var(--border);
  border-radius:2px;cursor:pointer}
.scrub-fill{height:100%;background:var(--green);border-radius:2px;transition:.1s}
.ev-counter{font-family:'IBM Plex Mono',monospace;font-size:11px;
  color:var(--muted);white-space:nowrap}

/* ── FINDING CARDS ── */
.act-divider{
  margin:48px 0 24px;padding:20px 24px;
  background:var(--panel);border:1px solid var(--border);border-radius:4px;
  border-left:3px solid var(--amber)
}
.act-num{font-family:'IBM Plex Mono',monospace;font-size:10px;
  letter-spacing:.15em;text-transform:uppercase;color:var(--amber);margin-bottom:4px}
.act-title{font-family:'Fraunces',serif;font-size:22px;font-weight:700;color:var(--text)}
.act-tc{font-family:'IBM Plex Mono',monospace;font-size:11px;
  color:var(--muted);margin-top:4px}

.finding-card{
  border:1px solid var(--border);border-radius:4px;overflow:hidden;
  margin:20px 0;background:var(--panel);
}
.finding-card.critical{border-left:3px solid var(--red)}
.finding-card.high{border-left:3px solid var(--amber)}
.finding-card.medium{border-left:3px solid var(--violet)}
.finding-card.low{border-left:3px solid var(--cyan)}
.fc-header{padding:16px 20px;background:#0d1117;border-bottom:1px solid var(--border)}
.fc-id{font-family:'IBM Plex Mono',monospace;font-size:11px;
  color:var(--muted);margin-bottom:4px}
.fc-title{font-size:17px;font-weight:700;color:var(--text);margin-bottom:10px}
.fc-meta{display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--muted)}
.fc-meta span{font-family:'IBM Plex Mono',monospace}
.fc-meta .k{color:var(--muted);margin-right:4px}
.fc-meta .v{color:var(--text)}
.fc-body{padding:20px}
.fc-body p{color:var(--muted);font-size:13px;margin:8px 0}
.fc-body h4{color:var(--text);margin:16px 0 6px;font-size:13px;
  font-family:'IBM Plex Mono',monospace;font-size:11px;
  letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
pre.term{
  background:#0d1117;border:1px solid var(--border);border-radius:3px;
  padding:14px 16px;overflow-x:auto;font-family:'IBM Plex Mono',monospace;
  font-size:12px;color:var(--green);line-height:1.6;margin:10px 0;
  white-space:pre-wrap;word-break:break-all
}
.sev-badge{font-family:'IBM Plex Mono',monospace;font-size:11px;
  font-weight:700;letter-spacing:.06em;padding:2px 8px;border-radius:3px}

/* ── HOST GRID ── */
.host-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin:24px 0}
.host-card{
  background:var(--panel);border:1px solid var(--border);
  border-radius:4px;padding:16px;
}
.hc-name{font-family:'IBM Plex Mono',monospace;font-size:13px;
  font-weight:600;color:var(--text);margin-bottom:4px}
.hc-ip{font-size:12px;color:var(--muted);font-family:'IBM Plex Mono',monospace;margin-bottom:8px}
.hc-role{font-size:11px;letter-spacing:.06em;text-transform:uppercase;
  padding:2px 8px;border-radius:10px;display:inline-block;margin-bottom:8px}
.hc-verdict{font-family:'IBM Plex Mono',monospace;font-size:12px;font-weight:700}
.hc-verdict.pwnd{color:var(--red)}
.hc-verdict.comp{color:var(--amber)}
.hc-verdict.hard{color:var(--green)}

/* ── TTP MATRIX ── */
.ttp-grid{
  display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));
  gap:8px;margin:24px 0
}
.ttp-cell{
  background:var(--panel);border:1px solid var(--border);
  border-radius:4px;padding:14px;
}
.ttp-tactic{font-size:9px;letter-spacing:.12em;text-transform:uppercase;
  color:var(--muted);margin-bottom:4px}
.ttp-name{font-size:13px;font-weight:600;color:var(--text);margin-bottom:4px}
.ttp-id{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--green)}
.ttp-ev{font-size:12px;color:var(--muted);margin-top:6px}

/* ── ATTACK CHAINS ── */
.chain-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;margin:24px 0}
.chain-card{
  background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:20px
}
.chain-title{font-size:14px;font-weight:700;color:var(--text);margin-bottom:8px}
.chain-body{font-size:13px;color:var(--muted);margin-bottom:12px}
.chain-status{
  display:inline-block;font-family:'IBM Plex Mono',monospace;
  font-size:10px;letter-spacing:.08em;text-transform:uppercase;
  padding:3px 10px;border-radius:10px
}
.chain-status.cleared{background:#00ff9c18;color:var(--green);border:1px solid #00ff9c30}
.chain-status.partial{background:#ffb80018;color:var(--amber);border:1px solid #ffb80030}
.chain-bar{height:3px;background:var(--border);border-radius:2px;margin-top:12px}
.chain-fill{height:100%;border-radius:2px;background:var(--green)}

/* ── DEAD ENDS ── */
.reject-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;margin:24px 0}
.reject{
  background:var(--panel);border:1px solid var(--border);
  border-radius:4px;padding:16px;border-left:3px solid var(--muted)
}
.reject-title{font-size:13px;font-weight:600;color:var(--muted);margin-bottom:6px}
.reject-why{font-size:12px;color:#6e7681}

/* ── STRENGTHS ── */
.strength-list{list-style:none;margin:20px 0}
.strength-list li{
  padding:10px 16px;border-bottom:1px solid var(--border);
  font-size:13px;color:var(--muted)
}
.strength-list li::before{content:'✓ ';color:var(--green);font-weight:700}

/* ── CLOSE STAMP ── */
#sec-close{
  text-align:center;padding:100px 24px;background:var(--bg1);
  border-top:1px solid var(--border)
}
.close-stamp{
  display:inline-block;
  border:3px solid var(--green);
  padding:20px 48px;
  font-family:'IBM Plex Mono',monospace;
  font-size:clamp(18px,3vw,32px);
  font-weight:700;letter-spacing:.2em;
  text-transform:uppercase;color:var(--green);
  transform:rotate(-2deg);
  text-shadow:0 0 20px rgba(0,255,156,.5);
  box-shadow:0 0 30px rgba(0,255,156,.15),inset 0 0 30px rgba(0,255,156,.05);
  margin-bottom:32px;
}
.close-meta{font-family:'IBM Plex Mono',monospace;font-size:12px;
  color:var(--muted);letter-spacing:.06em;margin-top:8px}
.close-caption{max-width:600px;margin:24px auto 0;
  font-size:14px;color:var(--muted);line-height:1.7}
.tlp{
  display:inline-block;margin-top:24px;
  font-family:'IBM Plex Mono',monospace;font-size:11px;
  letter-spacing:.12em;padding:4px 14px;
  border:1px solid #ff3b3b60;color:var(--red);border-radius:3px
}

/* ── MISC ── */
.md-table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}
.md-table th{background:#0d1117;color:var(--cyan);text-align:left;
  padding:8px 12px;border-bottom:2px solid var(--border);
  font-family:'IBM Plex Mono',monospace;font-size:11px;letter-spacing:.06em;text-transform:uppercase}
.md-table td{padding:8px 12px;border-bottom:1px solid var(--border);color:var(--muted)}
.md-table tr:hover td{background:#ffffff04}
blockquote{border-left:3px solid var(--amber);padding:10px 16px;
  background:#ffb80010;border-radius:0 4px 4px 0;margin:12px 0;
  color:var(--muted);font-style:italic}
@media(max-width:640px){
  .replay-inner{grid-template-columns:1fr}
  .host-rail{display:none}
  .roadmap,.dossier,.story-stats{grid-template-columns:1fr}
}
"""

# ── JS ────────────────────────────────────────────────────────────────────────
def make_replay_js(events, hosts):
    import json
    evs_js  = json.dumps(events)
    hosts_js = json.dumps(hosts)
    phase_js = json.dumps(PHASE_COLOR)
    return r"""
(function(){
const EVENTS=""" + evs_js + r""";
const HOSTS=""" + hosts_js + r""";
const COLORS=""" + phase_js + r""";
let idx=0,playing=false,timer=null,speed=1;
const SPEEDS=[1,4,16,60];
let sIdx=0;

function hostEl(h){return document.getElementById('hc-'+h.replace(/[^a-z0-9]/gi,'_'))}
function evEl(i){return document.getElementById('ev-'+i)}

function render(n){
  idx=Math.max(0,Math.min(n,EVENTS.length-1));
  EVENTS.forEach((_,i)=>{
    const el=evEl(i);if(!el)return;
    el.classList.toggle('fired',i<idx);
    el.classList.toggle('current',i===idx);
  });
  // update host chips
  const pwnd=new Set(),act=new Set();
  for(let i=0;i<=idx;i++){
    const ph=EVENTS[i][2];
    const h=EVENTS[i][1];
    if(ph==='pwn') pwnd.add(h); else act.add(h);
  }
  HOSTS.forEach(h=>{
    const el=hostEl(h);if(!el)return;
    el.classList.toggle('pwned',pwnd.has(h));
    el.classList.toggle('active',act.has(h)&&!pwnd.has(h));
  });
  // scrub
  const pct=EVENTS.length>1?(idx/(EVENTS.length-1)*100):0;
  const fill=document.getElementById('scrub-fill');
  if(fill)fill.style.width=pct+'%';
  // counter
  const ctr=document.getElementById('ev-ctr');
  if(ctr)ctr.textContent=(idx+1)+'/'+EVENTS.length;
  // scroll event into view
  const cur=evEl(idx);if(cur)cur.scrollIntoView({block:'nearest'});
}

function step(d){stop();render(idx+d)}
function stop(){if(timer){clearInterval(timer);timer=null}playing=false;
  const pb=document.getElementById('btn-play');if(pb)pb.textContent='▶'}
function play(){
  if(idx>=EVENTS.length-1)render(0);
  playing=true;
  const pb=document.getElementById('btn-play');if(pb)pb.textContent='⏸';
  timer=setInterval(()=>{
    if(idx>=EVENTS.length-1){stop();return}
    render(idx+1);
  },600/speed);
}
function togglePlay(){playing?stop():play()}

window.replayReset=()=>{stop();render(0)};
window.replayBack=()=>step(-1);
window.replayPlay=()=>togglePlay();
window.replayFwd=()=>step(1);
window.replayCycle=()=>{
  sIdx=(sIdx+1)%SPEEDS.length;speed=SPEEDS[sIdx];
  const el=document.getElementById('speed-lbl');if(el)el.textContent=speed+'×';
  if(playing){stop();play();}
};

document.addEventListener('DOMContentLoaded',()=>{
  render(0);
  const scrub=document.getElementById('scrub-bar');
  if(scrub){scrub.addEventListener('click',e=>{
    const r=scrub.getBoundingClientRect();
    const pct=(e.clientX-r.left)/r.width;
    render(Math.round(pct*(EVENTS.length-1)));
  });}
  // click event rows
  EVENTS.forEach((_,i)=>{
    const el=evEl(i);if(!el)return;
    el.addEventListener('click',()=>{stop();render(i);});
  });
  // nav
  const tog=document.getElementById('nav-toggle');
  const drw=document.getElementById('nav-drawer');
  const cls=document.getElementById('nav-close');
  if(tog)tog.onclick=()=>drw.classList.toggle('open');
  if(cls)cls.onclick=()=>drw.classList.remove('open');
  // build nav links dynamically
  const nav=document.getElementById('nav-links');
  if(nav){
    document.querySelectorAll('[data-nav]').forEach((el,n)=>{
      const a=document.createElement('a');
      a.className='nav-item';a.href='#'+el.id;
      a.innerHTML='<span class="nav-num">'+String(n+1).padStart(2,'0')+'</span>'+el.dataset.nav;
      a.onclick=()=>drw.classList.remove('open');
      nav.appendChild(a);
    });
  }
});
})();
"""

# ── section builder helpers ───────────────────────────────────────────────────
def wrap(id_, data_nav, content):
    return f'<div id="{id_}" data-nav="{html.escape(data_nav)}">{content}</div>'

def sec(id_, data_nav, label, title, body, bg=""):
    bg_style = f' style="background:{bg}"' if bg else ""
    return (f'<div id="{id_}" data-nav="{html.escape(data_nav)}"{bg_style}>'
            f'<div class="section"><p class="sec-label">{html.escape(label)}</p>'
            f'<h2>{inline(title)}</h2>{body}</div></div><hr class="divider">')

# ── BUILD ─────────────────────────────────────────────────────────────────────
def build(eng_dir, out_path):
    yaml   = read(os.path.join(eng_dir, "engagement.yaml"))
    report = read(os.path.join(eng_dir, "report.md"))
    tl_md  = read(os.path.join(eng_dir, "timeline.md"))
    hosts_raw = read(os.path.join(eng_dir, "hosts.csv"))
    mmd    = read(os.path.join(eng_dir, "attack_graph.mmd"))

    # metadata
    g = lambda k, d="—": yaml_get(yaml, k, d)
    client   = g("client")
    window   = f"{g('window_start')} → {g('window_end')}"
    model    = g("model")
    scope    = g("scope")
    operator = g("operator")
    soph     = g("sophistication")
    obj      = g("compromise_objective")
    worst    = g("worst_outcome")
    ttda     = g("time_to_da")
    pwnd     = g("hosts_pwnd")
    forests  = g("forests_compromised")
    tooling  = g("tooling")
    mode     = g("testing_mode")
    ttps     = g("ttps_catalogued")
    iocvol   = g("ioc_volume")
    status   = g("final_status")
    headline = g("headline")
    eid      = g("engagement_id")
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    findings  = parse_findings(report)
    phases    = parse_timeline(tl_md)
    hosts     = parse_hosts(hosts_raw)
    chains    = parse_chains(report)
    dead_ends = parse_dead_ends(report)
    strengths = parse_strengths(report)

    sev_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for f in findings:
        k = f["rating"].upper()
        if k in sev_counts: sev_counts[k]+=1

    # narrative from report
    narr_m = re.search(r"## Engagement Narrative\n(.*?)(?=\n##|\Z)", report, re.DOTALL)
    narrative = narr_m.group(1).strip() if narr_m else "See findings below."

    # remediation roadmap from finding remediations
    p0, p1, p2 = [], [], []
    for f in findings:
        rem = f["remediation"]
        for line in rem.splitlines():
            stripped = line.strip()
            if stripped.startswith("Immediate:") or stripped.startswith("Immediate"):
                txt = re.sub(r"^Immediate[:\s]*","",stripped).strip()
                if txt: p0.append(txt)
            elif stripped.startswith("Short-term"):
                txt = re.sub(r"^Short-term[:\s]*","",stripped).strip()
                if txt: p1.append(txt)
            elif stripped.startswith("Long-term"):
                txt = re.sub(r"^Long-term[:\s]*","",stripped).strip()
                if txt: p2.append(txt)

    # ── HERO ──
    dossier_cells = [
        ("Engagement ID",  eid,        ""),
        ("Client / Target",client,     ""),
        ("Window",         window,     ""),
        ("Model",          model,      ""),
        ("Scope",          scope,      ""),
        ("Operator",       operator,   ""),
        ("Sophistication", soph,       "amber"),
        ("Objective",      obj,        "red"),
        ("Worst Outcome",  worst,      "red"),
        ("Time-to-DA",     ttda,       "red"),
        ("Hosts Pwn3d",    str(pwnd),  "red"),
        ("Forests",        str(forests),"red"),
        ("Tooling",        tooling,    ""),
        ("Testing Mode",   mode,       ""),
        ("TTPs Catalogued",str(ttps),  "green"),
        ("IOC Volume",     iocvol,     ""),
    ]
    dos_html = "".join(
        f'<div class="dos-cell"><div class="label">{html.escape(k)}</div>'
        f'<div class="val {cls}">{html.escape(v)}</div></div>'
        for k,v,cls in dossier_cells
    )
    score_html = (
        f'<div class="score-cell"><div class="s-num" style="color:var(--red)">{sev_counts["CRITICAL"]}</div><div class="s-lbl">Critical</div></div>'
        f'<div class="score-cell"><div class="s-num" style="color:var(--amber)">{sev_counts["HIGH"]}</div><div class="s-lbl">High</div></div>'
        f'<div class="score-cell"><div class="s-num" style="color:var(--violet)">{sev_counts["MEDIUM"]}</div><div class="s-lbl">Medium</div></div>'
        f'<div class="score-cell"><div class="s-num" style="color:var(--cyan)">{sev_counts["LOW"]}</div><div class="s-lbl">Low</div></div>'
        f'<div class="score-cell"><div class="s-num" style="color:var(--muted)">{sev_counts["INFO"]}</div><div class="s-lbl">Info</div></div>'
        f'<div class="score-cell"><div class="s-num" style="color:var(--green)">{pwnd}</div><div class="s-lbl">Hosts</div></div>'
    )
    hero = f"""
<section id="hero" data-nav="Hero / Dossier">
  <p class="hero-tag">// Protocol SIFT — DFIR Operator Casebook</p>
  <h1 class="hero-title">Jack<em>of</em>AllHacks</h1>
  <p class="hero-sub">{html.escape(client)} &nbsp;·&nbsp; {html.escape(window)} &nbsp;·&nbsp; {html.escape(model)}</p>
  <div class="dossier">{dos_html}</div>
  <div class="scoreboard">{score_html}</div>
  <div class="stamp">CONFIDENTIAL // FOR OPERATOR EYES ONLY</div>
</section>
"""

    # ── EXEC BRIEFING ──
    sev_banner = f"""
<div class="sev-banner">
  <div class="sev-cell red"><div class="sv-label">Severity</div><div class="sv-val">CRITICAL</div></div>
  <div class="sev-cell red"><div class="sv-label">Hosts Pwn3d</div><div class="sv-val">{html.escape(str(pwnd))}</div></div>
  <div class="sev-cell amber"><div class="sv-label">Time-to-DA</div><div class="sv-val">{html.escape(ttda)}</div></div>
  <div class="sev-cell red"><div class="sv-label">Recoverability</div><div class="sv-val">NONE</div></div>
  <div class="sev-cell violet"><div class="sv-label">Data Exfil</div><div class="sv-val">Confirmed</div></div>
  <div class="sev-cell amber"><div class="sv-label">Cloud Blast</div><div class="sv-val">AWS EC2 Role</div></div>
</div>"""
    root_rows = [
        ("Web Application Security","No input validation on CheckStatus.aspx · OWASP A01/A03"),
        ("Service Hardening","Unquoted SolarwindsTFTP service path · exploited to SYSTEM"),
        ("Credential Hygiene","Reuse of LAFAdmin DA creds from compromised server"),
        ("Network Segmentation","No east-west controls — ransomware spread domain-wide"),
        ("Endpoint Detection","No EDR alert on rnSylwOz.exe ADMIN$ service creation"),
        ("Cloud Security","IMDSv2 not enforced; EC2 role over-permissioned for S3"),
        ("Backup Resilience","VSS deleted; no offline/immutable backup existed"),
    ]
    rc_html = '<div class="root-causes">'+"".join(
        f'<div class="root-row"><div class="root-ctrl">{html.escape(k)}</div>'
        f'<div class="root-fail">{html.escape(v)}</div></div>' for k,v in root_rows
    )+"</div>"
    rm_html = f"""<div class="roadmap">
<div class="rm-card p0"><h4>P0 — Within 48h</h4><ul>{"".join(f"<li>{html.escape(x)}</li>" for x in p0[:6])}</ul></div>
<div class="rm-card p1"><h4>P1 — Within 2wk</h4><ul>{"".join(f"<li>{html.escape(x)}</li>" for x in p1[:6])}</ul></div>
<div class="rm-card p2"><h4>P2 — Within 30d</h4><ul>{"".join(f"<li>{html.escape(x)}</li>" for x in p2[:6])}</ul></div>
</div>"""
    residual = ('<div class="sev-banner"><div class="sev-cell red">'
                '<div class="sv-label">Residual Risk</div>'
                '<div class="sv-val">HIGH — krbtgt must be rotated ×2; all AD creds are compromised</div>'
                '</div></div>')
    exec_body = sev_banner + "<h3>Root Causes</h3>" + rc_html + "<h3>Mitigation Roadmap</h3>" + rm_html + residual
    exec_sec = sec("sec-exec","Executive Briefing","01 · executive briefing","What actually happened",exec_body,"#0a0e14")

    # ── STORY ──
    all_evs = sum(len(p["events"]) for p in phases)
    story_stats = f"""<div class="story-stats">
  <div class="ss-cell"><div class="ss-val">{len(findings)}</div><div class="ss-lbl">Findings</div></div>
  <div class="ss-cell"><div class="ss-val">{all_evs}</div><div class="ss-lbl">Timeline Events</div></div>
  <div class="ss-cell"><div class="ss-val">{pwnd}</div><div class="ss-lbl">Hosts Pwn3d</div></div>
  <div class="ss-cell"><div class="ss-val">~3h</div><div class="ss-lbl">Total Dwell</div></div>
  <div class="ss-cell"><div class="ss-val">Full Domain</div><div class="ss-lbl">Objective</div></div>
</div>"""
    story_sec = sec("sec-story","The Story","02 · the story","How it unfolded",
                    story_stats + md2html(narrative))

    # ── TIMELINE ──
    tl_html = ""
    for ph in phases:
        rows = "".join(
            f"<tr><td class='tl-time'>{html.escape(c[0]) if c else ''}</td>"
            f"<td class='tl-host'>{html.escape(c[1]) if len(c)>1 else ''}</td>"
            f"<td>{inline(c[2]) if len(c)>2 else ''}</td>"
            f"<td style='color:var(--muted);font-size:11px'>{html.escape(c[3]) if len(c)>3 else ''}</td></tr>"
            for c in ph["events"]
        )
        tl_html += f"""<div class="phase-block">
<p class="phase-label">{html.escape(ph["name"])}</p>
<table class="tl-table"><thead><tr><th>UTC</th><th>Host</th><th>Event</th><th>Evidence</th></tr></thead>
<tbody>{rows}</tbody></table></div>"""
    tl_sec = sec("sec-timeline","Master Timeline","03 · master timeline","Attack timeline",tl_html)

    # ── ATTACK GRAPH ──
    graph_body = f"""<div class="graph-wrap">
<div class="mermaid">
{mmd}
</div></div>""" if mmd else "<p style='color:var(--muted)'>No attack graph available.</p>"
    graph_sec = sec("sec-graph","Attack Graph","04 · attack graph","Kill chain",graph_body)

    # ── KILL-CHAIN REPLAY ──
    host_chips = "".join(
        f'<div class="host-chip" id="hc-{h.replace("-","_").replace(".","_")}">{html.escape(h)}</div>'
        for h in HOSTS_ALL
    )
    ev_rows = "".join(
        f'<div class="ev-row" id="ev-{i}">'
        f'<div class="ev-dot" style="background:{PHASE_COLOR.get(e[2],chr(35)+chr(56))+chr(98)+chr(57)+chr(52)+chr(57)+chr(101)}"></div>'
        f'<div class="ev-time">{html.escape(e[0])}</div>'
        f'<div class="ev-host">{html.escape(e[1])}</div>'
        f'<div class="ev-desc">{html.escape(e[3])}</div></div>'
        for i, e in enumerate(REPLAY_EVENTS)
    )
    # fix the color inline properly
    ev_rows = ""
    for i, e in enumerate(REPLAY_EVENTS):
        col = PHASE_COLOR.get(e[2], "#8b949e")
        ev_rows += (f'<div class="ev-row" id="ev-{i}">'
                    f'<div class="ev-dot" style="background:{col}"></div>'
                    f'<div class="ev-time">{html.escape(e[0])}</div>'
                    f'<div class="ev-host">{html.escape(e[1])}</div>'
                    f'<div class="ev-desc">{html.escape(e[3])}</div></div>')

    replay_body = f"""
<div class="replay-shell">
  <div class="replay-header">
    <div class="replay-dot" style="background:#ff5f57"></div>
    <div class="replay-dot" style="background:#febc2e"></div>
    <div class="replay-dot" style="background:#28c840"></div>
    <span style="font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--muted);margin-left:12px">kill-chain-replay.js</span>
  </div>
  <div class="replay-inner">
    <div class="host-rail">
      <h4>Host Status</h4>
      {host_chips}
    </div>
    <div class="event-feed">{ev_rows}</div>
  </div>
  <div class="transport">
    <button class="tp-btn" onclick="replayReset()">⏮</button>
    <button class="tp-btn" onclick="replayBack()">◀</button>
    <button class="tp-btn" id="btn-play" onclick="replayPlay()">▶</button>
    <button class="tp-btn" onclick="replayFwd()">▶</button>
    <button class="tp-btn" onclick="replayCycle()">⚡ <span id="speed-lbl">1×</span></button>
    <div class="scrub-wrap" id="scrub-bar"><div class="scrub-fill" id="scrub-fill"></div></div>
    <span class="ev-counter" id="ev-ctr">1/{len(REPLAY_EVENTS)}</span>
  </div>
</div>"""
    replay_sec = sec("sec-replay","Kill-Chain Replay","05 · kill-chain replay","Replay the attack",replay_body)

    # ── ACTS + FINDING CHAPTERS ──
    ACT_DEFS = [
        ("01","Ingress & Foothold","18:38 – 19:38","F01","F02"),
        ("02","Implant & Domain Compromise","19:59 – 20:09","F03"),
        ("03","Data Exfiltration & Cloud Pivot","20:20 – 21:51","F04"),
        ("04","Persistence & Ransomware","22:00 – 22:46","F05"),
    ]
    acts_html = ""
    fmap = {f["id"]:f for f in findings}
    act_idx = 1
    for act_def in ACT_DEFS:
        num, title, tc = act_def[0], act_def[1], act_def[2]
        fids = act_def[3:]
        acts_html += f"""<div class="act-divider">
<p class="act-num">ACT {num} // {tc}</p>
<p class="act-title">{html.escape(title)}</p>
</div>"""
        for fid in fids:
            f = fmap.get(fid)
            if not f: continue
            rating = f["rating"].upper()
            fc_cls = rating.lower() if rating in SEV_COLOR else "info"
            rem_html = md2html(f["remediation"]) if f["remediation"] else ""
            acts_html += f"""<div class="finding-card {fc_cls}" id="finding-{f['id'].lower()}">
  <div class="fc-header">
    <div class="fc-id">{html.escape(f['id'])}</div>
    <div class="fc-title">{html.escape(f['title'])}</div>
    <div class="fc-meta">
      <span>{sev_badge(rating)}</span>
      <span><span class="k">CVSSv4</span><span class="v">{html.escape(f['cvss'])}</span></span>
      <span><span class="k">CWE</span><span class="v">{html.escape(f['cwe'])}</span></span>
      <span><span class="k">MITRE</span><span class="v">{html.escape(f['mitre'])}</span></span>
      <span><span class="k">Hosts</span><span class="v">{html.escape(f['hosts'])}</span></span>
      <span><span class="k">Status</span><span class="v" style="color:var(--red)">{html.escape(f['status'])}</span></span>
    </div>
  </div>
  <div class="fc-body">
    {md2html(f['prose'])}
    {"<h4>Remediation</h4>"+rem_html if rem_html else ""}
  </div>
</div>"""
    acts_sec = (f'<div id="sec-acts" data-nav="Findings / Acts"><div class="section">'
                f'<p class="sec-label">06 · acts &amp; chapters</p>'
                f'<h2>Findings</h2>{acts_html}</div></div><hr class="divider">')

    # ── HOST GRID ──
    role_label = {"entry":"Entry Point","DC":"Domain Controller","pivot":"Pivot",
                  "victim":"Victim","cloud":"Cloud","member":"Member Server"}
    host_cards = ""
    for h in hosts:
        role = h.get("role","member")
        rc = ROLE_COLOR.get(role,"#8b949e")
        verdict = h.get("verdict","—")
        vc = "pwnd" if verdict=="Pwn3d" else ("comp" if verdict=="Compromised" else "hard")
        host_cards += f"""<div class="host-card" style="border-top:3px solid {rc}">
  <div class="hc-name">{html.escape(h.get('host','?'))}</div>
  <div class="hc-ip">{html.escape(h.get('ip','?'))}</div>
  <div class="hc-role" style="background:{rc}20;color:{rc}">{html.escape(role_label.get(role,role))}</div>
  <div class="hc-verdict {vc}">{html.escape(verdict)}</div>
</div>"""
    hosts_sec = sec("sec-hosts","Host Grid","07 · host grid","Scope & verdicts",
                    f'<div class="host-grid">{host_cards}</div>')

    # ── TTP MATRIX ──
    ttp_cells = "".join(
        f'<div class="ttp-cell"><div class="ttp-tactic">{html.escape(tactic)}</div>'
        f'<div class="ttp-name">{html.escape(name)}</div>'
        f'<div class="ttp-id">{html.escape(tid)}</div>'
        f'<div class="ttp-ev">{html.escape(ev[:80])}</div></div>'
        for tactic,tid,name,ev in MITRE_DATA
    )
    ttp_sec = sec("sec-ttp","TTP Matrix","08 · ttp matrix","MITRE ATT&CK",
                  f'<div class="ttp-grid">{ttp_cells}</div>')

    # ── ATTACK CHAINS ──
    chain_cards = ""
    for ch in chains:
        status_cls = "cleared" if ch["status"]=="cleared" else "partial"
        pct = "100" if status_cls=="cleared" else "65"
        chain_cards += f"""<div class="chain-card">
  <div class="chain-title">{html.escape(ch['title'])}</div>
  <div class="chain-body">{html.escape(ch['body'][:200])}</div>
  <span class="chain-status {status_cls}">{'COMPLETE' if status_cls=='cleared' else 'PARTIAL'}</span>
  <div class="chain-bar"><div class="chain-fill" style="width:{pct}%"></div></div>
</div>"""
    chains_sec = sec("sec-chains","Attack Chains","09 · attack chains","How we got in",
                     f'<div class="chain-grid">{chain_cards}</div>') if chain_cards else ""

    # ── DEAD ENDS ──
    dead_html = ""
    if dead_ends:
        rejects = "".join(
            f'<div class="reject"><div class="reject-title">Dead End</div>'
            f'<div class="reject-why">{html.escape(d)}</div></div>'
            for d in dead_ends
        )
        dead_html = sec("sec-dead-ends","Dead Ends","10 · dead ends","What didn't work",
                        f'<div class="reject-grid">{rejects}</div>')

    # ── STRENGTHS ──
    str_html = ""
    if strengths:
        items = "".join(f"<li>{html.escape(s)}</li>" for s in strengths)
        str_html = sec("sec-strengths","Strengths","11 · strengths","What worked",
                       f'<ul class="strength-list">{items}</ul>')

    # ── CLOSE STAMP ──
    close_sec = f"""
<div id="sec-close" data-nav="Close Stamp">
  <div class="close-stamp">ENGAGEMENT CLOSED · {datetime.now(timezone.utc).strftime("%Y-%m-%d")}</div>
  <div class="close-meta">{html.escape(operator)} &nbsp;·&nbsp; v1.0 &nbsp;·&nbsp; {html.escape(eid)}</div>
  <div class="close-meta">Generated {html.escape(generated)}</div>
  <p class="close-caption">{html.escape(headline)}</p>
  <div class="tlp">TLP:AMBER // CONFIDENTIAL // NOT FOR PUBLIC RELEASE</div>
</div>"""

    # ── REPLAY JS ──
    replay_js = make_replay_js(
        [[e[0],e[1],e[2],e[3]] for e in REPLAY_EVENTS],
        HOSTS_ALL
    )

    # ── NAV ──
    nav_html = """
<button id="nav-toggle">≡ CHAPTERS</button>
<div id="nav-drawer">
  <button id="nav-close">×</button>
  <h3>// Chapters</h3>
  <nav id="nav-links"></nav>
</div>"""

    full = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Casebook — {html.escape(eid)} — {html.escape(client)}</title>
<style>{CSS}</style>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"></script>
</head>
<body>
{nav_html}
{hero}
{exec_sec}
{story_sec}
{tl_sec}
{graph_sec}
{replay_sec}
{acts_sec}
{hosts_sec}
{ttp_sec}
{chains_sec}
{dead_html}
{str_html}
{close_sec}
<script>
mermaid.initialize({{
  startOnLoad:true,
  theme:'dark',
  themeVariables:{{
    primaryColor:'#0e1319',
    primaryTextColor:'#e6edf3',
    primaryBorderColor:'#21262d',
    lineColor:'#58a6ff',
    secondaryColor:'#0b0f14',
    tertiaryColor:'#05070a'
  }}
}});
</script>
<script>{replay_js}</script>
</body>
</html>"""

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(full)
    return out_path, os.path.getsize(out_path)

# ── main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--engagement", default=DEFAULT_ENG)
    ap.add_argument("--out", default=os.path.join(CASE_DIR,"casebook_JackofAllHacks_fancy.html"))
    args = ap.parse_args()
    path, size = build(args.engagement, args.out)
    findings = parse_findings(read(os.path.join(args.engagement,"report.md")))
    sev = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for f in findings:
        k=f["rating"].upper()
        if k in sev: sev[k]+=1
    print(f"[OK] {path}")
    print(f"     Size  : {size:,} bytes")
    print(f"     Findings: {len(findings)} total — {sev}")
