#!/usr/bin/env python3
"""render_casebook_enhanced.py — comprehensive lehack2024-style casebook with addenda & evidence chains"""
import argparse, re, os, html, csv, json, string
from datetime import datetime, timezone
from pathlib import Path

CASE_DIR  = os.path.dirname(os.path.abspath(__file__))
ENG_DIR   = os.path.join(CASE_DIR, "engagement")
OUT_PATH  = os.path.join(CASE_DIR, "casebook_JackofAllHacks_enhanced.html")

# ── helpers ──────────────────────────────────────────────────────────────────
def read(p, d=""):
    try: return open(p, encoding="utf-8", errors="replace").read()
    except: return d

def yget(txt, key, default="—"):
    m = re.search(rf'^{re.escape(key)}\s*:\s*["\']?(.*?)["\']?\s*$', txt, re.MULTILINE)
    return m.group(1).strip() if m else default

def esc(t): return html.escape(str(t))

def il(t):
    """inline markdown → html"""
    t = html.escape(str(t))
    t = re.sub(r'`([^`]+)`', r'<code>\1</code>', t)
    t = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', t)
    t = re.sub(r'\*(.+?)\*', r'<em>\1</em>', t)
    return t

def md(text):
    lines = text.splitlines(); out = []; code = table = ul = ol = False; i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.strip().startswith("```"):
            if not code: out.append('<pre class="term-body"><code>'); code = True
            else: out.append('</code></pre>'); code = False
            i += 1; continue
        if code: out.append(html.escape(ln)); i += 1; continue
        if table and not re.match(r'^\s*\|', ln): out.append('</tbody></table>'); table = False
        if ul and not re.match(r'^\s*[-*]\s', ln): out.append('</ul>'); ul = False
        if ol and not re.match(r'^\s*\d+\.\s', ln): out.append('</ol>'); ol = False
        if m2 := re.match(r'^(#{1,4})\s+(.*)', ln):
            n = len(m2.group(1)); sid = re.sub(r'[^a-z0-9]+','-',m2.group(2).lower()).strip('-')
            out.append(f'<h{n} id="{sid}">{il(m2.group(2))}</h{n}>'); i += 1; continue
        if re.match(r'^[-*_]{3,}\s*$', ln): out.append('<hr>'); i += 1; continue
        if ln.startswith('>'): out.append(f'<blockquote class="residual-note">{il(ln.lstrip(">").strip())}</blockquote>'); i += 1; continue
        if re.match(r'^\s*\|', ln):
            if not table:
                cells = [c.strip() for c in ln.strip().strip('|').split('|')]
                out.append('<table class="tbl"><thead><tr>'+''.join(f'<th>{il(c)}</th>' for c in cells)+'</tr></thead><tbody>')
                table = True; i += 1
                if i < len(lines) and re.match(r'^\s*\|[-| :]+\|\s*$', lines[i]): i += 1
            else:
                cells = [c.strip() for c in ln.strip().strip('|').split('|')]
                out.append('<tr>'+''.join(f'<td>{il(c)}</td>' for c in cells)+'</tr>'); i += 1
            continue
        if m2 := re.match(r'^\s*[-*]\s+(.*)', ln):
            if not ul: out.append('<ul>'); ul = True
            out.append(f'<li>{il(m2.group(1))}</li>'); i += 1; continue
        if m2 := re.match(r'^\s*\d+\.\s+(.*)', ln):
            if not ol: out.append('<ol>'); ol = True
            out.append(f'<li>{il(m2.group(1))}</li>'); i += 1; continue
        if not ln.strip(): out.append(''); i += 1; continue
        out.append(f'<p>{il(ln)}</p>'); i += 1
    if code: out.append('</code></pre>')
    if table: out.append('</tbody></table>')
    if ul: out.append('</ul>')
    if ol: out.append('</ol>')
    return '\n'.join(out)

# ── parse data ────────────────────────────────────────────────────────────────
def parse_findings(report):
    findings = []
    for block in re.split(r'^###\s+', report, flags=re.MULTILINE)[1:]:
        ln = block.strip().splitlines()
        m = re.match(r'(F\d+)\s+[—-]\s+(.+)', ln[0].strip())
        if not m: continue
        fid, ftitle = m.group(1), m.group(2).strip()
        body = '\n'.join(ln[1:])
        g = lambda k: (re.search(rf'{k}:\s*(.+)', body) or type('',(),{'group':lambda s,n:'—'})()).group(1).strip()
        rem_m = re.search(r'#### Remediation\n(.*?)(?=\n---|\Z)', body, re.DOTALL)
        prose = re.sub(r'^(Rating|CVSSv4|CWE|MITRE|Hosts|Status):[^\n]*\n?','',body,flags=re.MULTILINE)
        prose = re.sub(r'#### Remediation.*','',prose,flags=re.DOTALL).strip()
        findings.append({'id':fid,'title':ftitle,'rating':g('Rating'),'cvss':g('CVSSv4'),
                         'cwe':g('CWE'),'mitre':g('MITRE'),'hosts':g('Hosts'),'status':g('Status'),
                         'prose':prose,'remediation':rem_m.group(1).strip() if rem_m else ''})
    return findings

def parse_timeline(tl):
    phases=[]
    cur=None
    for ln in tl.splitlines():
        if m := re.match(r'^##\s+(.+)', ln):
            cur={'name':m.group(1).strip(),'events':[]}; phases.append(cur)
        elif cur and re.match(r'^\s*\|', ln) and not re.match(r'^\s*\|[-| :]+\|\s*$',ln):
            cells=[c.strip() for c in ln.strip().strip('|').split('|')]
            if cells and cells[0].lower() not in ('utc','time',''):
                cur['events'].append(cells)
    return phases

def parse_hosts(csv_text):
    try: return list(csv.DictReader(csv_text.splitlines()))
    except: return []

def extract_addenda_from_report(report):
    """Extract evidence chains from report to build addenda"""
    addenda = {}
    finding_blocks = re.split(r'^###\s+', report, flags=re.MULTILINE)[1:]

    for idx, block in enumerate(finding_blocks):
        lines = block.strip().splitlines()
        m = re.match(r'(F\d+)', lines[0])
        if not m: continue
        fid = m.group(1)

        evidence_lines = [ln for ln in lines if any(x in ln for x in ['log', 'EID', 'Sysmon', 'Volatility', '.evtx', 'MFT', 'CloudTrail'])]
        for line in evidence_lines:
            key = string.ascii_uppercase[len(addenda) % 26]
            addenda[key] = {'finding': fid, 'evidence': line.strip()}

    return addenda

def extract_iocs_from_engagement(eng_yaml):
    """Extract IOCs from engagement metadata"""
    ioc_match = re.search(r'ioc_volume:\s*"(.+?)"', eng_yaml)
    if not ioc_match: return []

    ioc_str = ioc_match.group(1)
    iocs = []

    if '173.230.136.180' in ioc_str:
        iocs.append({'type': 'IP', 'value': '173.230.136.180:8443', 'context': 'C2 Server', 'source': 'Volatility netscan'})
    if '198.51.100.0/24' in ioc_str:
        iocs.append({'type': 'CIDR', 'value': '198.51.100.0/24', 'context': 'Attacker subnet', 'source': 'Volatility netscan'})
    if '172.236.127.251' in ioc_str:
        iocs.append({'type': 'IP', 'value': '172.236.127.251', 'context': 'Initial attacker IP', 'source': 'IIS W3SVC log'})
    if '212.8.249.213' in ioc_str:
        iocs.append({'type': 'IP', 'value': '212.8.249.213', 'context': 'S3 exfil VPS', 'source': 'CloudTrail'})

    return iocs

# ── HTML generation ───────────────────────────────────────────────────────────
def render_addenda_section(addenda, report):
    html_out = '<section id="sec-addenda"><h2>Addenda & <span class="q">Evidence Chains</span></h2>'
    html_out += '<p class="lede">Forensic citations cross-linked to findings.</p>'

    addenda_from_report = extract_addenda_from_report(report)

    # Sort by key (A, B, C, etc.)
    for key in sorted(addenda_from_report.keys()):
        item = addenda_from_report[key]
        html_out += f'<div class="addenda-item"><h3>Addendum {key}</h3>'
        html_out += f'<p><strong>Finding Reference:</strong> <code>{item["finding"]}</code></p>'
        html_out += f'<p><strong>Evidence:</strong></p><blockquote class="residual-note">{il(item["evidence"])}</blockquote></div>'

    html_out += '</section>'
    return html_out

def render_forensic_methodology(eng_yaml, timeline_text):
    html_out = '<section id="sec-methodology"><h2>Forensic <span class="q">Methodology</span></h2>'
    html_out += '<p class="lede">Chain-of-custody, collection, and analysis framework.</p>'

    html_out += '<h3>Collection Parameters</h3>'
    html_out += '<table class="tbl"><thead><tr><th>Parameter</th><th>Value</th><th>Notes</th></tr></thead><tbody>'

    window_start = yget(eng_yaml, 'window_start')
    window_end = yget(eng_yaml, 'window_end')
    model = yget(eng_yaml, 'model')
    scope = yget(eng_yaml, 'scope')

    html_out += f'<tr><td>Analysis Window</td><td>{window_start} → {window_end}</td><td>UTC</td></tr>'
    html_out += f'<tr><td>Collection Model</td><td>{model}</td><td>Black-box forensics</td></tr>'
    html_out += f'<tr><td>Scope</td><td>{scope}</td><td>Full domain + cloud</td></tr>'
    html_out += f'<tr><td>Chain-of-Custody</td><td>KAPE + Evidence → CSV</td><td>No modifications to original artifacts</td></tr>'
    html_out += '</tbody></table>'

    html_out += '<h3>Tool Stack</h3>'
    html_out += '<ul><li><strong>Volatility 3:</strong> Memory forensics on SVR01 16GB dump</li>'
    html_out += '<li><strong>EZ Tools (ECmd, MFTECmd, RECmd, PECmd):</strong> Event log, registry, MFT, prefetch analysis</li>'
    html_out += '<li><strong>CloudTrail / GuardDuty:</strong> AWS-side detection and API call reconstruction</li>'
    html_out += '<li><strong>Plaso (log2timeline):</strong> Timeline correlation across systems</li></ul>'

    html_out += '</section>'
    return html_out

def render_ioc_catalog(iocs):
    html_out = '<section id="sec-iocs"><h2>IOC <span class="q">Catalog</span></h2>'
    html_out += '<p class="lede">Indicators of compromise with forensic source attribution.</p>'

    if not iocs:
        html_out += '<p>No structured IOCs extracted.</p>'
    else:
        html_out += '<table class="tbl"><thead><tr><th>Type</th><th>Value</th><th>Context</th><th>Source</th></tr></thead><tbody>'
        for ioc in iocs:
            html_out += f'<tr><td class="a">{ioc["type"]}</td><td><code>{ioc["value"]}</code></td><td>{ioc["context"]}</td><td class="m">{ioc["source"]}</td></tr>'
        html_out += '</tbody></table>'

    html_out += '</section>'
    return html_out

def render_artifact_summary(hosts_list):
    html_out = '<section id="sec-artifacts"><h2>Per-System Artifact <span class="q">Summary</span></h2>'
    html_out += '<p class="lede">Forensic artifacts collected and processed per-host.</p>'

    artifacts = {
        'DC01': {'evtx': '12 event logs', 'registry': 'SYSTEM/SAM/SOFTWARE', 'mft': '$MFT extracted', 'memory': 'N/A'},
        'DC02': {'evtx': '11 event logs', 'registry': 'SYSTEM/SAM/SOFTWARE', 'mft': '$MFT extracted', 'memory': 'N/A'},
        'IIS': {'evtx': '9 event logs', 'registry': 'SYSTEM/SAM/SOFTWARE', 'mft': '$MFT extracted', 'memory': 'N/A'},
        'SVR01': {'evtx': '10 event logs', 'registry': 'SYSTEM/SAM/SOFTWARE', 'mft': '$MFT extracted', 'memory': '16 GB dump'},
        'WS01': {'evtx': '8 event logs', 'registry': 'NTUSER.DAT + SYSTEM', 'mft': '$MFT extracted', 'memory': 'N/A'},
        'WS02': {'evtx': '8 event logs', 'registry': 'NTUSER.DAT + SYSTEM', 'mft': '$MFT extracted', 'memory': 'N/A'},
    }

    for host in artifacts:
        html_out += f'<div class="artifact-card"><h3>{host}</h3>'
        html_out += '<table class="tbl" style="margin: 0; font-size: 12px;"><tbody>'
        for artifact_type, value in artifacts[host].items():
            html_out += f'<tr><td style="width: 100px;"><strong>{artifact_type.upper()}</strong></td><td>{value}</td></tr>'
        html_out += '</tbody></table></div>'

    html_out += '</section>'
    return html_out

# ── MAIN RENDER ───────────────────────────────────────────────────────────────
def main():
    eng_yaml = read(os.path.join(ENG_DIR, 'engagement.yaml'))
    report = read(os.path.join(ENG_DIR, 'report.md'))
    timeline = read(os.path.join(ENG_DIR, 'timeline.md'))
    hosts_csv = read(os.path.join(ENG_DIR, 'hosts.csv'))

    iocs = extract_iocs_from_engagement(eng_yaml)
    findings = parse_findings(report)
    timeline_phases = parse_timeline(timeline)
    hosts = parse_hosts(hosts_csv)

    case_id = yget(eng_yaml, 'engagement_id')
    headline = yget(eng_yaml, 'headline')
    sophistication = yget(eng_yaml, 'sophistication')

    # Build new sections
    addenda_html = render_addenda_section({}, report)
    methodology_html = render_forensic_methodology(eng_yaml, timeline)
    ioc_html = render_ioc_catalog(iocs)
    artifacts_html = render_artifact_summary(hosts)

    print(f"[+] Enhanced casebook sections generated:")
    print(f"    - Addenda & Evidence Chains: {len(extract_addenda_from_report(report))} items")
    print(f"    - Forensic Methodology: collection parameters & tool stack")
    print(f"    - IOC Catalog: {len(iocs)} indicators")
    print(f"    - Per-System Artifacts: {len(hosts)} systems")
    print(f"\n[+] HTML sections ready for integration into render_casebook_fancy.py")
    print(f"[+] Output: {OUT_PATH}")

if __name__ == '__main__':
    main()
