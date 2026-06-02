#!/usr/bin/env python3
"""
generate_dfir_casebook.py — Reusable DFIR Interactive Casebook Generator

Usage:
    python3 generate_dfir_casebook.py [--case <dir>] [--template <html>] [--out <html>]

Defaults:
    --case      .                          (current directory, must contain engagement/)
    --template  reference_casebook.html   (Aleemladha reference template)
    --out       casebook_<case_id>.html

Input structure expected under <case>/engagement/:
    engagement.yaml   — case metadata
    timeline.md       — UTC-timestamped events table
    report.md         — findings narrative
    hosts.csv         — host inventory

The generator:
    1. Removes sec-c2attrib (RE-based C2 tool attribution — requires separate RE analysis not in standard DFIR triage)
    2. Removes Recipe 3 from sec-proof (same reason)
    3. Replaces "AdaptixC2" / "Adaptix" specific-attribution text with generic "Unknown C2 Framework"
    4. Removes "RE-confirmed" claims (binary-level RE not performed in triage)
    5. Replaces the EVENTS JavaScript array with events from timeline.md
    6. Substitutes case title, client, headline from engagement.yaml
    7. Preserves ALL other sections, CSS, animations, and interactive features intact
"""

import argparse
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
parser = argparse.ArgumentParser(description="Generate interactive DFIR casebook")
parser.add_argument("--case",     default=".",                     help="Case directory containing engagement/")
parser.add_argument("--template", default="reference_casebook.html", help="Reference HTML template")
parser.add_argument("--out",      default=None,                    help="Output HTML filename")
args = parser.parse_args()

CASE_DIR = os.path.abspath(args.case)
ENG_DIR  = os.path.join(CASE_DIR, "engagement")
REF_HTML = os.path.join(CASE_DIR, args.template)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def read(path, default=""):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except FileNotFoundError:
        return default

def yaml_get(text, key, default="—"):
    m = re.search(rf'^{re.escape(key)}\s*:\s*["\']?(.*?)["\']?\s*$', text, re.MULTILINE)
    return m.group(1).strip() if m else default

def log(msg):
    print(f"[*] {msg}")

def ok(msg):
    print(f"    [✓] {msg}")

def warn(msg):
    print(f"    [!] {msg}", file=sys.stderr)

# ---------------------------------------------------------------------------
# Load inputs
# ---------------------------------------------------------------------------
log("Loading inputs...")
html = read(REF_HTML)
if not html:
    sys.exit(f"ERROR: Template not found: {REF_HTML}")

eng_yaml    = read(os.path.join(ENG_DIR, "engagement.yaml"))
timeline_md = read(os.path.join(ENG_DIR, "timeline.md"))
report_md   = read(os.path.join(ENG_DIR, "report.md"))
hosts_csv   = read(os.path.join(ENG_DIR, "hosts.csv"))

ok(f"Template:   {REF_HTML} ({len(html):,} bytes)")
ok(f"Engagement: {ENG_DIR}")

# Derive output path
case_id = yaml_get(eng_yaml, "engagement_id", "case")
out_path = args.out or os.path.join(CASE_DIR, f"casebook_{case_id.split('-')[0]}.html")

# ---------------------------------------------------------------------------
# STEP 1 — Remove sec-c2attrib (C2 tool RE-attribution section)
# ---------------------------------------------------------------------------
log("Step 1: Removing sec-c2attrib (RE-based C2 attribution)...")
before = len(html)
html = re.sub(
    r'<section[^>]*id="sec-c2attrib"[^>]*>.*?</section>',
    '',
    html,
    flags=re.DOTALL,
    count=1
)
delta = before - len(html)
if delta > 0:
    ok(f"Removed sec-c2attrib ({delta:,} bytes)")
else:
    warn("sec-c2attrib not found (already absent or different id)")

# ---------------------------------------------------------------------------
# STEP 2 — Remove Recipe 3 from sec-proof (AdaptixC2 VAD match recipe)
# ---------------------------------------------------------------------------
log("Step 2: Removing Recipe 3 (C2 binary RE analysis) from sec-proof...")
before = len(html)

# Recipe 3 is a <div> inside the grid — remove the specific div block
# Pattern: the <!-- Recipe 3 --> comment through end of that div
html = re.sub(
    r'\s*<!--\s*Recipe\s*3\s*[—–-]+\s*AdaptixC2[^>]*-->\s*'   # comment
    r'<div[^>]*>.*?</div>\s*',                                   # the recipe card div
    '\n    ',
    html,
    flags=re.DOTALL,
    count=1
)

# Also update the lede that says "three claims" → "two claims"
html = html.replace(
    "flagged three claims as the likeliest to be wrong: the impacket\n    attribution, the LSASS-dump actor, and the C2 family.",
    "flagged two claims as the likeliest to be wrong: the impacket\n    attribution and the LSASS-dump actor."
)

delta = before - len(html)
ok(f"Recipe 3 removed ({delta:,} bytes delta)")

# ---------------------------------------------------------------------------
# STEP 3 — Replace AdaptixC2 attribution text with evidence-grounded language
# ---------------------------------------------------------------------------
log("Step 3: Replacing AdaptixC2 attribution with evidence-grounded language...")

# We DO have evidence of: rnSylwOz.exe beaconing to 173.230.136.180:8443 (Volatility netscan)
# We DO NOT have: binary RE, source-to-binary match, git clone comparison
# Replace specific attribution claims; preserve factual C2 activity descriptions

replacements = [
    # Specific tool attribution → generic
    (r'AdaptixC2\b',                                       "Unknown C2 Framework"),
    (r'Adaptix\s+C2\b',                                    "Unknown C2 Framework"),
    (r'\bAdaptix\s+reflective-loader\b',                   "reflective loader"),
    (r'\bAdaptix\s+beacon\b',                              "C2 beacon"),
    (r'\bAdaptix\s+source\b',                              "C2 source"),
    (r'\bAdaptix\s+markers\b',                             "C2 indicators"),
    (r'\bAdaptix-specific\s+strings\b',                    "C2-specific strings"),
    (r'\bAdaptix\b(?!\s+/)',                               "Unknown C2"),
    # RE analysis claims
    (r'\bRE-confirmed\b',                                  "evidence-supported"),
    # YARA file references
    (r'adaptix_null404\.yar',                              "c2_ioc.yar"),
    (r'adaptix_beacon_reflective_loader[^\s<"\']*',        "c2_reflective_loader"),
    (r'adaptix_reflective_loader_in_memory',               "c2_in_memory"),
    (r'adaptix_\*\s+rules',                                "C2 detection rules"),
    (r'adaptix_\*',                                        "c2_*"),
    # git clone reference (RE workflow not in evidence)
    (r'git\s+clone\s+https?://[^\s<"\']+adaptix[^\s<"\']*', "# [C2 source analysis not performed in this engagement]"),
    # Source match claims
    (r'five grep-match hits against the (?:Adaptix|Unknown C2) repo',
                                                           "signature matches against known C2 indicators"),
    (r'matches (?:Adaptix|Unknown C2) public source 5-for-5',
                                                           "matches known C2 indicators 5-for-5"),
    (r'source-to-binary (?:Adaptix|Unknown C2) match',    "binary C2 indicator match"),
    (r'Addendum V[\'`]?s source-to-binary.*?match',       "binary indicator analysis"),
    # Column header in tables
    (r'C2 attribution\s*·\s*(?:Adaptix|Unknown) C2',      "C2 attribution · Unknown C2 Framework (rnSylwOz.exe)"),
    (r'(?:Adaptix|Unknown C2) C2 (?:HTTPS )?listener',    "Unknown C2 Framework listener"),
    # GitHub path reference embedded in tech analysis (exposes specific source attribution)
    (r'Unknown C2 Framework/AdaptixServer/extenders/[^\s<"\'`]+',
                                                           "[C2 source path — RE analysis not performed in this engagement]"),
    # "Adaptix / Sliver / Havoc" — keep this, it's generic threat landscape context
    # (no replacement needed — "Adaptix/Sliver/Havoc" is factual threat landscape language)
]

count_total = 0
for pattern, replacement in replacements:
    new_html, n = re.subn(pattern, replacement, html, flags=re.IGNORECASE)
    if n:
        count_total += n
        html = new_html
        ok(f"  '{pattern[:50]}' → '{replacement[:50]}' ({n}×)")

ok(f"Total replacements: {count_total}")

# Special case: "Adaptix/Sliver/Havoc" — restore (it's generic context, not tool attribution)
html = html.replace("Unknown C2/Sliver/Havoc", "Adaptix/Sliver/Havoc")
html = html.replace("Unknown C2 / Sliver / Havoc", "Adaptix/Sliver/Havoc")

# ---------------------------------------------------------------------------
# STEP 4 — Parse timeline events
# ---------------------------------------------------------------------------
log("Step 4: Parsing timeline events from engagement/timeline.md...")

events = []
current_phase = None

for line in timeline_md.split('\n'):
    # Phase marker
    phase_match = re.match(r'^##\s+Phase\s+(\d+)\s+[·•]\s+(.+)', line)
    if phase_match:
        current_phase = phase_match.group(2).strip()
        continue

    # Event row: | 2026-03-08 HH:MM:SS | HOST | description | source |
    if re.match(r'^\|\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', line):
        cells = [c.strip() for c in line.split('|')[1:-1]]
        if len(cells) >= 3:
            time_match = re.search(r'(\d{2}:\d{2}:\d{2})', cells[0])
            if time_match:
                events.append({
                    't':      time_match.group(1),
                    'host':   cells[1],
                    'desc':   cells[2],
                    'source': cells[3] if len(cells) > 3 else "",
                    'phase':  current_phase or "—",
                })

ok(f"{len(events)} events from {len(set(e['phase'] for e in events))} phases")

if not events:
    warn("No events parsed — check timeline.md format")

# Assign act codes based on phase names
phase_act_map = {
    "Unauthenticated Recon":          "I",
    "Initial Foothold":               "I",
    "Cloud Pivot":                    "VI",
    "Privilege Escalation":           "II",
    "Lateral Movement":               "III",
    "Domain Dominance":               "IV",
    "Ransomware":                     "V",
    "Domain Dominance & Ransomware":  "V",
}

for evt in events:
    act = "I"
    for key, val in phase_act_map.items():
        if key.lower() in evt['phase'].lower():
            act = val
            break
    evt['act'] = act

# ---------------------------------------------------------------------------
# STEP 5 — Build EVENTS JavaScript array
# ---------------------------------------------------------------------------
log("Step 5: Building EVENTS JavaScript array...")

# Map timeline host names → SVG node short IDs (data-host attributes on <g> nodes).
# The reference template SVG uses short IDs: IIS, SVR01, DC01, DC02, WS01, WS02,
# OP, TOOL, ROLE, S3, SINK.  Timeline host names vary by case (e.g. IIS-SERV-PROD,
# LAF-SVR01).  Build a normalization map from hosts.csv (host column → SVG id).
HOST_NORM_MAP = {}
for line in hosts_csv.split('\n')[1:]:  # skip header
    cols = [c.strip() for c in line.split(',')]
    if len(cols) >= 1 and cols[0]:
        full = cols[0]                          # e.g. IIS-SERV-PROD
        # Derive short ID: strip common prefixes, take last component
        short = re.sub(r'^(?:LAF|laf)-', '', full, flags=re.IGNORECASE)  # LAF-SVR01 → SVR01
        short = re.sub(r'-SERV-PROD$', '', short, flags=re.IGNORECASE)   # IIS-SERV-PROD → IIS
        short = re.sub(r'^AWS-\d+$', 'S3', short, flags=re.IGNORECASE)   # AWS-464... → S3
        HOST_NORM_MAP[full] = short

def norm_host(h):
    return HOST_NORM_MAP.get(h, h)

# Collect unique timeline host names and their normalized SVG IDs for HOST_NORM JS
unique_hosts = {e['host']: norm_host(e['host']) for e in events}

js_lines = ["const EVENTS = ["]
for i, evt in enumerate(events):
    desc = evt['desc'].replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ")
    comma = "," if i < len(events) - 1 else ""
    js_lines.append(
        f"  {{ t:'{evt['t']}', host:'{evt['host']}', act:'{evt['act']}', "
        f"edge:null, desc:'{desc}' }}{comma}"
    )
js_lines.append("];")
js_lines.append("EVENTS.forEach(e => e.sec = toSec(e.t));")

# Build HOST_NORM JS map so the replay engine can resolve timeline host names
# to SVG node data-host IDs.  Injected immediately after the EVENTS array.
norm_entries = ", ".join(f"'{k}':'{v}'" for k, v in sorted(unique_hosts.items()) if k != v)
js_lines.append(f"// Host name normalization: timeline names → SVG data-host IDs")
js_lines.append(f"const HOST_NORM = {{ {norm_entries} }};")
js_lines.append("function normHost(h) { return HOST_NORM[h] || h; }")

# Inject flashNode() — positions a cmd-flash popup near the active SVG host node
js_lines.append("""
// Flash popup near SVG host node when an event fires
let _graphWrap = null;
function flashNode(svgId, label, desc, colorCls) {
  if (!_graphWrap) _graphWrap = document.querySelector('.graph-wrap');
  if (!_graphWrap) return;
  const node = document.getElementById('n-' + svgId);
  if (!node) return;
  const wrapRect = _graphWrap.getBoundingClientRect();
  const nodeRect = node.getBoundingClientRect();
  if (!wrapRect.width) return;
  const left = (nodeRect.left + nodeRect.width / 2) - wrapRect.left;
  const top  = (nodeRect.top  + nodeRect.height / 2) - wrapRect.top;
  _graphWrap.querySelectorAll('.cmd-flash[data-node="' + svgId + '"]').forEach(el => el.remove());
  const div = document.createElement('div');
  div.className = 'cmd-flash ' + (colorCls || 'green');
  div.dataset.node = svgId;
  div.style.left = left + 'px';
  div.style.top  = top  + 'px';
  const shortDesc = desc.length > 120 ? desc.slice(0, 117) + '\\u2026' : desc;
  div.innerHTML = '<span class="cf-label">' + label + '</span><span class="cf-cmd">' + shortDesc + '</span>';
  _graphWrap.appendChild(div);
  setTimeout(() => { if (div.parentNode) div.remove(); }, 2700);
}
""")

events_js = "\n".join(js_lines) + "\n"

ok(f"EVENTS array: {len(events)} entries")
ok(f"HOST_NORM:    {len([k for k,v in unique_hosts.items() if k != v])} mappings ({', '.join(f'{k}→{v}' for k,v in sorted(unique_hosts.items()) if k != v)})")

# Replace EVENTS array in template (pattern matches through EVENTS.forEach line)
events_pattern = r'const EVENTS = \[.*?\];.*?EVENTS\.forEach\(e => e\.sec = toSec\(e\.t\)\);'
html, n = re.subn(events_pattern, lambda _: events_js, html, flags=re.DOTALL, count=1)
if n:
    ok("EVENTS array + HOST_NORM + flashNode() replaced in template")
else:
    warn("EVENTS pattern not found — array may not have been replaced")

# Patch applyEventsForTime to use normHost() for hostSet and host-active detection.
# This ensures SVG nodes pulse even when event host names don't exactly match
# the short data-host IDs on the SVG <g> elements.
old_hostset = "hostSet.add(ev.host);"
new_hostset = "hostSet.add(normHost(ev.host));"
if old_hostset in html:
    html = html.replace(old_hostset, new_hostset, 1)
    ok("Patched hostSet.add() to use normHost()")

old_active = "e.host === h && e.sec <= sec && sec - e.sec < 5"
new_active  = "normHost(e.host) === h && e.sec <= sec && sec - e.sec < 8"
if old_active in html:
    html = html.replace(old_active, new_active, 1)
    ok("Patched host-active detection to use normHost() + 8s window")

# Wire flashNode() call into the event card update block
old_card = "const ev = EVENTS[latestIdx];\n      const nxt = EVENTS[latestIdx + 1];"
new_card  = ("const ev = EVENTS[latestIdx];\n"
             "      flashNode(normHost(ev.host), ev.t + ' · ' + (HOST_LABEL[normHost(ev.host)] || ev.host), ev.desc, HOST_COLOR[normHost(ev.host)] || 'green');\n"
             "      const nxt = EVENTS[latestIdx + 1];")
if old_card in html:
    html = html.replace(old_card, new_card, 1)
    ok("Wired flashNode() into event card update")

# ---------------------------------------------------------------------------
# STEP 6 — Case metadata substitutions
# ---------------------------------------------------------------------------
log("Step 6: Applying case metadata substitutions...")

headline  = yaml_get(eng_yaml, "headline", "")
client    = yaml_get(eng_yaml, "client",   "Unknown Client")
case_name = yaml_get(eng_yaml, "engagement_id", case_id).split("-")[0]

# Case title in hero
html = re.sub(
    r'<h1 class="case-title">.*?</h1>',
    f'<h1 class="case-title">{case_name}</h1>',
    html,
    flags=re.DOTALL,
    count=1
)

# HTML <title> tag
html = re.sub(
    r'<title>[^<]*</title>',
    f'<title>{case_name} — DFIR Casebook</title>',
    html,
    count=1
)

ok(f"Case title: {case_name}")
ok(f"Client:     {client}")

# ---------------------------------------------------------------------------
# STEP 6b — Strip ALF-specific CTF scorecard widgets
# These values (72/72 solves, 71/71 verified, 7th placement, 22 burned attempts,
# 475 score) are hard-coded to the ALF/LeHack 2024 CTF run and are wrong for any
# other case. Replace with neutral/evidence-grounded language.
# ---------------------------------------------------------------------------
log("Step 6b: Replacing ALF-specific CTF scorecard widgets with case-verified counts...")

# Read CTF metrics from engagement.yaml (defaults to neutral if not set)
ctf_total    = yaml_get(eng_yaml, "ctf_questions_total",   "—")
ctf_answered = yaml_get(eng_yaml, "ctf_questions_answered","—")
ctf_verified = yaml_get(eng_yaml, "ctf_answers_verified",  "—")
ctf_eng_type = yaml_get(eng_yaml, "ctf_engagement_type",   "Post-CTF analysis")

solves_str   = f"{ctf_answered} / {ctf_total}"
verified_str = f"{ctf_verified} / {ctf_verified}"

# Hero metadata row: "Resolution 72 / 72 solves · 71 / 71 Inspector-verified · cleared"
html = re.sub(
    r'72\s*/\s*72\s+solves\s*·\s*71\s*/\s*71\s+Inspector-verified\s*·\s*cleared',
    f'{solves_str} CTF questions answered · {verified_str} evidence-backed · cleared',
    html
)

# Scoreboard widget: Solves 72/72 "all challenges"
html = re.sub(
    r'(<div class="k">Solves</div>\s*<div class="v">)\s*72\s*/\s*72\s*(<\/div>\s*<div class="d">)\s*all challenges',
    rf'\g<1>{solves_str}\2CTF questions',
    html
)

# Scoreboard widget: Verified 71/71 "SoloAgent oracle"
html = re.sub(
    r'(<div class="k">Verified</div>\s*<div class="v[^"]*">)\s*71\s*/\s*71\s*(<\/div>\s*<div class="d">)\s*SoloAgent oracle',
    rf'\g<1>{verified_str}\2evidence-backed',
    html
)

# Scoreboard widget: Final Score 475 "cap reached" — remove entirely (score requires
# live CTF participation; cannot be determined from post-CTF analysis alone)
html = re.sub(
    r'<div class="score-cell">\s*<div class="k">Final Score</div>.*?</div>\s*</div>',
    '',
    html,
    flags=re.DOTALL,
    count=1
)

# Scoreboard widget: Placement "7th" "tied at cap" — remove entirely (no CTF submission)
html = re.sub(
    r'<div class="score-cell">\s*<div class="k">Placement</div>.*?</div>\s*</div>',
    '<div class="score-cell"><div class="k">Engagement</div><div class="v">Post-CTF</div><div class="d">analysis only</div></div>',
    html,
    flags=re.DOTALL,
    count=1
)

# Scoreboard widget: Burned Attempts "22" "logged as rejects" — remove entirely
# (only meaningful for live CTF submissions; not applicable for post-CTF analysis)
html = re.sub(
    r'<div class="score-cell">\s*<div class="k">Burned Attempts</div>.*?</div>\s*</div>',
    '',
    html,
    flags=re.DOTALL,
    count=1
)

# Ledger artifact-backed count "71 / 71" — value is in a sibling <div class="v"> tag
html = re.sub(
    r'(Artifact-backed</div><div class="v">)\s*71\s*/\s*71',
    r'\1— / —',
    html
)
# Fallback for plain-text variant
html = re.sub(r'Artifact-backed\s+71\s*/\s*71', 'Artifact-backed — / —', html)

# HTML comment above sec-rejects
html = re.sub(r'<!--\s*=+\s*BURNED ATTEMPTS\s*=+\s*-->', '<!-- FORENSIC JUDGEMENT CALLS -->', html, flags=re.IGNORECASE)

# sec-rejects section tag: "// 12 burned attempts · forensic judgement calls"
html = re.sub(
    r'//\s*12\s+burned\s+attempts\s*·\s*forensic\s+judgement\s+calls',
    '// forensic judgement calls',
    html,
    flags=re.IGNORECASE
)

# sec-rejects section intro: remove CTF "burns attempts" framing
html = re.sub(
    r'The board burns attempts on wrong answers\.',
    'These findings were identified during forensic analysis.',
    html
)

ok("Scorecard widgets neutralised (72/72 solves, 71/71 verified, 7th placement, 22 burned attempts, 475 score)")

# ---------------------------------------------------------------------------
# STEP 6c — Map MITRE ATT&CK techniques into the master-timeline phase tables
# Adds an "ATT&CK" column to every phase table in sec-master-timeline, tagging
# each event row by keyword. Baseline / infrastructure rows correctly show "—".
# Also writes an ATT&CK Navigator layer JSON to ./analysis/ for import at
# https://mitre-attack.github.io/attack-navigator/
# ---------------------------------------------------------------------------
log("Step 6c: Mapping MITRE ATT&CK techniques into master timeline...")

# technique_id → (tactic_shortname, hex_color, display_name)
ATTACK_TECH = {
    "T1190":    ("initial-access",       "#e53935", "Exploit Public-Facing Application"),
    "T1059.003":("execution",            "#f57c00", "Windows Command Shell"),
    "T1569.002":("execution",            "#f57c00", "Service Execution"),
    "T1105":    ("command-and-control",  "#6d4c41", "Ingress Tool Transfer"),
    "T1505.003":("persistence",          "#fb8c00", "Web Shell"),
    "T1136.002":("persistence",          "#fb8c00", "Create Domain Account"),
    "T1098":    ("persistence",          "#fb8c00", "Account Manipulation"),
    "T1098.001":("persistence",          "#fb8c00", "Additional Cloud Credentials"),
    "T1053.005":("persistence",          "#fb8c00", "Scheduled Task"),
    "T1546.012":("persistence",          "#fb8c00", "IFEO Injection"),
    "T1546.013":("persistence",          "#fb8c00", "PowerShell Profile"),
    "T1574.009":("privilege-escalation", "#8e24aa", "Unquoted Service Path"),
    "T1055":    ("defense-evasion",      "#1e88e5", "Process Injection"),
    "T1112":    ("defense-evasion",      "#1e88e5", "Modify Registry"),
    "T1070.001":("defense-evasion",      "#1e88e5", "Clear Windows Event Logs"),
    "T1036.003":("defense-evasion",      "#1e88e5", "Rename System Utilities"),
    "T1021.001":("lateral-movement",     "#039be5", "Remote Desktop Protocol"),
    "T1021.002":("lateral-movement",     "#039be5", "SMB/Windows Admin Shares"),
    "T1570":    ("lateral-movement",     "#039be5", "Lateral Tool Transfer"),
    "T1003.001":("credential-access",    "#b71c1c", "LSASS Memory"),
    "T1003.003":("credential-access",    "#b71c1c", "NTDS"),
    "T1555":    ("credential-access",    "#b71c1c", "Credentials from Password Stores"),
    "T1552.005":("credential-access",    "#b71c1c", "Cloud Instance Metadata API"),
    "T1018":    ("discovery",            "#00897b", "Remote System Discovery"),
    "T1087":    ("discovery",            "#00897b", "Account Discovery"),
    "T1082":    ("discovery",            "#00897b", "System Information Discovery"),
    "T1016":    ("discovery",            "#00897b", "System Network Config Discovery"),
    "T1049":    ("discovery",            "#00897b", "System Network Connections"),
    "T1482":    ("discovery",            "#00897b", "Domain Trust Discovery"),
    "T1560.001":("collection",           "#43a047", "Archive via Utility"),
    "T1530":    ("collection",           "#43a047", "Data from Cloud Storage"),
    "T1048.002":("exfiltration",         "#7cb342", "Exfil Over Asymmetric Encrypted Protocol"),
    "T1486":    ("impact",               "#37474f", "Data Encrypted for Impact"),
    "T1490":    ("impact",               "#37474f", "Inhibit System Recovery"),
}

# (regex on event text, [technique IDs]) — order independent, all matches accumulate
ATTACK_EVENT_MAP = [
    (r'url=.*(?:cat|ls|dir|type|whoami|&&|;)',            ["T1190"]),
    (r'cmd.injection|CheckStatus|GET.injection',           ["T1190"]),
    (r'certutil.*urlcache|certutil.*so\.aspx',             ["T1190", "T1105"]),
    (r'certutil.*iis\.exe',                                ["T1105"]),
    (r'POST.*so\.aspx|so\.aspx.*whoami|so\.aspx.*hostname',["T1505.003", "T1082", "T1016", "T1049", "T1087", "T1482"]),
    (r'beacon.*TCP|TCP.*8443|:8443',                       ["T1105"]),
    (r'SolarWinds.*TFTP|SolarWinds\.exe|unquoted.service', ["T1574.009"]),
    (r'rnSylwOz.*ADMIN\$|ADMIN\$.*rnSylwOz|service.*rnSylwOz', ["T1569.002", "T1021.002"]),
    (r'explorer.*inject|inject.*explorer|RWX PE|malfind|CreateRemoteThread', ["T1055"]),
    (r'net user.*serviceaccount|serviceaccount.*add.*domain', ["T1136.002"]),
    (r"serviceaccount.*Domain Admin|Domain Admin.*serviceaccount|group.*Domain Admins.*add|EID 4728", ["T1136.002", "T1098"]),
    (r'abedgdaa|LSASS.*dump|dump.*LSASS|opens LSASS',      ["T1003.001"]),
    (r'secretsdump|ntds\.dit|ZIFylmKF|shadow.copy.*ntds|impacket.*VSS|impacket smbexec|NTDS pickup', ["T1003.003", "T1569.002"]),
    (r'DonPAPI|DPAPI.*[Mm]aster[Kk]ey|Dashlane|MasterKey backup', ["T1555"]),
    (r'RDP.*session|RDP.*open|RDP.*logon|RDP.*SVR01|RDP.*WS|RDP from|RDP as|MSTSC', ["T1021.001"]),
    (r'msupdate|data\.cab|makecab',                        ["T1560.001", "T1036.003"]),
    (r'aws_backup\.exe',                                   ["T1105"]),
    (r'FileZilla|fzsftp|SFTP.*172\.236|172\.236.*22|SFTP exfil', ["T1048.002"]),
    (r'IFEO|Image File Execution|taskmgr.*Debugger',       ["T1546.012"]),
    (r'PowerShell.profile|profile\.ps1|PS-profile',        ["T1546.013"]),
    (r'OlgyLYbd|sysAV\.bat|[Ss]cheduled task|schtask',     ["T1053.005"]),
    (r'Advanced IP Scanner|IP.scan|nmap|scans 10\.',       ["T1018"]),
    (r'nltest|dclist',                                     ["T1482", "T1087"]),
    (r'LogDel\.bat|wevtutil.*cl|event.log.*clear|wipes \d+ channels', ["T1070.001"]),
    (r'DisableRestrictedAdmin|registry.*PtH|reg add.*Restricted', ["T1112"]),
    (r'GetCallerIdentity|IMDS|iam.security-credentials|STS theft', ["T1552.005"]),
    (r'CreateAccessKey',                                   ["T1098.001"]),
    (r'S3.*GetObject|GetObject.*S3|s3.*cp|aws s3',         ["T1530"]),
    (r'IamBatman.*SYSVOL|SYSVOL.*IamBatman|pulls.*SYSVOL|dropped to SYSVOL|DFSR replica', ["T1570"]),
    (r'vssadmin.*delete|delete.*shadow|bcdedit',           ["T1490"]),
    (r'IamBatman|\.bWqQUx|encrypt C:|encrypted file|ransomware', ["T1486"]),
]

def attack_ttps_for(event_html):
    plain = re.sub(r'<[^>]+>', '', event_html)
    found = []
    for pattern, ttps in ATTACK_EVENT_MAP:
        if re.search(pattern, plain, re.IGNORECASE):
            for t in ttps:
                if t not in found:
                    found.append(t)
    return found

def attack_cell(ttps):
    if not ttps:
        return '<td style="color:var(--dim);font-size:.8em">—</td>'
    badges = []
    for t in ttps:
        color = ATTACK_TECH.get(t, ("", "#888", ""))[1]
        badges.append(
            f'<code style="font-size:.75em;background:rgba(255,255,255,.06);'
            f'border:1px solid {color}55;color:{color};padding:1px 5px;'
            f'border-radius:2px;white-space:nowrap">{t}</code>'
        )
    return '<td style="white-space:nowrap;min-width:8em">' + ' '.join(badges) + '</td>'

mt = re.search(r'(<section[^>]*id="sec-master-timeline"[^>]*>)(.*?)(</section>)', html, re.DOTALL)
if mt:
    mt_body = mt.group(2)
    # Add ATT&CK header to every <thead> row that doesn't already have one
    mt_body = re.sub(
        r'(<thead>.*?<tr[^>]*>)(.*?)(</tr>.*?</thead>)',
        lambda m: m.group(1) + m.group(2)
                  + ('' if 'ATT&amp;CK' in m.group(2) else '<th>ATT&amp;CK</th>')
                  + m.group(3),
        mt_body, flags=re.DOTALL
    )
    # Add ATT&CK cell to every tbody data row (matches <tr ...><td ...>)
    def _row_with_ttp(m):
        row = m.group(0)
        cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
        event_text = cells[2] if len(cells) >= 3 else ""
        return row.replace('</tr>', attack_cell(attack_ttps_for(event_text)) + '</tr>', 1)
    mt_body = re.sub(r'<tr[^>]*>\s*<td.*?</tr>', _row_with_ttp, mt_body, flags=re.DOTALL)

    html = html[:mt.start()] + mt.group(1) + mt_body + mt.group(3) + html[mt.end():]

    # Count coverage
    new_mt = re.search(r'<section[^>]*id="sec-master-timeline"[^>]*>(.*?)</section>', html, re.DOTALL).group(1)
    rows = re.findall(r'<tr[^>]*>\s*<td.*?</tr>', new_mt, re.DOTALL)
    tagged = sum(1 for r in rows if re.search(r'T1[\d.]+', r))
    ok(f"ATT&CK column added to {len(rows)} rows ({tagged} tagged · {len(rows)-tagged} baseline/infra)")

    # Build ATT&CK Navigator layer from observed techniques
    observed = set()
    for r in rows:
        cs = re.findall(r'<td[^>]*>(.*?)</td>', r, re.DOTALL)
        if len(cs) >= 3:
            observed.update(attack_ttps_for(cs[2]))
    nav_layer = {
        "name": f"{case_name} — ATT&CK Coverage",
        "versions": {"attack": "16", "navigator": "5.0.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"MITRE ATT&CK technique coverage for {case_id}, mapped from master-timeline events.",
        "filters": {"platforms": ["Windows", "IaaS"]},
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": [
            {"techniqueID": t, "tactic": ATTACK_TECH[t][0], "color": ATTACK_TECH[t][1],
             "comment": ATTACK_TECH[t][2], "enabled": True, "showSubtechniques": True}
            for t in sorted(observed) if t in ATTACK_TECH
        ],
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
        "metadata": [{"name": "case", "value": case_id}],
        "showTacticRowBackground": True, "tacticRowBackground": "#1a1f27",
    }
    nav_dir = os.path.join(CASE_DIR, "analysis")
    os.makedirs(nav_dir, exist_ok=True)
    nav_path = os.path.join(nav_dir, f"{case_name}_navigator_layer.json")
    with open(nav_path, "w", encoding="utf-8") as f:
        json.dump(nav_layer, f, indent=2)
    ok(f"ATT&CK Navigator layer: {nav_path} ({len(nav_layer['techniques'])} techniques)")
else:
    warn("sec-master-timeline not found — ATT&CK column skipped")

# ---------------------------------------------------------------------------
# STEP 7 — Redact credentials for publication (prevents GitHub secret scanning blocks)
# Evidence files retain originals; HTML output uses clearly-redacted placeholders.
# ---------------------------------------------------------------------------
log("Step 7: Redacting credentials for public publication...")

# AWS Access Key IDs: AKIA[16 uppercase alphanumeric] (long-term)
html, n_key = re.subn(r'\bAKIA[A-Z0-9]{16}\b', 'AKIA[REDACTED-FOR-PUBLICATION]', html)
# AWS STS temporary key IDs: ASIA[16 uppercase alphanumeric]
html, n_sts = re.subn(r'\bASIA[A-Z0-9]{16}\b', 'ASIA[REDACTED-FOR-PUBLICATION]', html)
# AWS Secret Access Keys: 40-char base64-like strings following "SecretAccessKey"
html, n_secret = re.subn(
    r'(SecretAccessKey\s*[:\s]+)[A-Za-z0-9+/]{40}',
    r'\1[REDACTED-FOR-PUBLICATION]',
    html
)

ok(f"Redacted {n_key} AKIA key IDs, {n_sts} ASIA STS key IDs, and {n_secret} secret keys")

# ---------------------------------------------------------------------------
# STEP 8 — Verify sections
# ---------------------------------------------------------------------------
log("Step 8: Verifying section completeness...")

ref_html     = read(REF_HTML)
ref_sections = set(re.findall(r'id="(sec-[^"]*)"', ref_html))
gen_sections = set(re.findall(r'id="(sec-[^"]*)"', html))
expected_removed = {"sec-c2attrib"}
missing = ref_sections - gen_sections - expected_removed

ok(f"Sections in output: {len(gen_sections)}/{len(ref_sections)} "
   f"(removed: {expected_removed})")

if missing:
    warn(f"Unexpected missing sections: {missing}")
else:
    ok("All expected sections preserved")

# ---------------------------------------------------------------------------
# STEP 9 — Write output
# ---------------------------------------------------------------------------
log(f"Step 9: Writing {out_path}...")
os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
with open(out_path, "w", encoding="utf-8") as f:
    f.write(html)

# Final evidence check
# "Adaptix/Sliver/Havoc" is acceptable threat-landscape context (not specific attribution)
remaining_adaptix = len([m for m in re.finditer(r'\badaptix\b', html, re.IGNORECASE)
                         if not re.search(r'adaptix\s*/\s*Sliver|Sliver.*adaptix', m.string[max(0,m.start()-30):m.end()+30], re.IGNORECASE)])
remaining_re_conf = len(re.findall(r'RE-confirmed', html))

print()
print("=" * 70)
print(f"  OUTPUT:   {out_path}")
print(f"  SIZE:     {len(html) / 1024:.0f} KB")
print(f"  EVENTS:   {len(events)}")
print(f"  SECTIONS: {len(gen_sections)}/28 (sec-c2attrib intentionally omitted)")
print()
print(f"  Evidence integrity checks:")
print(f"    AdaptixC2 attribution remaining:  {remaining_adaptix} (target: 0)")
print(f"    RE-confirmed claims remaining:    {remaining_re_conf} (target: 0)")
print()
if remaining_adaptix == 0 and remaining_re_conf == 0:
    print("  [✓] PASS — casebook is grounded in collected evidence only")
else:
    print("  [!] REVIEW — some attribution text may remain (check manually)")
print("=" * 70)
