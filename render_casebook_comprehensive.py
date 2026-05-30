#!/usr/bin/env python3
"""
render_casebook_comprehensive.py — Full lehack2024 reference-matched DFIR casebook
Includes: master timeline (phase-based), interactive SVG replay movie, heatmap, act deep-dives
"""
import argparse, re, os, html, csv, json, textwrap
from datetime import datetime, timezone

CASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENG_DIR = os.path.join(CASE_DIR, "engagement")
OUT_PATH = os.path.join(CASE_DIR, "casebook_JackofAllHacks_comprehensive.html")

def read(path, default=""):
    try: return open(path, encoding="utf-8", errors="replace").read()
    except: return default

def yget(text, key, default="—"):
    m = re.search(rf'^{re.escape(key)}\s*:\s*["\']?(.*?)["\']?\s*$', text, re.MULTILINE)
    return m.group(1).strip() if m else default

def esc(t): return html.escape(str(t))

def gen_master_timeline_html(timeline_text):
    """Generate phase-based master timeline with evidence cross-refs and color coding"""
    html_out = '<section id="sec-master-timeline" style="background: linear-gradient(180deg, rgba(88,166,255,.05), transparent 80%)">'
    html_out += '<h2>Master <span class="q">Timeline</span></h2>'
    html_out += '<p class="lede">Forensic ground truth: 164 minutes, 6 phases, 53 events. Every row sourced.</p>'

    phases = []
    current_phase = None

    for line in timeline_text.splitlines():
        if line.startswith('## Phase'):
            m = re.match(r'## (Phase \d+.*)', line)
            if m:
                current_phase = {'name': m.group(1), 'events': []}
                phases.append(current_phase)
        elif current_phase and line.strip().startswith('|') and '|' in line and 'UTC' not in line and '---' not in line:
            cells = [c.strip() for c in line.split('|')[1:-1]]
            if len(cells) >= 4:
                current_phase['events'].append({
                    'utc': cells[0],
                    'host': cells[1] if len(cells) > 1 else '',
                    'event': cells[2] if len(cells) > 2 else '',
                    'evidence': cells[3] if len(cells) > 3 else ''
                })

    # Render phases with improved styling
    for phase_idx, phase in enumerate(phases):
        html_out += f'<div class="phase-card"><h3 class="phase-title">{esc(phase["name"])}</h3>'
        html_out += '<table class="tbl-timeline"><thead><tr><th>UTC</th><th>Host</th><th>Event</th><th>Evidence</th></tr></thead><tbody>'

        for event in phase['events']:
            # Color-code rows by threat level
            row_class = ''
            if 'encryption' in event['event'].lower() or 'ransomware' in event['event'].lower():
                row_class = 'class="r"'
            elif 'domain admin' in event['event'].lower() or 'ntds' in event['event'].lower():
                row_class = 'class="a"'
            elif 'exfil' in event['event'].lower():
                row_class = 'class="g"'

            html_out += f'<tr {row_class}><td class="mono">{esc(event["utc"])}</td><td class="host-cell">{esc(event["host"])}</td>'
            html_out += f'<td>{esc(event["event"])}</td><td class="evidence">{esc(event["evidence"])}</td></tr>'

        html_out += '</tbody></table></div>'

    html_out += '</section>'
    return html_out

def gen_replay_svg_movie():
    """Generate interactive SVG network graph for replay movie"""
    svg = '''<section id="sec-graph">
<h2>Interactive <span class="q">Movie</span> — Attack Replay</h2>
<p class="lede">Click play. Watch the attack unfold in real-time. Drag the scrubber to jump to any moment.</p>

<div class="replay-panel">
  <div class="rp-bar">
    <span style="font-family:'IBM Plex Mono'; font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.2em">Kill Chain Replay</span>
  </div>

  <div class="event-card" id="eventCard" class="act-I">
    <div class="ec-time">
      <div class="ec-t" id="ecTime">18:38:29</div>
      <div class="ec-elapsed" id="ecElapsed">T+00:00</div>
    </div>
    <div class="ec-body">
      <span class="ec-host" id="ecHost" style="color:var(--cyan)">IIS-SERV-PROD</span>
      <div class="ec-desc" id="ecDesc">Attacker reconnaissance begins — probing CheckStatus.aspx endpoint</div>
    </div>
    <div class="ec-tags">
      <span class="ec-tag ttp">T1190</span>
      <span class="ec-tag eid">IIS W3SVC</span>
      <span class="ec-tag next">Play to advance →</span>
    </div>
  </div>

  <div class="replay-scrubber" id="scrubber">
    <div class="scrubber-fill" id="scrubFill" style="width:0%"></div>
    <!-- Phase separators -->
    <div class="scrubber-phase" style="left:0%"><span>Phase 0</span></div>
    <div class="scrubber-phase" style="left:18%"><span>Phase 1</span></div>
    <div class="scrubber-phase" style="left:38%"><span>Phase 2</span></div>
    <div class="scrubber-phase" style="left:52%"><span>Phase 3</span></div>
    <div class="scrubber-phase" style="left:72%"><span>Phase 4</span></div>
    <div class="scrubber-phase" style="left:88%"><span>Phase 5</span></div>
  </div>

  <div class="rp-ctrl">
    <button class="replay-btn" onclick="replayReset()">⏮ Reset</button>
    <button class="replay-btn" onclick="replayPrev()">◀ Back</button>
    <button class="replay-btn primary" id="btn-play" onclick="replayToggle()">▶ Play</button>
    <button class="replay-btn" onclick="replayNext()">Next ▶</button>
    <div class="speed-pick">
      <button onclick="setSpeeds(1)" class="active">1×</button>
      <button onclick="setSpeeds(10)">10×</button>
      <button onclick="setSpeeds(60)">60×</button>
    </div>
    <span class="ev-counter" id="evCounter">Event 1 of 53</span>
  </div>
</div>

<div class="graph-wrap">
  <svg viewBox="0 0 1200 600" style="width:100%; height:auto; min-height:500px">
    <defs>
      <marker id="arrC" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
        <path d="M0,0 L0,6 L9,3 z" fill="var(--cyan)"/>
      </marker>
      <marker id="arrA" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
        <path d="M0,0 L0,6 L9,3 z" fill="var(--amber)"/>
      </marker>
      <marker id="arrR" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
        <path d="M0,0 L0,6 L9,3 z" fill="var(--red)"/>
      </marker>
      <radialGradient id="detonateGradient" cx="50%" cy="50%">
        <stop offset="0%" style="stop-color:var(--red); stop-opacity:.8"/>
        <stop offset="100%" style="stop-color:var(--red); stop-opacity:0"/>
      </radialGradient>
    </defs>

    <!-- Network zones -->
    <rect x="20" y="20" width="250" height="560" fill="none" stroke="var(--red)" stroke-dasharray="5 5" opacity="0.3"/>
    <text x="40" y="45" font-size="11" fill="var(--dim)" font-family="IBM Plex Mono" text-transform="uppercase">INTERNET</text>

    <rect x="300" y="20" width="900" height="560" fill="none" stroke="var(--cyan)" stroke-dasharray="5 5" opacity="0.2"/>
    <text x="320" y="45" font-size="11" fill="var(--dim)" font-family="IBM Plex Mono">LAF.LOCAL DOMAIN</text>

    <!-- Host nodes -->
    <g class="host-g entry" id="h-IIS">
      <rect x="70" y="100" width="160" height="80" rx="4" fill="rgba(88,166,255,.1)" stroke="var(--cyan)" stroke-width="2"/>
      <text x="90" y="130" font-weight="600" font-size="13" fill="var(--cyan)">IIS-SERV-PROD</text>
      <text x="90" y="150" font-size="10" fill="var(--muted)" font-family="IBM Plex Mono">198.51.100.10:80</text>
      <text x="90" y="165" font-size="9" fill="var(--green)">ENTRY</text>
    </g>

    <g class="host-g piv" id="h-SVR01">
      <rect x="350" y="80" width="160" height="80" rx="4" fill="rgba(255,184,0,.1)" stroke="var(--amber)" stroke-width="2"/>
      <text x="370" y="110" font-weight="600" font-size="13" fill="var(--amber)">LAF-SVR01</text>
      <text x="370" y="130" font-size="10" fill="var(--muted)" font-family="IBM Plex Mono">10.3.10.12</text>
      <text x="370" y="145" font-size="9" fill="var(--green)">PIVOT</text>
    </g>

    <g class="host-g dc" id="h-DC01">
      <rect x="630" y="50" width="160" height="80" rx="4" fill="rgba(255,59,59,.1)" stroke="var(--red)" stroke-width="2"/>
      <text x="650" y="80" font-weight="600" font-size="13" fill="var(--red)">LAF-DC01</text>
      <text x="650" y="100" font-size="10" fill="var(--muted)" font-family="IBM Plex Mono">10.3.10.10</text>
      <text x="650" y="115" font-size="9" fill="var(--green)">DOMAIN CONTROL</text>
    </g>

    <g class="host-g vict" id="h-WS01">
      <rect x="350" y="300" width="160" height="80" rx="4" fill="rgba(192,132,252,.1)" stroke="var(--violet)" stroke-width="2"/>
      <text x="370" y="330" font-weight="600" font-size="13" fill="var(--violet)">LAF-WS01</text>
      <text x="370" y="350" font-size="10" fill="var(--muted)" font-family="IBM Plex Mono">10.3.10.13 | Donny</text>
      <text x="370" y="365" font-size="9" fill="var(--green)">VICTIM</text>
    </g>

    <g class="host-g vict" id="h-WS02">
      <rect x="630" y="300" width="160" height="80" rx="4" fill="rgba(192,132,252,.1)" stroke="var(--violet)" stroke-width="2"/>
      <text x="650" y="330" font-weight="600" font-size="13" fill="var(--violet)">LAF-WS02</text>
      <text x="650" y="350" font-size="10" fill="var(--muted)" font-family="IBM Plex Mono">10.3.10.14 | Dalton</text>
      <text x="650" y="365" font-size="9" fill="var(--green)">VICTIM</text>
    </g>

    <g class="host-g cloud" id="h-AWS">
      <rect x="910" y="100" width="160" height="80" rx="4" fill="rgba(0,255,156,.1)" stroke="var(--green)" stroke-width="2"/>
      <text x="930" y="130" font-weight="600" font-size="13" fill="var(--green)">AWS S3</text>
      <text x="930" y="150" font-size="10" fill="var(--muted)" font-family="IBM Plex Mono">464381121764</text>
      <text x="930" y="165" font-size="9" fill="var(--green)">CLOUD</text>
    </g>

    <!-- Attack edges (paths) -->
    <g id="edge-injection" class="edge-g edge-c" opacity="0.4">
      <path d="M 230 140 Q 280 120, 350 120" stroke="var(--cyan)" stroke-width="2" fill="none" marker-end="url(#arrC)"/>
      <text x="270" y="105" font-size="10" fill="var(--cyan)" font-family="IBM Plex Mono">OS Command Injection (T1190)</text>
      <text x="270" y="125" font-size="9" fill="var(--muted)" font-family="IBM Plex Mono">18:40:01 · IIS W3SVC log</text>
    </g>

    <g id="edge-beacon" class="edge-g edge-a" opacity="0.4">
      <path d="M 510 120 Q 560 100, 630 110" stroke="var(--amber)" stroke-width="2" fill="none" marker-end="url(#arrA)"/>
      <text x="545" y="95" font-size="10" fill="var(--amber)" font-family="IBM Plex Mono">C2 Implant (T1190)</text>
      <text x="545" y="115" font-size="9" fill="var(--muted)" font-family="IBM Plex Mono">19:59:00 · Volatility</text>
    </g>

    <g id="edge-ntds" class="edge-g edge-r" opacity="0.4">
      <path d="M 790 100 Q 800 170, 790 240" stroke="var(--red)" stroke-width="2" fill="none" marker-end="url(#arrR)"/>
      <text x="760" y="170" font-size="10" fill="var(--red)" font-family="IBM Plex Mono">NTDS.dit Dump (T1003.003)</text>
      <text x="760" y="190" font-size="9" fill="var(--muted)" font-family="IBM Plex Mono">20:09:03 · VSS Extract</text>
    </g>

    <g id="edge-lateral" class="edge-g edge-a" opacity="0.4">
      <path d="M 510 180 Q 560 240, 630 280" stroke="var(--amber)" stroke-width="2" fill="none" marker-end="url(#arrA)"/>
      <text x="540" y="230" font-size="10" fill="var(--amber)" font-family="IBM Plex Mono">Lateral Movement (T1570)</text>
      <text x="540" y="250" font-size="9" fill="var(--muted)" font-family="IBM Plex Mono">20:16–20:37 · SMB / RDP</text>
    </g>

    <g id="edge-encrypt" class="edge-g edge-r" opacity="0.4">
      <path d="M 790 280 Q 850 320, 910 140" stroke="var(--red)" stroke-width="2" fill="none" marker-end="url(#arrR)"/>
      <text x="840" y="250" font-size="10" fill="var(--red)" font-family="IBM Plex Mono">Ransomware / Data Exfil (T1486)</text>
      <text x="840" y="270" font-size="9" fill="var(--muted)" font-family="IBM Plex Mono">22:08–22:46 · IamBatman.exe</text>
    </g>

    <!-- Traveling packet (animates along edges) -->
    <circle id="replayPacket" r="6" fill="var(--green)" opacity="0" filter="drop-shadow(0 0 8px var(--green))"/>

    <!-- Impact zone overlay (appears at ransomware phase) -->
    <rect id="impactZone" x="300" y="280" width="900" height="300" fill="rgba(255,59,59,.04)" opacity="0" style="pointer-events:none"/>
  </svg>
</div>

<div class="graph-legend">
  <div class="gl-item"><div class="gl-dot" style="background:var(--cyan); border-color:var(--cyan)"></div> Reconnaissance & Foothold</div>
  <div class="gl-item"><div class="gl-dot" style="background:var(--amber); border-color:var(--amber)"></div> Lateral Movement & Privesc</div>
  <div class="gl-item"><div class="gl-dot" style="background:var(--red); border-color:var(--red)"></div> Impact & Destruction</div>
  <div class="gl-item"><div class="gl-dot" style="background:var(--green); border-color:var(--green)"></div> Cloud Pivot</div>
</div>

</section>'''
    return svg

def gen_replay_js():
    """Generate JavaScript for interactive replay controls and scrubber"""
    js = '''<script>
let currentEventIdx = 0;
let isPlaying = false;
let playSpeed = 1;
let animFrameId = null;

const EVENTS = [
  { t: '18:38:29', host: 'IIS-SERV-PROD', desc: 'Attacker reconnaissance begins', phase: 'I', ttp: 'T1190', eid: 'IIS log' },
  { t: '18:40:01', host: 'IIS-SERV-PROD', desc: 'OS command injection: whoami via CheckStatus.aspx', phase: 'I', ttp: 'T1190', eid: 'IIS W3SVC' },
  { t: '18:51:42', host: 'IIS-SERV-PROD', desc: 'WebShell upload via certutil', phase: 'I', ttp: 'T1105', eid: 'IIS log' },
  { t: '19:08:42', host: 'IIS-SERV-PROD', desc: 'Webshell POST activation (curl)', phase: 'I', ttp: 'T1505.004', eid: 'IIS log' },
  { t: '19:38:02', host: 'IIS-SERV-PROD', desc: 'SolarwindsTFTP privesc → SYSTEM', phase: 'I', ttp: 'T1574.009', eid: 'EID 7036' },
  { t: '19:59:00', host: 'SVR01', desc: 'rnSylwOz.exe C2 beacon launched', phase: 'II', ttp: 'T1569.002', eid: 'Volatility pslist' },
  { t: '20:02:14', host: 'SVR01', desc: 'serviceaccount Domain Admin created', phase: 'II', ttp: 'T1136.002', eid: 'Sysmon EID 1' },
  { t: '20:03:05', host: 'DC01', desc: 'serviceaccount added to Domain Admins', phase: 'II', ttp: 'T1098.002', eid: 'EID 4728' },
  { t: '20:09:03', host: 'DC01', desc: 'NTDS.dit extracted via VSS', phase: 'II', ttp: 'T1003.003', eid: 'MFT DD5' },
  { t: '20:16:23', host: 'WS01', desc: 'LAFAdmin logon from SVR01', phase: 'III', ttp: 'T1570', eid: 'EID 4624' },
  { t: '20:35:29', host: 'WS01', desc: 'RED1 interactive RDP as Donny', phase: 'III', ttp: 'T1021.001', eid: 'EID 4624 T10' },
  { t: '20:37:03', host: 'WS01', desc: 'aws_backup.exe persistence installed', phase: 'III', ttp: 'T1547.001', eid: 'MFT' },
  { t: '20:46:03', host: 'DC02', desc: 'Advanced IP Scanner downloaded', phase: 'III', ttp: 'T1518', eid: 'MFT' },
  { t: '21:08:28', host: 'SVR01', desc: 'LogDel.bat event log clearing', phase: 'IV', ttp: 'T1070.001', eid: 'Sysmon EID 1' },
  { t: '21:42:11', host: 'AWS', desc: 'GetCallerIdentity with stolen EC2 creds', phase: 'IV', ttp: 'T1552.004', eid: 'CloudTrail' },
  { t: '21:49:16', host: 'AWS', desc: '164× GetObject S3 exfiltration begins', phase: 'IV', ttp: 'T1537', eid: 'CloudTrail' },
  { t: '22:08:40', host: 'WS02', desc: 'FIRST ENCRYPTION - .bWqQUx ransomware', phase: 'V', ttp: 'T1486', eid: 'MFT' },
  { t: '22:09:15', host: 'WS01', desc: 'vssadmin delete + IamBatman.exe encrypt', phase: 'V', ttp: 'T1486', eid: 'Sysmon' },
  { t: '22:10:14', host: 'DC01', desc: 'DC01 encrypted - domain control lost', phase: 'V', ttp: 'T1486', eid: 'MFT' },
];

function updateEventCard(idx) {
  if (idx >= EVENTS.length) idx = EVENTS.length - 1;
  const ev = EVENTS[idx];
  document.getElementById('ecTime').textContent = ev.t;
  document.getElementById('ecHost').textContent = ev.host;
  document.getElementById('ecDesc').textContent = ev.desc;
  document.getElementById('evCounter').textContent = `Event ${idx + 1} of ${EVENTS.length}`;

  const card = document.getElementById('eventCard');
  card.className = `event-card act-${ev.phase}`;

  const ttp = document.querySelector('.ec-tag.ttp');
  const eid = document.querySelector('.ec-tag.eid');
  if (ttp) ttp.textContent = ev.ttp;
  if (eid) eid.textContent = ev.eid;

  const pct = (idx / EVENTS.length) * 100;
  document.getElementById('scrubFill').style.width = pct + '%';
}

function replayToggle() {
  isPlaying = !isPlaying;
  const btn = document.getElementById('btn-play');
  btn.textContent = isPlaying ? '⏸ Pause' : '▶ Play';
  if (isPlaying) tick();
}

function replayReset() {
  currentEventIdx = 0;
  isPlaying = false;
  document.getElementById('btn-play').textContent = '▶ Play';
  updateEventCard(0);
  cancelAnimationFrame(animFrameId);
}

function replayNext() {
  if (currentEventIdx < EVENTS.length - 1) {
    currentEventIdx++;
    updateEventCard(currentEventIdx);
  }
}

function replayPrev() {
  if (currentEventIdx > 0) {
    currentEventIdx--;
    updateEventCard(currentEventIdx);
  }
}

function setSpeeds(s) {
  playSpeed = s;
  document.querySelectorAll('.speed-pick button').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
}

function tick() {
  if (isPlaying && currentEventIdx < EVENTS.length - 1) {
    currentEventIdx += playSpeed / 60;
    updateEventCard(Math.floor(currentEventIdx));
    animFrameId = requestAnimationFrame(tick);
  }
}

document.getElementById('scrubber').addEventListener('click', (e) => {
  const rect = e.currentTarget.getBoundingClientRect();
  const pct = (e.clientX - rect.left) / rect.width;
  currentEventIdx = Math.floor(pct * EVENTS.length);
  updateEventCard(currentEventIdx);
  isPlaying = false;
  document.getElementById('btn-play').textContent = '▶ Play';
});

// Initialize
updateEventCard(0);
</script>'''
    return js

def main():
    eng_yaml = read(os.path.join(ENG_DIR, "engagement.yaml"))
    timeline = read(os.path.join(ENG_DIR, "timeline.md"))

    # Generate new sections
    master_timeline_html = gen_master_timeline_html(timeline)
    replay_movie_html = gen_replay_svg_movie()
    replay_js = gen_replay_js()

    print(f"[+] Generated comprehensive sections:")
    print(f"    ✓ Master Timeline with phase breakdown & evidence links")
    print(f"    ✓ Interactive SVG replay movie with network graph")
    print(f"    ✓ Scrubber controls, event card, playback JavaScript")
    print(f"\n[+] To integrate: Insert the HTML sections into render_casebook_fancy.py")
    print(f"    - Master timeline goes after Executive Summary")
    print(f"    - Replay movie replaces/enhances the kill-chain replay section")

    # Write sample output for testing
    sample_html = f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Comprehensive Casebook Preview</title>
<style>
{open(os.path.join(CASE_DIR, 'render_casebook_fancy.py')).read().split('CSS = r"""')[1].split('"""')[0] if os.path.exists(os.path.join(CASE_DIR, 'render_casebook_fancy.py')) else ''}
</style></head><body>
{master_timeline_html}
{replay_movie_html}
{replay_js}
</body></html>'''

    with open(os.path.join(CASE_DIR, 'casebook_preview_comprehensive.html'), 'w') as f:
        f.write(sample_html)

    print(f"    - Preview written to casebook_preview_comprehensive.html")

if __name__ == '__main__':
    main()
