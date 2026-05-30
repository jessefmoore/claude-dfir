import csv, collections, re
IOCS=['10.3.10.12','198.51.100','173.230.136','rnSylwOz','serviceaccount','LAFAdmin']
for S in ['WS01','WS02']:
    fn='exports/%s_evtx.csv'%S
    out=['===== %s ====='%S]
    eidc=collections.Counter(); chan=collections.Counter()
    ioc=collections.Counter()
    logon_src=collections.Counter()      # 4624 source IPs
    rdp=[]; psexec=[]; svc=[]; netconn=[]; suspproc=[]
    tmin=tmax=None
    try: f=open(fn,encoding='utf-8',errors='replace')
    except Exception as e:
        out.append('open err %s'%e); open('analysis/ws_%s.txt'%S,'w').write('\n'.join(out)); continue
    for row in csv.DictReader(f):
        eid=row.get('EventId',''); eidc[eid]+=1
        ch=row.get('Channel',''); chan[ch]+=1
        t=row.get('TimeCreated','')
        if t:
            if tmin is None or t<tmin: tmin=t
            if tmax is None or t>tmax: tmax=t
        blob=' '.join((row.get(c) or '') for c in ['MapDescription','UserName','RemoteHost','PayloadData1','PayloadData2','PayloadData3','PayloadData4','PayloadData5','PayloadData6','ExecutableInfo'])
        for x in IOCS:
            if x in blob: ioc[x]+=1
        # 4624 network/RDP logons w/ source IP
        if eid=='4624':
            m=re.search(r'\b(10\.3\.10\.\d+|198\.51\.100\.\d+)\b',blob)
            if m: logon_src[m.group(1)]+=1
        # C2 / external network (Sysmon 3)
        if eid=='3' and ('173.230.136' in blob or '198.51.100' in blob):
            netconn.append('%s %s'%(t[:19],blob[:120]))
        # Sysmon process create (1) or 4688 w/ suspicious
        if eid in ('1','4688'):
            if re.search(r'rnSylwOz|\\ADMIN\$|powershell.*-enc|-nop|FromBase64|IEX|DownloadString|certutil|rundll32|regsvr32|mimikatz|psexec|wmic|comsvcs',blob,re.I):
                suspproc.append('%s %s'%(t[:19],blob[:160]))
        # service install 7045
        if eid=='7045':
            svc.append('%s %s'%(t[:19],blob[:140]))
    out.append('rows %d  time %s..%s'%(sum(eidc.values()),(tmin or '')[:19],(tmax or '')[:19]))
    out.append('IOC hits: %s'%dict(ioc))
    out.append('4624 logon source IPs (internal/attacker): %s'%dict(logon_src.most_common(10)))
    out.append('C2/attacker netconns: %d'%len(netconn))
    for x in netconn[:8]: out.append('  '+x)
    out.append('suspicious proc creations: %d'%len(suspproc))
    for x in suspproc[:12]: out.append('  '+x)
    out.append('7045 service installs: %d'%len(svc))
    for x in svc[:10]: out.append('  '+x)
    out.append('top channels: %s'%dict(chan.most_common(6)))
    open('analysis/ws_%s.txt'%S,'w').write('\n'.join(out))
    print('%s done: ioc=%s logons=%s netconn=%d susp=%d svc=%d'%(S,dict(ioc),dict(logon_src.most_common(5)),len(netconn),len(suspproc),len(svc)))
