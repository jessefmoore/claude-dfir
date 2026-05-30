import csv, collections, json
csv.field_size_limit(10**7)
FILES = {
 'DC01': '/home/localuser/cases/JackofAllHacks/exports/DC01_security.csv',
 'DC02': '/home/localuser/cases/JackofAllHacks/exports/DC02_security.csv',
}
WATCH=['svc_backup','admin','dalton','donny','ad-join','adjoin','ad_join']
o=open('/home/localuser/cases/JackofAllHacks/analysis/dc_logons.txt','w')
def W(s):o.write(s+'\n')

for host,path in FILES.items():
    W(f'###### {host} ######')
    a4624=collections.Counter(); a4625=collections.Counter()
    type10=set(); ipcount=collections.Counter()
    creator=[]  # svc_backup2 creation subject
    with open(path,encoding='utf-8',errors='replace',newline='') as f:
        r=csv.DictReader(f)
        for row in r:
            eid=row['EventId']; tc=row['TimeCreated']
            if not ('2026-03-01'<=tc<'2026-03-02'):
                pass
            pay=row.get('Payload','') or ''
            try: d=json.loads(pay)
            except: d={}
            inwin='2026-03-01'<=tc<'2026-03-02'
            if eid=='4624' and inwin:
                lt=str(d.get('LogonType',''))
                ip=d.get('IpAddress','') or ''
                tu=(d.get('TargetUserName','') or '')
                if ip and ip not in ('-','::1','127.0.0.1'):
                    ipcount[ip]+=1
                if lt in ('3','10') or any(w in tu.lower() for w in WATCH):
                    a4624[(lt,ip,tu)]+=1
                if lt=='10':
                    type10.add((tc[:19],ip,tu))
            elif eid=='4625' and inwin:
                lt=str(d.get('LogonType',''))
                ip=d.get('IpAddress','') or ''
                tu=(d.get('TargetUserName','') or '')
                a4625[(lt,ip,tu)]+=1
            elif eid in ('4720','4726','4728','4732','4756') and inwin:
                subj=d.get('SubjectUserName',''); tgt=d.get('TargetUserName','') or d.get('MemberName','') or d.get('MemberSid','')
                grp=d.get('TargetUserName','')
                creator.append(f'{eid} {tc[:19]} BY subj={subj} :: target={d.get("TargetUserName","")} member={d.get("MemberName","")}')
    W('--4624 (Type3/10 or watched acct) in window [logontype,srcip,user]xN:')
    for k,c in sorted(a4624.items(),key=lambda x:-x[1])[:30]:
        W(f'   T{k[0]} ip={k[1]} user={k[2]} x{c}')
    W('--Type10 RDP logons (ts,ip,user):')
    for t in sorted(type10):
        W(f'   {t[0]} ip={t[1]} user={t[2]}')
    W('--4625 failed logons in window [type,ip,user]xN:')
    for k,c in sorted(a4625.items(),key=lambda x:-x[1])[:30]:
        W(f'   T{k[0]} ip={k[1]} user={k[2]} x{c}')
    W('--Top src IPs in 4624 (window):')
    for ip,c in ipcount.most_common(12):
        W(f'   {ip} x{c}')
    W('--Account/Group change events with SUBJECT (who did it):')
    for l in creator: W('   '+l)
    o.flush()
o.close()
print('done')
