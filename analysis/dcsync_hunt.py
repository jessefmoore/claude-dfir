import csv, collections, json
csv.field_size_limit(10**7)
FILES = {
 'DC01': '/home/localuser/cases/JackofAllHacks/exports/DC01_security.csv',
 'DC02': '/home/localuser/cases/JackofAllHacks/exports/DC02_security.csv',
}
REPL=['1131f6aa','1131f6ad']  # Get-Changes + Get-Changes-All (the two that matter for DCSync)
o=open('/home/localuser/cases/JackofAllHacks/analysis/dcsync_hunt.txt','w')
def W(s):o.write(s+'\n')
for host,path in FILES.items():
    W(f'###### {host} ######')
    # non-machine subjects performing replication, by day
    byuser=collections.Counter()
    win=[]  # incident-window hits with non-machine subject
    samples={}
    with open(path,encoding='utf-8',errors='replace',newline='') as f:
        r=csv.DictReader(f)
        for row in r:
            if row['EventId']!='4662': continue
            pay=row.get('Payload','') or ''
            low=pay.lower()
            if not any(g in low for g in REPL): continue
            try: d=json.loads(pay)
            except: d={}
            subj=d.get('SubjectUserName','') or ''
            tc=row['TimeCreated']
            # skip machine accounts and ANONYMOUS
            if subj.endswith('$') or subj.upper() in ('ANONYMOUS LOGON','',):
                byuser['<machine/blank>']+=1
                continue
            byuser[subj]+=1
            if '2026-03-01'<=tc<'2026-03-02':
                win.append((tc,subj,d.get('SubjectDomainName',''),d.get('ObjectName','')))
            if subj not in samples: samples[subj]=(tc,d.get('Properties','')[:200])
    W('Non-machine SubjectUserName performing DS-Replication-Get-Changes(-All):')
    for u,c in byuser.most_common():
        if u=='<machine/blank>': continue
        W(f'   USER={u} total_repl_events={c} first_sample_ts={samples.get(u,("",""))[0]}')
    W(f'(machine/blank replication events skipped = {byuser["<machine/blank>"]})')
    W('Incident-window (2026-03-01) DCSync by NON-machine user:')
    for t in win[:40]:
        W(f'   {t[0]} subj={t[1]}\\{t[2]} obj={t[3]}')
    W(f'   ...total window non-machine DCSync events = {len(win)}')
    o.flush()
o.close()
print('done')
