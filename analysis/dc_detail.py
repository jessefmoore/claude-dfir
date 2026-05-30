import csv, collections, json, re
csv.field_size_limit(10**7)

FILES = {
 'DC01': '/home/localuser/cases/JackofAllHacks/exports/DC01_security.csv',
 'DC02': '/home/localuser/cases/JackofAllHacks/exports/DC02_security.csv',
}
REPL = ['1131f6aa','1131f6ad','89e95b76']
# Incident window: 2026-03-01 (focus 16:00-20:00 but capture whole day +/- )
WIN_LO='2026-03-01'
WIN_HI='2026-03-02'

ACCT_EVENTS=set('4720 4722 4724 4725 4726 4738 4781'.split())
GRP_EVENTS=set('4728 4732 4756 4729 4733 4757'.split())

o=open('/home/localuser/cases/JackofAllHacks/analysis/dc_detail.txt','w')
def W(s):o.write(s+'\n')

def payget(p, *keys):
    try: d=json.loads(p)
    except: return ''
    for k in keys:
        if k in d: return str(d[k])
    return ''

for host,path in FILES.items():
    W(f'###### {host} ######')
    repl_by_user=collections.Counter()
    repl_first={}; repl_ip={}
    acct=[]; grp=[]; logclear=[]; compchg=[]
    with open(path, encoding='utf-8', errors='replace', newline='') as f:
        r=csv.DictReader(f)
        for row in r:
            eid=row['EventId']; tc=row['TimeCreated']
            inwin = (WIN_LO <= tc < WIN_HI)
            pay=row.get('Payload','') or ''
            low=pay.lower()
            user=row.get('UserName','')
            pd1=row.get('PayloadData1','');pd2=row.get('PayloadData2','')
            pd3=row.get('PayloadData3','');pd4=row.get('PayloadData4','')
            md=row.get('MapDescription','')
            rh=row.get('RemoteHost','')
            if eid=='4662' and any(g in low for g in REPL):
                tu = payget(pay,'SubjectUserName')
                repl_by_user[tu]+=1
                if tu not in repl_first or tc<repl_first[tu]: repl_first[tu]=tc
            if not inwin: continue
            line=f'[{host}][{eid}] {tc} | user={user} | {md} | {pd1};{pd2};{pd3};{pd4} | rh={rh}'
            if eid in ACCT_EVENTS: acct.append(line+' || '+pay[:500])
            elif eid in GRP_EVENTS: grp.append(line+' || '+pay[:500])
            elif eid=='1102': logclear.append(line+' || '+pay[:400])
            elif eid=='4742': compchg.append(line)
    W('--ACCOUNT events (4720/22/24/25/26/38) in window:')
    for l in acct: W(l)
    W('--GROUP membership events (4728/32/56/...) in window:')
    for l in grp: W(l)
    W('--LOG CLEARED 1102 in window:')
    for l in logclear: W(l)
    W('--COMPUTER acct 4742 in window: count='+str(len(compchg)))
    for l in compchg[:10]: W(l)
    W('--4662 REPLICATION (DCSync) by SubjectUserName (ALL dates):')
    for u,c in repl_by_user.most_common(15):
        W(f'   user={u} count={c} first={repl_first.get(u)}')
    o.flush()
o.close()
print('done')
