import csv,re,collections
o=[]
for S in ['WS01','WS02']:
    lt=collections.Counter()
    f=open('exports/%s_evtx.csv'%S,encoding='utf-8',errors='replace')
    for row in csv.DictReader(f):
        if row.get('EventId')!='4624': continue
        blob=' '.join((row.get(c) or '') for c in ['MapDescription','PayloadData1','PayloadData2','PayloadData3','PayloadData4','PayloadData5','PayloadData6'])
        m=re.search(r'(198\.51\.100\.\d+|10\.3\.10\.12)',blob)
        if not m: continue
        ip=m.group(1)
        ty=re.search(r'(?:LogonType|Logon Type)\D*(\d+)',blob)
        u=(row.get('UserName') or '')[-22:]
        lt[(ip, ty.group(1) if ty else '?', u)]+=1
    o.append("== %s : 4624 from attacker-net/SVR01 =="%S)
    for k,n in lt.most_common(15):
        o.append("  ip=%s type=%s user=%s : %d"%(k[0],k[1],k[2],n))
open('analysis/ws_logon_types.txt','w').write('\n'.join(o))
print('\n'.join(o))
