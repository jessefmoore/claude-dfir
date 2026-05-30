import csv, collections
csv.field_size_limit(10**7)

FILES = {
 'DC01': '/home/localuser/cases/JackofAllHacks/exports/DC01_security.csv',
 'DC02': '/home/localuser/cases/JackofAllHacks/exports/DC02_security.csv',
}
INTEREST = set('4624 4625 4634 4647 4648 4672 4720 4722 4724 4725 4726 4728 4732 4756 4738 4742 4768 4769 4771 4662 1102 4776 4697 5140 5145'.split())

out = open('/home/localuser/cases/JackofAllHacks/analysis/dc_counts.txt','w')
def w(s): out.write(s+'\n')

for host,path in FILES.items():
    counts=collections.Counter(); total=0; tmin=None; tmax=None
    with open(path, encoding='utf-8', errors='replace', newline='') as f:
        r=csv.DictReader(f)
        for row in r:
            total+=1
            eid=row.get('EventId','')
            tc=row.get('TimeCreated','')
            counts[eid]+=1
            if tc:
                if tmin is None or tc<tmin: tmin=tc
                if tmax is None or tc>tmax: tmax=tc
    w(f'==== {host} total={total} range {tmin} .. {tmax}')
    for eid in sorted(INTEREST, key=lambda x:int(x)):
        if counts[eid]: w(f'  {host} EID {eid} = {counts[eid]}')
    out.flush()
out.close()
print('done')
