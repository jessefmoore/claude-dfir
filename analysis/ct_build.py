#!/usr/bin/env python3
import gzip, json, glob, os
base='cloud/cloudtrail/AWSLogs/464381121764/CloudTrail'
files=glob.glob(os.path.join(base,'**','*.json.gz'),recursive=True)
out=open('analysis/cloudtrail_all_events.json','w')
n=0; bad=0
for fp in files:
    try:
        with gzip.open(fp,'rt',encoding='utf-8',errors='replace') as fh:
            d=json.load(fh)
        for r in d.get('Records',[]):
            out.write(json.dumps(r)+'\n'); n+=1
    except Exception as e:
        bad+=1
out.close()
print('files=%d events=%d bad=%d'%(len(files),n,bad))
