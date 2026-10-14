"""Import user-downloaded threat intelligence snapshots without active crawling.

Feeds are one-sided assertions, NOT a balanced training set. Do not infer
benign from absence from the feed. Never infer capture time from feed time.
"""
from __future__ import annotations
import csv,hashlib,json
from datetime import datetime,timezone
from pathlib import Path
from .public_data import sha256_file


def _yes(x): return str(x).strip().lower() in ('yes','true','1','y')


def import_snapshot(source:str,file_path:str,output_path:str):
    if source not in ('phishtank','urlhaus','tranco'):
        raise ValueError('source must be phishtank, urlhaus or tranco')
    fpath=Path(file_path);out=Path(output_path);out.parent.mkdir(parents=True,exist_ok=True)
    acquired_at=datetime.now(timezone.utc).isoformat()
    total=0
    records=[]
    with fpath.open(newline='',encoding='utf-8-sig',errors='replace') as f:
        lines=(line for line in f if not line.startswith('#'))
        if source=='tranco':
            rows=csv.reader(lines)
            for cols in rows:
                if len(cols)<2:continue
                rank,domain=cols[:2]
                if not domain.strip():continue
                records.append({'url':'https://'+domain.strip(),'label_class':'unknown',
                                'label_status':'benign_candidate_unverified',
                                'source_event_at':None,'source_record_id':rank})
        else:
            rows=csv.DictReader(lines)
            for row in rows:
                lower={str(k).strip().lower().lstrip('#'):v for k,v in row.items() if k}
                url=lower.get('url','').strip()
                if not url:continue
                if source=='phishtank':
                    verified=_yes(lower.get('verified',''))
                    records.append({'url':url,'label_class':'phishing' if verified else 'unknown',
                                    'label_status':'source_verified' if verified else 'pending',
                                    'source_event_at':lower.get('verification_time') or None,
                                    'source_record_id':lower.get('phish_id')})
                else:
                    records.append({'url':url,'label_class':'malware_distribution',
                                    'label_status':'source_asserted',
                                    'source_event_at':lower.get('dateadded') or lower.get('date_added') or None,
                                    'source_record_id':lower.get('id') or lower.get('url_id')})
    with out.open('w',encoding='utf-8') as f:
        for r in records:
            key=hashlib.sha256(r['url'].encode('utf-8')).hexdigest()
            data={'url_id':key,'source_dataset':source,'source_snapshot_sha256':sha256_file(fpath),
                  'snapshot_acquired_at':acquired_at,'url':r['url'],
                  'label_class':r['label_class'],'label_status':r['label_status'],
                  'label_available_at':acquired_at,'source_event_at':r['source_event_at'],
                  'source_record_id':r['source_record_id'],
                  'html_capture_at':None,'collector_verified':None,
                  'world_type':'external_feed_snapshot'}
            f.write(json.dumps(data)+'\n')
    return {'source':source,'observations':len(records),'output':str(out),
            'warning':'Snapshot labels and acquisition time only; not independent web captures'}
