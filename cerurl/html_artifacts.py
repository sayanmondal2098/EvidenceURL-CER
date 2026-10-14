"""Safely inspect local archived HTML without executing JavaScript or network IO.

Offline HTML-derived links are NOT independently verified observations, and
HTML existence does not establish a capture timestamp. Explicitly exploratory.
"""
from __future__ import annotations
import csv,hashlib,json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin,urlsplit


class HTMLInspector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links=[];self.forms=[];self.scripts=[];self.iframes=[]
        self.has_password_field=False;self.title_parts=[];self._in_title=False

    def handle_starttag(self,tag,attrs):
        kv=dict(attrs)
        if tag=='a' and kv.get('href'):self.links.append(kv['href'])
        if tag=='form':self.forms.append(kv.get('action',''))
        if tag=='script' and kv.get('src'):self.scripts.append(kv['src'])
        if tag=='iframe' and kv.get('src'):self.iframes.append(kv['src'])
        if tag=='input' and kv.get('type','').lower()=='password':self.has_password_field=True
        if tag=='title':self._in_title=True

    def handle_endtag(self,tag):
        if tag=='title':self._in_title=False

    def handle_data(self,data):
        if self._in_title:self.title_parts.append(data)


def inspect_html(path: str|Path,base_url: str):
    path=Path(path)
    data=path.read_bytes()
    # Only local-file parsing; nothing is executed or fetched.
    parser=HTMLInspector()
    parser.feed(data.decode('utf-8',errors='replace'))
    def normalize(links):
        out=[]
        for link in links:
            try:
                full=urljoin(base_url,link)
                if urlsplit(full).scheme in ('http','https'):out.append(full)
            except ValueError:pass
        return sorted(set(out))
    return {'html_sha256':hashlib.sha256(data).hexdigest(), 'bytes':len(data),
            'title':' '.join(parser.title_parts).strip(),
            'has_password_field':parser.has_password_field,
            'form_actions':normalize(parser.forms),'outbound_links':normalize(parser.links),
            'scripts':normalize(parser.scripts),'iframes':normalize(parser.iframes),
            'html_capture_timestamp':None,'source_verified':False,
            'warning':'Local archived artifact; no collector attestation or capture time inferred'}


def extract_manifest(manifest_csv: str,html_root: str,out_jsonl: str):
    root=Path(html_root).resolve();out=Path(out_jsonl);out.parent.mkdir(parents=True,exist_ok=True)
    total=success=0
    with open(manifest_csv,newline='',encoding='utf-8') as f, out.open('w',encoding='utf-8') as dest:
        reader=csv.DictReader(f)
        if not {'url','html_path'}.issubset(reader.fieldnames or []):
            raise ValueError('Required columns: url,html_path')
        for row in reader:
            total+=1
            relative=Path(row['html_path'])
            resolved=(root/relative).resolve()
            # Reject path traversal and non-files.
            if not resolved.is_relative_to(root) or not resolved.is_file():
                dest.write(json.dumps({'url':row['url'],'error':'missing or forbidden relative HTML path'})+'\n');continue
            try:
                record={'url':row['url'],'html_path':str(relative),**inspect_html(resolved,row['url'])}
                success+=1
            except (OSError,ValueError) as e:record={'url':row['url'],'error':str(e)}
            dest.write(json.dumps(record)+'\n')
    return {'total':total,'succeeded':success,'failed':total-success,'output':str(out),
            'capture_timestamps_inferred':0,'world_type':'archived_local_unverified'}
