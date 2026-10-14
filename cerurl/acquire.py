"""Single-command, receipt-producing acquisition of authorised source artifacts.

This downloader fetches files only.  It never visits URLs contained in a feed,
extracts archives, or executes HTML.  Restricted-source approval is checked
locally before any network request is made.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .sources import SOURCES


SOURCE_IDS={s["source_id"]:s for s in SOURCES}
DEFAULT_URLS={
    "phiusiil":"https://archive.ics.uci.edu/static/public/967/phiusiil%2Bphishing%2Burl%2Bdataset.zip",
    "phishtank":"https://data.phishtank.com/data/online-valid.csv",
    "phishingeval":"https://github.com/Fujiaoji/PhishingEval/archive/refs/heads/main.zip",
    "tranco":"https://tranco-list.eu/top-1m.csv.zip",
}


def _safe_name(url: str, source_id: str) -> str:
    value=Path(urlsplit(url).path).name or source_id
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in value)[:160]


def _sha(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()


def _md5(path: Path) -> str:
    h=hashlib.md5()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()


def _url(item: dict, source_id: str) -> str | None:
    if item.get("download_url_env"):
        return os.environ.get(item["download_url_env"])
    return item.get("download_url") or DEFAULT_URLS.get(source_id)


def _append_run_log(log_path: Path, result: dict) -> None:
    """Append a URL-free, line-addressable record of an acquisition attempt."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    events=[]
    for item in result["acquired"]:
        events.append({key:item[key] for key in ("source_id", "artifact_id", "status", "sha256", "receipt", "artifact_path", "target") if key in item})
    for item in result["refused"]:
        events.append({key:item[key] for key in ("source_id", "artifact_id", "reason") if key in item})
    entry={
        "event":"source_acquisition_run",
        "logged_at":datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z"),
        "plan":result["plan"],
        "out":result["out"],
        "dry_run":result["dry_run"],
        "only":result["only"],
        "acquired_count":len(result["acquired"]),
        "refused_count":len(result["refused"]),
        "events":events,
        "log_semantics":"One record per command invocation; no URL payloads or credentials are written here. Receipts retain artifact provenance.",
    }
    with log_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")


def acquire_sources(plan_path: str, out_dir: str="data/acquired", dry_run: bool=False, only: set[str] | None=None, log_path: str="data/logs/source_acquisition.jsonl", terminal_log: bool=False) -> dict:
    """Acquire every enabled plan item in one command, with fail-closed gates."""
    def emit(message: str) -> None:
        if terminal_log:
            print(f"[acquire] {message}", file=sys.stderr, flush=True)

    plan_file=Path(plan_path)
    if not plan_file.is_file():
        raise FileNotFoundError(f"Acquisition plan not found: {plan_file}. Use data/source_acquisition_plan.json or copy data/source_acquisition_plan.example.json to that path.")
    plan=json.loads(plan_file.read_text(encoding="utf-8"))
    items=plan.get("sources",[])
    if not isinstance(items,list): raise ValueError("plan.sources must be a list")
    root=Path(out_dir); root.mkdir(parents=True,exist_ok=True)
    receipts=[]; refused=[]
    emit(f"plan={plan_file}; out={root}; dry_run={dry_run}; only={','.join(sorted(only)) if only else 'all'}")
    # A source may contain separately enabled, release-pinned artifacts. This
    # prevents a code repository ZIP from being mistaken for its large datasets.
    operations=[]
    for parent in items:
        source_id=parent.get("source_id")
        if source_id not in SOURCE_IDS: raise ValueError(f"unknown source_id: {source_id}")
        if only is not None and source_id not in only: continue
        if not parent.get("enabled",False): continue
        artifacts=parent.get("artifacts")
        if artifacts is None: operations.append(parent); continue
        if not isinstance(artifacts,list): raise ValueError(f"artifacts for {source_id} must be a list")
        base={k:v for k,v in parent.items() if k!="artifacts"}
        operations.extend({**base,**artifact} for artifact in artifacts if artifact.get("enabled",False))
    for item in operations:
        source_id=item.get("source_id")
        auth=item.get("authorisation",{})
        if not (auth.get("acquisition_authorized_by_user") is True and auth.get("terms_reference")):
            refused.append({"source_id":source_id,"reason":"missing_explicit_authorisation_or_terms_reference"}); emit(f"{source_id}: REFUSED (missing authorisation or terms reference)"); continue
        if source_id=="phishark2026":
            proof=item.get("restricted_access_receipt_path")
            if not proof or not Path(proof).is_file():
                refused.append({"source_id":source_id,"reason":"restricted_access_receipt_or_signed_DUA_not_supplied"}); emit(f"{source_id}: REFUSED (missing access approval receipt)"); continue
        local=item.get("local_artifact_path")
        if local:
            emit(f"{source_id}: checking declared local artifact")
            artifact=Path(local)
            if not artifact.is_file():
                refused.append({"source_id":source_id,"reason":"declared_local_artifact_not_found"}); emit(f"{source_id}: REFUSED (declared local artifact not found)"); continue
            if dry_run:
                receipts.append({"source_id":source_id,"status":"dry_run_register_existing_local_artifact","artifact_path":str(artifact)}); emit(f"{source_id}: DRY RUN (would register local artifact)"); continue
            receipt={"source_id":source_id,"source_registry_url":SOURCE_IDS[source_id]["url"],"status":"registered_existing_local_artifact","registered_at":datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z"),"artifact_path":str(artifact),"sha256":_sha(artifact),"bytes":artifact.stat().st_size,"authorisation":auth,"release_id":item.get("release_id"),"note":"Existing bytes were registered; no new download was made."}
            receipt_path=root/source_id/(artifact.name+".receipt.json"); receipt_path.parent.mkdir(parents=True,exist_ok=True); receipt_path.write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8"); receipts.append({"source_id":source_id,"status":"registered_existing_local_artifact","receipt":str(receipt_path),"sha256":receipt["sha256"]}); emit(f"{source_id}: REGISTERED sha256={receipt['sha256'][:12]}…"); continue
        url=_url(item,source_id)
        if not url or not url.lower().startswith("https://"):
            refused.append({"source_id":source_id,"reason":"missing_provider_pinned_https_download_url"}); emit(f"{source_id}: REFUSED (missing pinned HTTPS URL)"); continue
        if source_id=="common_crawl" and not item.get("crawl_id"):
            refused.append({"source_id":source_id,"reason":"missing_pinned_crawl_id"}); emit(f"{source_id}: REFUSED (missing pinned crawl ID)"); continue
        filename=item.get("filename") or _safe_name(url,source_id)
        target=(root/source_id/filename).resolve(); target.parent.mkdir(parents=True,exist_ok=True)
        if dry_run:
            receipts.append({"source_id":source_id,"status":"dry_run_authorised","url":url,"target":str(target)}); emit(f"{source_id}/{item.get('artifact_id', filename)}: DRY RUN (authorised)"); continue
        emit(f"{source_id}/{item.get('artifact_id', filename)}: downloading")
        request=urllib.request.Request(url,headers={"User-Agent":item.get("user_agent","EvidenceURL-CER authorised research acquisition")})
        try:
            with urllib.request.urlopen(request,timeout=int(item.get("timeout_seconds",60))) as response, target.open("wb") as dest:
                shutil.copyfileobj(response,dest,length=1024*1024)
                headers={k:v for k,v in response.headers.items() if k.lower() in {"etag","last-modified","content-type","content-length"}}
        except Exception as exc:
            if target.exists(): target.unlink()
            refused.append({"source_id":source_id,"reason":f"download_failed:{type(exc).__name__}"}); emit(f"{source_id}/{item.get('artifact_id', filename)}: FAILED ({type(exc).__name__})"); continue
        expected_md5=item.get("expected_md5")
        actual_md5=_md5(target)
        if expected_md5 and actual_md5.lower()!=str(expected_md5).lower():
            target.unlink(); refused.append({"source_id":source_id,"artifact_id":item.get("artifact_id"),"reason":"downloaded_artifact_md5_mismatch"}); emit(f"{source_id}/{item.get('artifact_id', filename)}: REJECTED (MD5 mismatch)"); continue
        receipt={"source_id":source_id,"artifact_id":item.get("artifact_id"),"source_registry_url":SOURCE_IDS[source_id]["url"],"download_url":url,"acquired_at":datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z"),"artifact_path":str(target),"sha256":_sha(target),"md5":actual_md5,"expected_md5":expected_md5,"bytes":target.stat().st_size,"headers":headers,"authorisation":auth,"crawl_id":item.get("crawl_id"),"release_id":item.get("release_id"),"restricted_access_receipt_path":item.get("restricted_access_receipt_path")}
        receipt_path=target.with_suffix(target.suffix+".receipt.json"); receipt_path.write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8"); receipts.append({"source_id":source_id,"status":"acquired","receipt":str(receipt_path),"sha256":receipt["sha256"]}); emit(f"{source_id}/{item.get('artifact_id', filename)}: ACQUIRED sha256={receipt['sha256'][:12]}…")
    result={"plan":str(plan_file),"out":str(root),"dry_run":dry_run,"only":sorted(only) if only else None,"acquired":receipts,"refused":refused}
    (root/"acquisition_manifest.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    if log_path:
        _append_run_log(Path(log_path), result)
        result["log_path"]=str(Path(log_path))
    emit(f"complete: acquired={len(receipts)} refused={len(refused)}; log={log_path or 'disabled'}")
    return result
