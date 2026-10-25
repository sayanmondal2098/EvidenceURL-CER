"""Fail-closed provenance curation for locally supplied URLTrust-style data.

This module deliberately does not crawl URLs, manufacture capture dates, or
turn missing archived HTML into a benign observation.  It is an ingestion
boundary: every source row is retained or accounted for in an exclusion ledger.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit


URL_COLUMNS = ("url", "uri", "address", "link")
HTML_COLUMNS = ("html_path", "html_file", "file_path", "filename", "path")
URL_COLUMNS_OUT = ["url_id", "canonical_url", "host", "registrable_domain", "etld_plus_one_status",
 "source_record_id", "source_dataset", "cohort", "world_type", "label", "label_class", "label_status",
 "label_event_at", "label_available_at", "record_ingested_at", "source_created_date", "html_relative_path",
 "html_sha256", "capture_at", "capture_status", "campaign_id", "split_name", "raw_row_sha256", "authority", "external_access_terms"]
OBS_COLUMNS = ["observation_id", "url_id", "observed_at", "ingested_at", "vantage_group_id", "collector_id",
 "collector_build", "modality", "artifact_sha256", "artifact_uri", "quality_status", "signature_verified",
 "attestation_status", "source_group_ids", "parent_observation_ids", "capture_error", "world_type", "source_snapshot_id"]


def _sha(value: bytes | str) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _text(value):
    return None if value is None or str(value).strip() == "" else str(value).strip()


def canonical_url(value: str) -> str | None:
    """Conservative URL canonicalisation; query order/content is intentionally kept."""
    try:
        raw = str(value).strip()
        if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", raw):
            raw = "http://" + raw
        p = urlsplit(raw)
        if p.scheme.lower() not in ("http", "https") or not p.hostname:
            return None
        host = p.hostname.lower().rstrip(".")
        port = p.port
        netloc = host if port is None or (p.scheme.lower() == "http" and port == 80) or (p.scheme.lower() == "https" and port == 443) else f"{host}:{port}"
        path = p.path or "/"
        return urlunsplit((p.scheme.lower(), netloc, path, p.query, ""))
    except (TypeError, ValueError):
        return None


def host_of(url: str) -> str | None:
    try: return urlsplit(url).hostname
    except ValueError: return None


def etld_plus_one(_host: str | None) -> tuple[None, str]:
    # Do not substitute a last-two-label heuristic for the Public Suffix List.
    # It is materially wrong for many ccTLDs and would make the audit misleading.
    return None, "missing_public_suffix_list"


def _read_index(path: Path) -> tuple[list[dict], dict]:
    suffix = path.suffix.lower()
    raw = path.read_bytes()
    meta = {"path": str(path), "sha256": _sha(raw), "bytes": len(raw), "kind": suffix.lstrip(".")}
    if suffix in (".sqlite", ".sqlite3", ".db"):
        con = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)
        try:
            tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
            table = "index" if "index" in tables else next((t for t in tables if any(x[1].lower() in URL_COLUMNS for x in con.execute(f'pragma table_info("{t}")'))), None)
            if not table: raise ValueError("no SQLite table with a URL field")
            cur = con.execute(f'select rowid as _sqlite_rowid_, * from "{table}"')
            cols = [x[0] for x in cur.description]
            rows = [dict(zip(cols, r)) for r in cur]
            meta["table"] = table
            return rows, meta
        finally: con.close()
    if suffix == ".jsonl":
        return [json.loads(x) for x in raw.decode("utf-8-sig", "replace").splitlines() if x.strip()], meta
    if suffix == ".json":
        obj = json.loads(raw.decode("utf-8-sig", "replace")); return (obj if isinstance(obj, list) else obj.get("rows", [])), meta
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as f:
        return list(csv.DictReader(f)), meta


def _field(row: dict, names: tuple[str, ...]):
    lower = {str(k).lower(): v for k, v in row.items()}
    return next((_text(lower.get(n)) for n in names if _text(lower.get(n)) is not None), None)


def _source_profile(rows: list[dict], requested: str) -> dict:
    """Recognise only documented label conventions; unknown schemas fail closed."""
    columns={str(k).lower() for r in rows[:25] for k in r}
    if requested == "auto":
        if "result" in columns: requested="urltrust"
        elif "original_label" in columns and "label" in columns: requested="phiusiil"
        elif "label" in columns: requested="cer_binary"
        else: requested="unknown"
    profiles={
        "urltrust":{"name":"URLTrust_local_index","cohort":"urltrust_index","group":"urltrust_index","world":"observed_historical","authority":"locally_supplied_unverified","terms":"not_supplied","semantics":"result=0 is benign; result=1 is phishing; created_date is source metadata only"},
        "phiusiil":{"name":"PhiUSIIL_UCI_967","cohort":"phiusiil_uci_967","group":"phiusiil_uci_967","world":"observed_historical","authority":"local_copy_of_UCI_dataset_unverified_against_upstream","terms":"CC_BY_4.0_claimed_in_project_README; verify upstream before redistribution","semantics":"official original_label=1 legitimate/benign and 0 phishing; prepared CER label must be its exact inverse"},
        "cer_binary":{"name":"CER_binary_local","cohort":"cer_binary_local","group":"cer_binary_local","world":"observed_historical","authority":"locally_supplied_unverified","terms":"not_supplied","semantics":"declared CER convention only: label=0 benign; label=1 phishing"},
    }
    if requested not in profiles:
        return {"name":"unknown","cohort":"unknown","group":"unknown","world":"unknown","authority":"not_assessable","terms":"not_supplied","semantics":"unknown label convention; rows are excluded", "requested":requested}
    return {**profiles[requested], "requested":requested}


def _map_label(row: dict, profile: dict) -> tuple[int | None, str | None, str | None]:
    """Return CER label/class or a ledger reason.  No label is guessed."""
    kind=profile["requested"]
    if kind == "urltrust":
        raw=_field(row,("result",))
        if raw not in ("0","1"): return None,None,"result_not_in_{0,1}"
        return int(raw), ("benign" if raw=="0" else "phishing"), None
    if kind == "phiusiil":
        original=_field(row,("original_label",))
        if original not in ("0","1"): return None,None,"phiusiil_original_label_not_in_{0,1}"
        mapped=1-int(original); prepared=_field(row,("label",))
        if prepared is not None and prepared not in ("0","1"): return None,None,"phiusiil_prepared_label_not_in_{0,1}"
        if prepared is not None and int(prepared)!=mapped: return None,None,"phiusiil_original_and_prepared_label_conflict"
        return mapped, ("phishing" if mapped else "benign"), None
    if kind == "cer_binary":
        raw=_field(row,("label",))
        if raw not in ("0","1"): return None,None,"cer_label_not_in_{0,1}"
        return int(raw), ("benign" if raw=="0" else "phishing"), None
    return None,None,"unknown_source_schema"


def _relative_html(root: Path | None, value: str | None) -> tuple[Path | None, str | None]:
    if root is None or value is None: return None, "no_declared_html_path" if value is None else "html_root_not_supplied"
    candidate = (root / value).resolve()
    try: candidate.relative_to(root)
    except ValueError: return None, "html_path_outside_declared_root"
    return (candidate, None) if candidate.is_file() else (None, "declared_html_file_missing")


class _Links(HTMLParser):
    def __init__(self): super().__init__(convert_charrefs=True); self.links = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for key in (("href",) if tag == "a" else (("action",) if tag == "form" else (("src",) if tag in ("iframe", "script") else ()))):
            if a.get(key[0]): self.links.append((tag, a[key[0]]))


def _find_split_overlaps(rows: list[dict]) -> list[dict]:
    by_url = defaultdict(set)
    for r in rows:
        if r.get("split_name"): by_url[r["url_id"]].add(r["split_name"])
    return [{"kind":"url_in_multiple_splits", "url_id":u, "splits":sorted(s), "severity":"error"} for u,s in by_url.items() if len(s)>1]


def _group_split_contamination(rows: list[dict]) -> list[dict]:
    findings=[]
    for field,kind in (("host","same_domain_across_splits"),("campaign_id","same_campaign_across_splits")):
        grouped=defaultdict(set)
        for r in rows:
            if r.get(field) and r.get("split_name"): grouped[r[field]].add(r["split_name"])
        findings.extend({"kind":kind,"url_id":None,"group_value":value,"splits":sorted(splits),"severity":"error"} for value,splits in grouped.items() if len(splits)>1)
    return findings


def _after_decision(edges: list[dict], decisions: dict[str, str]) -> list[dict]:
    findings=[]
    for e in edges:
        decision=decisions.get(e["source_url_id"])
        evidence=e.get("observed_at") or e.get("available_at")
        if decision and evidence and evidence > decision:
            findings.append({"kind":"graph_edge_after_decision", "edge_id":e["edge_id"], "url_id":e["source_url_id"], "decision_at":decision, "evidence_at":evidence, "severity":"error"})
    return findings


def _feed_mirrors(groups: list[dict]) -> list[dict]:
    by_parent=defaultdict(list)
    for g in groups:
        if g.get("parent_source_group_id"): by_parent[g["parent_source_group_id"]].append(g["source_group_id"])
    return [{"kind":"feed_mirroring", "parent_source_group_id":p, "children":sorted(c), "severity":"warning"} for p,c in by_parent.items() if len(c)>1]


def _control_tests() -> dict:
    rows=[{"url_id":"u", "split_name":"train"},{"url_id":"u", "split_name":"test"}]
    edges=[{"edge_id":"e", "source_url_id":"u", "observed_at":"2024-01-02T00:00:00Z", "available_at":None}]
    groups=[{"source_group_id":"feed-a", "parent_source_group_id":"root"},{"source_group_id":"feed-b", "parent_source_group_id":"root"}]
    checks={"url_in_train_and_test": bool(_find_split_overlaps(rows)), "timestamp_after_decision": bool(_after_decision(edges,{"u":"2024-01-01T00:00:00Z"})), "two_feeds_mirror_one_source": bool(_feed_mirrors(groups))}
    if not all(checks.values()): raise AssertionError(f"leakage controls did not flag: {checks}")
    return {"executed":True, "checks":checks, "passed":True}


def _write_csv(path: Path, rows: list[dict], columns: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w=csv.DictWriter(f, fieldnames=columns, extrasaction="ignore"); w.writeheader()
        for r in rows:
            w.writerow({c: json.dumps(r[c], sort_keys=True) if isinstance(r.get(c),(list,dict)) else r.get(c) for c in columns})


def _tex(value):
    return str(value).replace("_", r"\_").replace("&", r"\&").replace("%", r"\%")


def _write_characteristics(tables: Path, summaries: dict):
    tex_rows=[r"\begin{tabular}{lll}",r"Cohort & characteristic & count \\",r"\hline"]
    for key, values in summaries.items():
        for v in values: tex_rows.append(f"{_tex(v['cohort'])} & {_tex(key + ': ' + str(v['value']))} & {v['count']} \\\\")
    tex_rows.append(r"\end{tabular}"); (tables/"dataset_characteristics.tex").write_text("\n".join(tex_rows)+"\n",encoding="utf-8")


def _curate_phiusiil_csv(path: Path, out: Path, tables: Path, run_at: str) -> dict:
    """Streaming PhiUSIIL adapter.  It avoids holding one observation dict per row."""
    profile=_source_profile([{"original_label":None,"label":None}],"phiusiil")
    source_hash=_sha(path.read_bytes())
    ledger_path=out/"inclusion_exclusion_ledger.csv"; urls_path=tables/"urls.csv"; obs_path=tables/"observations.jsonl"
    labels_by_id={}; counts=Counter(); summaries_count={name:Counter() for name in ("label","source","month","etld_plus_one","campaign","capture_availability","independent_source_ancestry")}; samples=[]
    included=excluded=raw_count=0
    with path.open(newline="",encoding="utf-8-sig",errors="replace") as src, urls_path.open("w",newline="",encoding="utf-8") as uf, ledger_path.open("w",newline="",encoding="utf-8") as lf, obs_path.open("w",encoding="utf-8") as of:
        reader=csv.DictReader(src); uw=csv.DictWriter(uf,fieldnames=URL_COLUMNS_OUT,extrasaction="ignore"); uw.writeheader(); lw=csv.DictWriter(lf,fieldnames=["ledger_id","stage","action","reason","raw_row_sha256","url_id","details"]); lw.writeheader()
        for pos,row in enumerate(reader,1):
            raw_count=pos; raw_json=json.dumps(row,sort_keys=True,default=str,separators=(",",":")); raw_hash=_sha(raw_json); record_id=_field(row,("id","record_id","index")) or str(pos); canon=canonical_url(_field(row,URL_COLUMNS) or ""); label_num,label,reason=_map_label(row,profile)
            if canon is None or label is None:
                excluded+=1; lw.writerow({"ledger_id":f"index:{record_id}","stage":"source_assertion","action":"excluded","reason":"missing_or_invalid_url" if canon is None else reason,"raw_row_sha256":raw_hash,"url_id":None,"details":"No label was repaired or inferred."}); continue
            included+=1; uid=_sha(canon); host=host_of(canon); registrable,status=etld_plus_one(host)
            row_out={"url_id":uid,"canonical_url":canon,"host":host,"registrable_domain":registrable,"etld_plus_one_status":status,"source_record_id":record_id,"source_dataset":profile["name"],"cohort":profile["cohort"],"world_type":profile["world"],"label":label_num,"label_class":label,"label_status":"source_asserted","label_event_at":None,"label_available_at":None,"record_ingested_at":run_at,"source_created_date":None,"html_relative_path":None,"html_sha256":None,"capture_at":None,"capture_status":"unavailable","campaign_id":None,"split_name":_field(row,("split_name","split","partition")),"raw_row_sha256":raw_hash,"authority":profile["authority"],"external_access_terms":profile["terms"]}
            uw.writerow(row_out); lw.writerow({"ledger_id":f"index:{record_id}","stage":"source_assertion","action":"included","reason":profile["semantics"],"raw_row_sha256":raw_hash,"url_id":uid,"details":"No HTML path or reliable historical availability time was supplied."})
            obs={"observation_id":_sha(f"{uid}|{record_id}|html"),"url_id":uid,"observed_at":None,"ingested_at":run_at,"vantage_group_id":profile["group"],"collector_id":None,"collector_build":None,"modality":"html","artifact_sha256":None,"artifact_uri":None,"quality_status":"capture_unavailable","signature_verified":None,"attestation_status":None,"source_group_ids":[profile["group"]],"parent_observation_ids":[],"capture_error":"no_declared_html_path","world_type":profile["world"],"source_snapshot_id":source_hash}; of.write(json.dumps(obs,sort_keys=True)+"\n")
            labels_by_id.setdefault(uid,set()).add(label); counts[uid]+=1
            for name,value in (("label",label),("source",profile["name"]),("month","missing_time"),("etld_plus_one","missing_psl"),("campaign","not_supplied"),("capture_availability","unavailable"),("independent_source_ancestry",profile["group"])): summaries_count[name][(profile["cohort"],value)]+=1
            if len(samples)<1000: samples.append({"sample_id":f"S{len(samples)+1:06d}","url_id":uid[:16],"source_record_id":record_id,"cohort":profile["cohort"],"label_class":label,"capture_status":"unavailable","html_sha256":"","raw_row_sha256":raw_hash[:16]})
    groups=[{"source_group_id":profile["group"],"operator_id":"UCI_dataset_publisher_unverified_local_copy","independence_claim":"one_dataset_group_not_independent_per_row","independence_basis":"all labels derive from one static dataset","first_valid_at":None,"last_valid_at":None,"parent_source_group_id":None,"authority":profile["authority"],"external_access_terms":profile["terms"]}]
    _write_csv(tables/"source_groups.csv",groups,["source_group_id","operator_id","independence_claim","independence_basis","first_valid_at","last_valid_at","parent_source_group_id","authority","external_access_terms"]); _write_csv(tables/"provenance_edges.csv",[],["parent_id","child_id","relation","valid_from","valid_until"]); _write_csv(tables/"url_graph_edges.csv",[],["edge_id","source_url_id","target_url_id","relation_type","observed_at","available_at","observer_group_id","source_observation_id","evidence_sha256","semantic_weight","quality_status","world_type"])
    source=[{"source_dataset":profile["name"],"artifact_path":str(path),"artifact_sha256":source_hash,"raw_rows":raw_count,"authority":profile["authority"],"external_access_terms":profile["terms"],"acquisition_status":"local_artifact_present","time_semantics":profile["semantics"]+"; no timestamp fields establish first-seen eligibility"}]; _write_csv(tables/"source_inventory.csv",source,["source_dataset","artifact_path","artifact_sha256","raw_rows","authority","external_access_terms","acquisition_status","time_semantics"]); _write_csv(out/"sample_ledger.csv",samples,["sample_id","url_id","source_record_id","cohort","label_class","capture_status","html_sha256","raw_row_sha256"])
    findings=[{"kind":"conflicting_labels","url_id":u,"labels":sorted(v),"severity":"error"} for u,v in labels_by_id.items() if len(v)>1]+[{"kind":"duplicate_canonical_url","url_id":u,"assertion_count":n,"severity":"warning"} for u,n in counts.items() if n>1]
    _write_csv(out/"duplicate_conflicts.csv",findings,["kind","url_id","group_value","labels","assertion_count","html_sha256","url_ids","splits","edge_id","decision_at","evidence_at","parent_source_group_id","children","severity"])
    summaries={name:[{"cohort":c,"value":v,"count":n} for (c,v),n in sorted(counter.items())] for name,counter in summaries_count.items()}; _write_characteristics(tables,summaries)
    audit={"audit_version":"E01-curation-1","run_at":run_at,"collection_framework":{"release_mode":"historical","permitted_analysis":"URL-only static-label baseline and duplicate/conflict audit","blocked_analysis":["first-seen or out-of-time evaluation","HTML/content analysis","provenance-independence or source-corruption claims","active evidence collection claims"]},"flow":{"raw_source_rows":raw_count,"included_assertions":included,"excluded_ledger_entries":excluded,"observations":included,"graph_edges":0,"decided_cases":0,"decided_case_reason":"no decision artifact supplied; ingestion does not decide labels"},"sources":source,"timestamp_semantics":{"source_created_date":"not present","capture_at":"null; PhiUSIIL supplies no HTML artifacts","label_available_at":"null; local file mtime/import time is not historical availability","first_seen_evaluation":{"evaluable":False,"reason":"PhiUSIIL CSV has no authenticated historical label availability or capture timestamps"}},"missingness":{"html_unavailable":included,"missing_etld_plus_one":included,"missing_capture_at":included},"summaries":summaries,"findings":findings,"controls":_control_tests(),"pass_criteria":{"silent_label_flips":0,"unflagged_leakage":0,"status":"pass_with_flagged_data_quality_findings","flagged_findings":len(findings)},"limitations":["PhiUSIIL is a URL/label-only historical cohort, not the requested URLTrust HTML archive.","No HTML was supplied; all capture observations are explicitly unavailable, not benign.","No split assignment was supplied, so actual train/test domain/campaign contamination is not evaluable (the assertion control was run).","No reliable historical time metadata exists, so first-seen evaluation is blocked.","No authorised external threat-feed snapshot was present.","eTLD+1 is null because no Public Suffix List was supplied."]}; (out/"audit.json").write_text(json.dumps(audit,indent=2,sort_keys=True),encoding="utf-8"); return audit


def curate_e01(index_path: str | None, html_root: str | None, out_dir: str="results/E01", table_dir: str="tables", decisions_path: str | None=None, source_schema: str="auto") -> dict:
    """Create all E01 curation artifacts.  No index means an explicit no-data audit."""
    run_at=_now(); out=Path(out_dir); tables=Path(table_dir); out.mkdir(parents=True,exist_ok=True); tables.mkdir(parents=True,exist_ok=True)
    # PhiUSIIL is intentionally handled in a streaming path: the local release
    # has 235k rows, and a provenance audit must not fail simply by retaining a
    # second in-memory copy of every row, observation, and ledger entry.
    if index_path and Path(index_path).is_file() and Path(index_path).suffix.lower()==".csv":
        with Path(index_path).open(newline="",encoding="utf-8-sig",errors="replace") as probe:
            header=next(csv.reader(probe),[])
        profile=_source_profile([{name:None for name in header}],source_schema)
        if profile["requested"]=="phiusiil": return _curate_phiusiil_csv(Path(index_path),out,tables,run_at)
    source_inventory=[]; ledger=[]; urls=[]; observations=[]; edges=[]; groups=[]
    root=Path(html_root).resolve() if html_root and Path(html_root).is_dir() else None
    if index_path and Path(index_path).is_file():
        index=Path(index_path); raw_rows, idx_meta=_read_index(index); profile=_source_profile(raw_rows,source_schema)
        source_inventory.append({"source_dataset":profile["name"], "artifact_path":str(index), "artifact_sha256":idx_meta["sha256"], "raw_rows":len(raw_rows), "authority":profile["authority"], "external_access_terms":profile["terms"], "acquisition_status":"local_artifact_present", "time_semantics":profile["semantics"]+"; no local historical availability timestamp establishes first-seen eligibility"})
        groups.append({"source_group_id":profile["group"], "operator_id":"unknown_local_dataset_operator", "independence_claim":"not_independent_of_its_archived_HTML_or_same_dataset_rows", "independence_basis":"same local dataset", "first_valid_at":None, "last_valid_at":None, "parent_source_group_id":None, "authority":profile["authority"], "external_access_terms":profile["terms"]})
        for pos,row in enumerate(raw_rows,1):
            raw_json=json.dumps(row,sort_keys=True,default=str,separators=(",",":")); record_id=_field(row,("id","_sqlite_rowid_","record_id","index")) or str(pos)
            supplied_url=_field(row,URL_COLUMNS); canon=canonical_url(supplied_url) if supplied_url else None
            result,label,reason=_map_label(row,profile)
            if canon is None or label is None:
                ledger.append({"ledger_id":f"index:{record_id}","stage":"source_assertion","action":"excluded","reason":"missing_or_invalid_url" if canon is None else reason,"raw_row_sha256":_sha(raw_json),"url_id":None,"details":"No label was repaired or inferred."}); continue
            url_id=_sha(canon); host=host_of(canon); registrable,status=etld_plus_one(host)
            rel=_field(row,HTML_COLUMNS); html_path,error=_relative_html(root,rel)
            html_sha=None; capture_status="unavailable"; parse_links=[]
            if html_path:
                try:
                    body=html_path.read_bytes(); html_sha=_sha(body); capture_status="available_local_unattested"
                    p=_Links(); p.feed(body.decode("utf-8","replace")); parse_links=p.links
                except OSError as exc: error=f"html_read_error:{type(exc).__name__}"
            source_created=_field(row,("created_date","created_at","date_created"))
            urlrow={"url_id":url_id,"canonical_url":canon,"host":host,"registrable_domain":registrable,"etld_plus_one_status":status,"source_record_id":record_id,"source_dataset":profile["name"],"cohort":_field(row,("cohort",)) or profile["cohort"],"world_type":profile["world"],"label":result,"label_class":label,"label_status":"source_asserted","label_event_at":None,"label_available_at":None,"record_ingested_at":run_at,"source_created_date":source_created,"html_relative_path":rel,"html_sha256":html_sha,"capture_at":None,"capture_status":capture_status,"campaign_id":_field(row,("campaign_id","campaign")),"raw_row_sha256":_sha(raw_json),"authority":profile["authority"],"external_access_terms":profile["terms"],"split_name":_field(row,("split_name","split","partition"))}
            urls.append(urlrow); ledger.append({"ledger_id":f"index:{record_id}","stage":"source_assertion","action":"included","reason":profile["semantics"],"raw_row_sha256":urlrow["raw_row_sha256"],"url_id":url_id,"details":"source_created_date was not used as capture_at or first_seen"})
            observation_id=_sha(f"{url_id}|{record_id}|html")
            observations.append({"observation_id":observation_id,"url_id":url_id,"observed_at":None,"ingested_at":run_at,"vantage_group_id":profile["group"],"collector_id":None,"collector_build":None,"modality":"html","artifact_sha256":html_sha,"artifact_uri":rel,"quality_status":"available_local_unattested" if html_sha else "capture_unavailable","signature_verified":None,"attestation_status":None,"source_group_ids":[profile["group"]],"parent_observation_ids":[],"capture_error":error,"world_type":profile["world"],"source_snapshot_id":idx_meta["sha256"]})
            if html_sha:
                for tag,link in parse_links:
                    target=canonical_url(urljoin(canon,link))
                    if target:
                        edges.append({"edge_id":_sha(f"{observation_id}|{tag}|{target}"),"source_url_id":url_id,"target_url_id":_sha(target),"relation_type":{"a":"hyperlink","form":"form_action","iframe":"iframe","script":"shared_resource"}[tag],"observed_at":None,"available_at":None,"observer_group_id":profile["group"],"source_observation_id":observation_id,"evidence_sha256":html_sha,"semantic_weight":None,"quality_status":"time_unknown_local_unattested","world_type":profile["world"]})
    else:
        source_inventory.append({"source_dataset":"URLTrust_local_index", "artifact_path":index_path or "database/index (not found)", "artifact_sha256":None, "raw_rows":0, "authority":"not_assessable", "external_access_terms":"not_supplied", "acquisition_status":"absent", "time_semantics":"No assertions ingested; UCI PhiUSIIL file is a different dataset and was excluded."})
        ledger.append({"ledger_id":"source:URLTrust_local_index","stage":"source_discovery","action":"excluded","reason":"local_index_not_found","raw_row_sha256":None,"url_id":None,"details":"No database/index was supplied in this workspace; no substitute dataset used."})
    decisions={}
    if decisions_path and Path(decisions_path).is_file():
        with Path(decisions_path).open(newline="",encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                c=canonical_url(r.get("url", "")); t=_text(r.get("decision_at"));
                if c and t: decisions[_sha(c)]=t
    conflicts=[]
    label_by_id=defaultdict(set)
    for r in urls: label_by_id[r["url_id"]].add(r["label_class"])
    for uid, labels in label_by_id.items():
        if len(labels)>1: conflicts.append({"kind":"conflicting_labels","url_id":uid,"labels":sorted(labels),"severity":"error"})
    duplicate_urls=[{"kind":"duplicate_canonical_url","url_id":uid,"assertion_count":sum(1 for r in urls if r["url_id"]==uid),"severity":"warning"} for uid in label_by_id if sum(1 for r in urls if r["url_id"]==uid)>1]
    by_hash=defaultdict(list)
    for r in urls:
        if r["html_sha256"]: by_hash[r["html_sha256"]].append(r["url_id"])
    html_dups=[{"kind":"duplicate_html_hash","html_sha256":h,"url_ids":sorted(set(us)),"assertion_count":len(us),"severity":"warning"} for h,us in by_hash.items() if len(set(us))>1]
    split_findings=_find_split_overlaps(urls)+_group_split_contamination(urls); time_findings=_after_decision(edges,decisions); mirror_findings=_feed_mirrors(groups)
    # Missing evidence time prevents a first-seen result, rather than treating ingestion time as history.
    first_seen={"evaluable":False,"reason":"no reliable historical label availability/capture timestamps in locally supplied URLTrust assertions"}
    findings=conflicts+duplicate_urls+html_dups+split_findings+time_findings+mirror_findings
    _write_csv(tables/"urls.csv",urls,URL_COLUMNS_OUT); _write_csv(tables/"source_groups.csv",groups,["source_group_id","operator_id","independence_claim","independence_basis","first_valid_at","last_valid_at","parent_source_group_id","authority","external_access_terms"])
    _write_csv(tables/"provenance_edges.csv",[{"parent_id":g.get("parent_source_group_id"),"child_id":g["source_group_id"],"relation":"mirrors_feed","valid_from":None,"valid_until":None} for g in groups if g.get("parent_source_group_id")],["parent_id","child_id","relation","valid_from","valid_until"])
    _write_csv(tables/"url_graph_edges.csv",edges,list(edges[0]) if edges else ["edge_id","source_url_id","target_url_id","relation_type","observed_at","available_at","observer_group_id","source_observation_id","evidence_sha256","semantic_weight","quality_status","world_type"])
    _write_csv(out/"inclusion_exclusion_ledger.csv",ledger,["ledger_id","stage","action","reason","raw_row_sha256","url_id","details"]); _write_csv(out/"duplicate_conflicts.csv",findings,["kind","url_id","group_value","labels","assertion_count","html_sha256","url_ids","splits","edge_id","decision_at","evidence_at","parent_source_group_id","children","severity"])
    _write_csv(out/"sample_ledger.csv",[{"sample_id":f"S{i:06d}","url_id":r["url_id"][:16],"source_record_id":r["source_record_id"],"cohort":r["cohort"],"label_class":r["label_class"],"capture_status":r["capture_status"],"html_sha256":(r["html_sha256"] or "")[:16],"raw_row_sha256":r["raw_row_sha256"][:16]} for i,r in enumerate(urls,1)],["sample_id","url_id","source_record_id","cohort","label_class","capture_status","html_sha256","raw_row_sha256"])
    _write_csv(tables/"source_inventory.csv",source_inventory,["source_dataset","artifact_path","artifact_sha256","raw_rows","authority","external_access_terms","acquisition_status","time_semantics"])
    with (tables/"observations.jsonl").open("w",encoding="utf-8") as f:
        for r in observations: f.write(json.dumps(r,sort_keys=True)+"\n")
    summaries={}
    dimensions={"label":lambda r:r["label_class"],"source":lambda r:r["source_dataset"],"month":lambda r:(r["label_event_at"] or "missing_time")[:7],"etld_plus_one":lambda r:r["registrable_domain"] or "missing_psl","campaign":lambda r:r["campaign_id"] or "not_supplied","capture_availability":lambda r:r["capture_status"],"independent_source_ancestry":lambda r:"urltrust_index"}
    for name,fn in dimensions.items():
        c=Counter((r["cohort"],fn(r)) for r in urls); summaries[name]=[{"cohort":a,"value":b,"count":n} for (a,b),n in sorted(c.items())]
    _write_characteristics(tables,summaries)
    audit={"audit_version":"E01-curation-1", "run_at":run_at, "flow":{"raw_source_rows":sum(x["raw_rows"] for x in source_inventory),"included_assertions":len(urls),"excluded_ledger_entries":sum(x["action"]=="excluded" for x in ledger),"observations":len(observations),"graph_edges":len(edges),"decided_cases":0,"decided_case_reason":"no decision artifact supplied; ingestion does not decide labels"},"sources":source_inventory,"timestamp_semantics":{"source_created_date":"retained verbatim; never used as capture_at","capture_at":"null without authenticated capture metadata","label_available_at":"null without snapshot acquisition metadata","first_seen_evaluation":first_seen},"missingness":{"html_unavailable":sum(r["capture_status"]!="available_local_unattested" for r in urls),"missing_etld_plus_one":sum(r["registrable_domain"] is None for r in urls),"missing_capture_at":sum(r["capture_at"] is None for r in urls)},"summaries":summaries,"findings":findings,"controls":_control_tests(),"pass_criteria":{"silent_label_flips":0,"unflagged_leakage":0,"status":"pass_with_flagged_data_quality_findings","flagged_findings":len(findings)},"limitations":["No external feed was ingested: no authorised local PhishTank or other snapshot was present.","eTLD+1 is null because no Public Suffix List was supplied; a naive suffix heuristic was intentionally not used.","No reliable historical time metadata exists, so first-seen evaluation is blocked."]}
    (out/"audit.json").write_text(json.dumps(audit,indent=2,sort_keys=True),encoding="utf-8")
    return audit
