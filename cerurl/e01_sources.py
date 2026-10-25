"""E01 multi-source audit over actually acquired, receipt-backed snapshots.

Fail-closed rules: an artifact whose bytes do not match its receipt hash is not
ingested; feed absence/popularity rank is never a benign label; no timestamp is
invented (snapshot acquisition time is recorded separately and is never
``capture_at``); no HTML was acquired so capture is "unavailable", not benign.
"""
from __future__ import annotations

import csv
import heapq
import ipaddress
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .curation import (OBS_COLUMNS, URL_COLUMNS_OUT, _control_tests, _now, _sha, _text, _write_csv,
                       canonical_url, host_of)

CLASSES = ("benign", "phishing", "malware")
MIRROR_FRACTION = 0.2  # overlap fraction of the smaller feed that triggers a suspected-mirroring flag
SAMPLE_PER_COHORT = 150
DEDICATED_COLUMNS = URL_COLUMNS_OUT + ["source_event_at", "snapshot_id", "snapshot_acquired_at", "source_group_id"]

SOURCES = {
    "phiusiil": dict(path="phiusiil/PhiUSIIL_Phishing_URL_Dataset.csv", kind="phiusiil", cohort="phiusiil_uci_967",
        semantics="official `label`: 1 legitimate/benign, 0 phishing (inverted to CER 0/1); no timestamps; static release"),
    "phishtank": dict(path="phishtank/online-valid.csv", kind="phishtank", cohort="phishtank_online_valid",
        semantics="verified=yes asserts phishing at verification_time (source event time); snapshot holds only currently valid entries so removed/invalidated history is absent"),
    "openphish": dict(path="openphish/feed.txt", kind="lines", cohort="openphish_feed", cls="phishing",
        semantics="URL-only current feed; no per-URL times; membership means phishing at snapshot only, absence is unknown"),
    "phishing_database": dict(path="phishing_database/phishing-links-ACTIVE.txt", kind="lines", cohort="phishing_database_active", cls="phishing",
        semantics="URL-only aggregated active list; no per-URL times; upstream ancestry undocumented in the snapshot"),
    "urlhaus": dict(path="urlhaus/csv_recent.csv", kind="urlhaus", cohort="urlhaus_recent",
        semantics="dateadded is source event time (UTC per file header); threat class is malware distribution, not phishing"),
}
CONTEXT_ONLY = {  # popularity lists: never labels
    "tranco": ("tranco/top-1m.csv", 1), "majestic_million": ("majestic_million/majestic_million.csv", 2),
    "umbrella": ("umbrella/umbrella-top-1m.csv", 1)}


def _file_sha(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()


def _utc(value: str | None) -> str | None:
    """Normalise source-reported time to UTC Z; naive values are taken as UTC (urlhaus header says UTC)."""
    if not value: return None
    try:
        t = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    t = t.replace(tzinfo=timezone.utc) if t.tzinfo is None else t.astimezone(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


class PublicSuffixList:
    def __init__(self, path: Path):
        self.exact, self.wild, self.exc = set(), set(), set()
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split()[0] if line.strip() and not line.startswith("//") else ""
            if not line: continue
            if line.startswith("!"): self.exc.add(line[1:])
            elif line.startswith("*."): self.wild.add(line[2:])
            else: self.exact.add(line)

    def etld1(self, host: str | None) -> tuple[str | None, str]:
        if not host: return None, "missing_host"
        try:
            ipaddress.ip_address(host.strip("[]")); return None, "ip_address_host"
        except ValueError: pass
        try: host = host.encode("idna").decode("ascii")
        except UnicodeError: return None, "idna_error"
        labels = host.split(".")
        n = len(labels)
        cut = n - 1  # default rule "*": the last label is the suffix
        for i in range(n):
            suffix = ".".join(labels[i:])
            if suffix in self.exc: cut = i + 1; break
            if suffix in self.exact or ".".join(labels[i + 1:]) in self.wild and i + 1 < n: cut = i; break
        if cut <= 0: return None, "host_is_public_suffix"
        return ".".join(labels[cut - 1:]), "psl_private_and_icann"


def _rows(name: str, spec: dict, path: Path):
    """Yield (record_id, raw_text_for_hash, url, class, reason, event_at, created_at, target)."""
    kind = spec["kind"]
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as f:
        if kind == "phiusiil":
            for pos, r in enumerate(csv.DictReader(f), 1):
                raw = json.dumps(r, sort_keys=True, separators=(",", ":"))
                lab = _text(r.get("label"))
                cls, reason = ({"1": "benign", "0": "phishing"}.get(lab), None) if lab in ("0", "1") else (None, "label_not_in_{0,1}")
                yield _text(r.get("FILENAME")) or str(pos), raw, _text(r.get("URL")), cls, reason, None, None, None
        elif kind == "phishtank":
            for r in csv.DictReader(f):
                raw = json.dumps(r, sort_keys=True, separators=(",", ":"))
                ok = (r.get("verified") or "").strip().lower() == "yes"
                yield (_text(r.get("phish_id")), raw, _text(r.get("url")), "phishing" if ok else None,
                       None if ok else "phishtank_not_verified", _utc(r.get("verification_time")), _utc(r.get("submission_time")), _text(r.get("target")))
        elif kind == "urlhaus":
            for r in csv.reader(l for l in f if not l.startswith("#")):
                if len(r) < 6: continue
                threat = r[5].strip().lower()
                yield (r[0], ",".join(r), _text(r[2]), "malware" if threat == "malware_download" else None,
                       None if threat == "malware_download" else f"urlhaus_threat_{threat}_unmapped", _utc(r[1]), _utc(r[1]), None)
        else:
            for pos, line in enumerate(f, 1):
                if line.strip(): yield str(pos), line.rstrip("\r\n"), _text(line), spec["cls"], None, None, None, None


def _comp_find(parent: dict, x):
    while parent.setdefault(x, x) != x:
        parent[x] = parent[parent[x]]; x = parent[x]
    return x


def audit_acquired_sources(raw_dir: str = "data/raw", out_dir: str = "results/E01", table_dir: str = "tables",
                           psl_path: str | None = None) -> dict:
    run_at = _now(); raw = Path(raw_dir); out = Path(out_dir); tables = Path(table_dir)
    out.mkdir(parents=True, exist_ok=True); tables.mkdir(parents=True, exist_ok=True)
    psl_file = Path(psl_path) if psl_path else raw / "public_suffix_list" / "public_suffix_list.dat"
    psl = PublicSuffixList(psl_file) if psl_file.is_file() else None
    psl_meta = {"path": str(psl_file), "sha256": _file_sha(psl_file) if psl else None, "present": psl is not None}
    names = list(SOURCES)
    url_mask: dict[bytes, int] = {}            # canonical URL digest -> bitmask of (source, class)
    dup_extra: Counter = Counter()             # extra within-source repeats per URL digest
    dom_mask: dict[str, int] = {}              # eTLD+1 -> bitmask of (source, class)
    conflict_seen: set[bytes] = set()          # independent incremental record of benign-vs-malicious URLs
    counters = {k: Counter() for k in ("label", "source", "month", "etld_plus_one", "campaign", "capture_availability", "independent_source_ancestry", "target_brand_not_campaign")}
    inventory, flow, ledger_reasons, anomalies = [], {}, defaultdict(Counter), []
    samples: dict[str, list] = defaultdict(list)
    tranco_domains = None
    bit = lambda s, c: 1 << (names.index(s) * 3 + CLASSES.index(c))
    uf = (tables / "urls.csv").open("w", newline="", encoding="utf-8")
    of = (tables / "observations.jsonl").open("w", encoding="utf-8")
    lf = (out / "inclusion_exclusion_ledger.csv").open("w", newline="", encoding="utf-8")
    try:
        uw = csv.DictWriter(uf, fieldnames=DEDICATED_COLUMNS, extrasaction="ignore"); uw.writeheader()
        lw = csv.DictWriter(lf, fieldnames=["ledger_id", "stage", "action", "reason", "raw_row_sha256", "url_id", "details"]); lw.writeheader()
        for name, spec in SOURCES.items():
            path = raw / spec["path"]; receipt_path = Path(str(path) + ".receipt.json")
            entry = {"source_dataset": name, "cohort": spec["cohort"], "artifact_path": str(path), "time_semantics": spec["semantics"],
                     "raw_rows": 0, "acquisition_status": "missing_artifact"}
            if not path.is_file() or not receipt_path.is_file():
                entry["acquisition_status"] = "not_ingested_missing_artifact_or_receipt"; inventory.append(entry); flow[name] = {"raw_rows": 0, "included": 0, "excluded": 0}; continue
            receipt = json.loads(receipt_path.read_text(encoding="utf-8")); actual = _file_sha(path)
            auth = receipt.get("authorisation") or {}
            entry.update(artifact_sha256=actual, receipt_sha256=receipt.get("sha256"), snapshot_acquired_at=receipt.get("acquired_at"),
                         download_url=receipt.get("download_url"), http_last_modified=(receipt.get("headers") or {}).get("Last-Modified"),
                         authority="receipt_backed_user_authorised_acquisition" if auth.get("acquisition_authorized_by_user") else "unauthorised",
                         external_access_terms=auth.get("terms_reference") or "not_recorded")
            if actual != receipt.get("sha256") or not auth.get("acquisition_authorized_by_user"):
                entry["acquisition_status"] = "not_ingested_hash_mismatch_or_unauthorised"; inventory.append(entry); flow[name] = {"raw_rows": 0, "included": 0, "excluded": 0}; continue
            entry["acquisition_status"] = "ingested_hash_verified"
            snap = f"{name}:{actual[:16]}"; acquired = receipt.get("acquired_at")
            cohort = spec["cohort"]; raw_n = inc = exc = 0
            for rec_id, raw_text, url, cls, reason, event_at, created_at, target in _rows(name, spec, path):
                raw_n += 1; raw_hash = _sha(raw_text); ledger_id = f"{name}:{rec_id or raw_n}"
                canon = canonical_url(url) if url else None
                if canon is None or cls is None:
                    exc += 1; why = "missing_or_invalid_or_non_http_url" if canon is None else reason
                    ledger_reasons[name][why] += 1
                    lw.writerow({"ledger_id": ledger_id, "stage": "source_assertion", "action": "excluded", "reason": why, "raw_row_sha256": raw_hash, "url_id": None, "details": "No label was repaired or inferred."}); continue
                inc += 1; digest = _sha(canon).encode(); uid = digest.decode(); b = bit(name, cls)
                prior = url_mask.get(digest, 0)
                if prior & b: dup_extra[digest] += 1
                url_mask[digest] = prior | b
                benign_present = any(url_mask[digest] & bit(s, "benign") for s in names)
                malicious_present = any(url_mask[digest] & bit(s, c) for s in names for c in ("phishing", "malware"))
                if benign_present and malicious_present: conflict_seen.add(digest)
                host = host_of(canon); e1, e1_status = psl.etld1(host) if psl else (None, "missing_public_suffix_list")
                if e1: dom_mask[e1] = dom_mask.get(e1, 0) | b
                for field, when in (("source_event_at", event_at), ("created", created_at)):
                    if when and acquired and when > acquired:
                        anomalies.append({"kind": "source_timestamp_after_snapshot_acquisition", "ledger_id": ledger_id, "field": field, "source_time": when, "snapshot_acquired_at": acquired, "severity": "error"})
                if event_at and created_at and event_at < created_at:
                    anomalies.append({"kind": "verification_before_submission", "ledger_id": ledger_id, "source_time": event_at, "created": created_at, "severity": "warning"})
                month = (created_at or event_at or "")[:7] or "missing_time"
                lab_num = {"benign": 0, "phishing": 1}.get(cls)
                row = {"url_id": uid, "canonical_url": canon, "host": host, "registrable_domain": e1, "etld_plus_one_status": e1_status,
                       "source_record_id": rec_id, "source_dataset": name, "cohort": cohort, "world_type": "observed_historical" if name == "phiusiil" else "snapshot_current_feed",
                       "label": lab_num, "label_class": cls, "label_status": "source_asserted" if lab_num is not None else "source_asserted_non_cer_class",
                       "label_event_at": event_at, "label_available_at": None, "record_ingested_at": run_at, "source_created_date": created_at,
                       "capture_at": None, "capture_status": "unavailable", "campaign_id": None, "split_name": None, "raw_row_sha256": raw_hash,
                       "authority": entry["authority"], "external_access_terms": entry["external_access_terms"],
                       "source_event_at": event_at, "snapshot_id": snap, "snapshot_acquired_at": acquired, "source_group_id": name}
                uw.writerow(row)
                lw.writerow({"ledger_id": ledger_id, "stage": "source_assertion", "action": "included", "reason": cls, "raw_row_sha256": raw_hash, "url_id": uid, "details": "no HTML; label_available_at unknown (snapshot receipt time is not historical availability)"})
                of.write(json.dumps({"observation_id": _sha(f"{uid}|{ledger_id}|html"), "url_id": uid, "observed_at": None, "ingested_at": run_at, "vantage_group_id": name,
                                     "modality": "html", "artifact_sha256": None, "quality_status": "capture_unavailable", "source_group_ids": [name], "parent_observation_ids": [],
                                     "capture_error": "no_html_artifact_acquired", "world_type": row["world_type"], "source_snapshot_id": snap}, separators=(",", ":")) + "\n")
                for key, val in (("label", cls), ("source", name), ("month", month), ("etld_plus_one", e1 or e1_status), ("campaign", "not_supplied"),
                                 ("capture_availability", "unavailable"), ("independent_source_ancestry", f"{name}(ancestry_unverified)")):
                    counters[key][(cohort, val)] += 1
                if target: counters["target_brand_not_campaign"][(cohort, target)] += 1
                key = int(raw_hash[:16], 16)
                if len(samples[cohort]) < SAMPLE_PER_COHORT: heapq.heappush(samples[cohort], (-key, rec_id, uid[:16], cls, month, raw_hash[:16]))
                elif -samples[cohort][0][0] > key: heapq.heapreplace(samples[cohort], (-key, rec_id, uid[:16], cls, month, raw_hash[:16]))
            entry["raw_rows"] = raw_n; inventory.append(entry); flow[name] = {"raw_rows": raw_n, "included": inc, "excluded": exc}
    finally:
        uf.close(); of.close(); lf.close()

    # context-only popularity lists: counted, hashed, never labelled
    for name, (rel, col) in CONTEXT_ONLY.items():
        path = raw / rel; receipt_path = Path(str(path) + ".receipt.json")
        if not path.is_file() or not receipt_path.is_file(): continue
        receipt = json.loads(receipt_path.read_text(encoding="utf-8")); actual = _file_sha(path)
        verified = actual == receipt.get("sha256")
        n = 0; domains = set() if name == "tranco" and verified else None
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as f:
            for r in csv.reader(f):
                if len(r) <= col or r[0] in ("GlobalRank",): continue
                n += 1
                if domains is not None: domains.add(r[col].lower())
        if domains is not None: tranco_domains = domains
        inventory.append({"source_dataset": name, "cohort": "context_only_popularity", "artifact_path": str(path), "artifact_sha256": actual, "receipt_sha256": receipt.get("sha256"),
                          "raw_rows": n, "snapshot_acquired_at": receipt.get("acquired_at"), "download_url": receipt.get("download_url"),
                          "authority": "receipt_backed_user_authorised_acquisition", "external_access_terms": (receipt.get("authorisation") or {}).get("terms_reference"),
                          "acquisition_status": "context_only_hash_verified" if verified else "not_ingested_hash_mismatch",
                          "time_semantics": "popularity rank snapshot: not a benign label, not a capture time"})
        flow[name] = {"raw_rows": n, "included": 0, "excluded": n, "exclusion_reason": "popularity_rank_is_not_a_label (aggregate ledger entry)"}
    for name, f in flow.items():
        if f.get("exclusion_reason"): ledger_reasons[name][f["exclusion_reason"]] += f["raw_rows"]

    # post-pass analysis: duplicates, conflicts, cross-feed overlap
    findings_counts: Counter = Counter(); examples: dict = defaultdict(list)
    src_unique = Counter(); pair = Counter(); conflict_urls = set(); class_disagree = 0
    cols = ["kind", "url_id", "sources", "classes", "assertion_count", "severity"]
    with (out / "duplicate_conflicts.csv").open("w", newline="", encoding="utf-8") as cf:
        cw = csv.DictWriter(cf, fieldnames=cols); cw.writeheader()
        for digest, mask in url_mask.items():
            srcs = [s for i, s in enumerate(names) if mask >> (i * 3) & 7]
            classes = sorted({c for i, s in enumerate(names) for j, c in enumerate(CLASSES) if mask >> (i * 3 + j) & 1})
            for s in srcs: src_unique[s] += 1
            for a in range(len(srcs)):
                for b2 in range(a + 1, len(srcs)): pair[(srcs[a], srcs[b2])] += 1
            kinds = []
            if "benign" in classes and len(classes) > 1: kinds.append(("conflicting_labels", "error")); conflict_urls.add(digest)
            elif "phishing" in classes and "malware" in classes: kinds.append(("class_disagreement_phishing_vs_malware", "warning")); class_disagree += 1
            if dup_extra.get(digest): kinds.append(("duplicate_within_source", "warning"))
            if len(srcs) > 1: kinds.append(("duplicate_across_sources", "warning"))
            for kind, sev in kinds:
                findings_counts[kind] += 1
                row = {"kind": kind, "url_id": digest.decode(), "sources": "|".join(srcs), "classes": "|".join(classes), "assertion_count": 1 + dup_extra.get(digest, 0) + len(srcs) - 1, "severity": sev}
                cw.writerow(row)
                if len(examples[kind]) < 20: examples[kind].append(row)
        for a in anomalies: cw.writerow({"kind": a["kind"], "url_id": "", "sources": a["ledger_id"], "classes": "", "assertion_count": "", "severity": a["severity"]}); findings_counts[a["kind"]] += 1
    silent_flips = len(conflict_seen ^ conflict_urls)  # any difference means a label conflict was not flagged

    parent: dict = {}; mirror = []
    for (a, b2), n in sorted(pair.items()):
        frac = n / max(1, min(src_unique[a], src_unique[b2]))
        suspected = frac >= MIRROR_FRACTION
        mirror.append({"feed_a": a, "feed_b": b2, "shared_urls": n, "fraction_of_smaller": round(frac, 6), "suspected_mirroring": suspected})
        if suspected: parent[_comp_find(parent, a)] = _comp_find(parent, b2)
    clusters = defaultdict(list)
    for s in names: clusters[_comp_find(parent, s)].append(s)
    ancestry = [{"cluster": sorted(v), "status": "suspected_shared_upstream" if len(v) > 1 else "ancestry_unverified_single_feed"} for v in clusters.values()]

    dom_pair = Counter(); benign_vs_mal_domains = 0
    for e1, mask in dom_mask.items():
        srcs = [s for i, s in enumerate(names) if mask >> (i * 3) & 7]
        for a in range(len(srcs)):
            for b2 in range(a + 1, len(srcs)): dom_pair[(srcs[a], srcs[b2])] += 1
        if any(mask & bit(s, "benign") for s in names) and any(mask & bit(s, c) for s in names for c in ("phishing", "malware")): benign_vs_mal_domains += 1
    popular_overlap = None
    if tranco_domains is not None:
        popular_overlap = {s: sum(1 for (c, v), n in counters["etld_plus_one"].items() if c == SOURCES[s]["cohort"] and v in tranco_domains) for s in names}

    # summaries, tables, ledgers
    def top(counter, k=25):
        by = defaultdict(list)
        for (c, v), n in counter.items(): by[c].append((v, n))
        return {c: {"distinct": len(vs), "top": [{"value": v, "count": n} for v, n in sorted(vs, key=lambda x: (-x[1], str(x[0])))[:k]]} for c, vs in by.items()}
    summaries = {k: top(v) for k, v in counters.items()}
    _write_csv(out / "etld_plus_one_counts.csv", [{"cohort": c, "etld_plus_one": v, "count": n} for (c, v), n in sorted(counters["etld_plus_one"].items(), key=lambda x: (x[0][0], -x[1]))], ["cohort", "etld_plus_one", "count"])
    tex = [r"\begin{tabular}{lll}", r"Cohort & characteristic & count \\", r"\hline"]
    esc = lambda s: str(s).translate(str.maketrans({"_": r"\_", "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#", "{": r"\{", "}": r"\}"}))
    for key, per in summaries.items():
        for c, d in sorted(per.items()):
            for item in d["top"][: 5 if key in ("etld_plus_one", "target_brand_not_campaign") else 25]: tex.append(f"{esc(c)} & {esc(key + ': ' + str(item['value']))} & {item['count']} \\\\")
    tex.append(r"\end{tabular}"); (tables / "dataset_characteristics.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")

    sample_rows = []
    for c in sorted(samples):
        for _k, rec, u, cls, month, rh in sorted(samples[c], key=lambda x: -x[0]):
            sample_rows.append({"sample_id": f"S{len(sample_rows) + 1:06d}", "cohort": c, "source_record_id": rec, "url_id_prefix": u, "label_class": cls, "month": month, "capture_status": "unavailable", "html_sha256": "", "raw_row_sha256_prefix": rh})
    _write_csv(out / "sample_ledger.csv", sample_rows, ["sample_id", "cohort", "source_record_id", "url_id_prefix", "label_class", "month", "capture_status", "html_sha256", "raw_row_sha256_prefix"])
    groups = [{"source_group_id": s, "operator_id": s, "independence_claim": "ancestry_unverified", "independence_basis": "no documented upstream lineage in snapshot",
               "first_valid_at": None, "last_valid_at": next((i.get("snapshot_acquired_at") for i in inventory if i["source_dataset"] == s), None), "parent_source_group_id": None} for s in names]
    _write_csv(tables / "source_groups.csv", groups, list(groups[0]))
    _write_csv(tables / "provenance_edges.csv", [], ["parent_id", "child_id", "relation", "valid_from", "valid_until"])
    _write_csv(tables / "url_graph_edges.csv", [], ["edge_id", "source_url_id", "target_url_id", "relation_type", "observed_at", "available_at", "observer_group_id", "source_observation_id", "evidence_sha256", "semantic_weight", "quality_status", "world_type"])
    inv_cols = ["source_dataset", "cohort", "artifact_path", "artifact_sha256", "receipt_sha256", "raw_rows", "snapshot_acquired_at", "download_url", "http_last_modified", "authority", "external_access_terms", "acquisition_status", "time_semantics"]
    _write_csv(tables / "source_inventory.csv", inventory, inv_cols)

    ctl = _control_tests()
    ingested = [s for s in names if flow.get(s, {}).get("raw_rows")]
    total_raw = sum(f["raw_rows"] for f in flow.values()); included = sum(f["included"] for f in flow.values())
    audit = {
        "audit_version": "E01-sources-1", "run_at": run_at,
        "dataset_scope": {"urltrust_index": "not_present_locally (no index/database/ supplied); not simulated", "ingested_sources": ingested,
                          "context_only": list(CONTEXT_ONLY), "public_suffix_list": psl_meta},
        "flow": {"raw_source_rows": total_raw, "included_assertions": included, "excluded_ledger_entries": total_raw - included,
                 "unique_canonical_urls": len(url_mask), "observations": included, "graph_edges": 0, "decided_cases": 0,
                 "decided_case_reason": "no decision artifact supplied; ingestion does not decide labels", "per_source": flow,
                 "exclusion_reasons": {k: dict(v) for k, v in ledger_reasons.items()}},
        "sources": inventory,
        "timestamp_semantics": {
            "capture_at": "null everywhere: no HTML or capture time was acquired; SQL created_date is never used",
            "label_event_at": "source-reported verification/dateadded time where present (PhishTank, URLhaus); otherwise null",
            "label_available_at": "null: snapshot receipt time is an upper bound for when the label was locally available, not historical availability",
            "snapshot_acquired_at": "receipt time, recorded separately per source",
            "first_seen_evaluation": {"evaluable": False, "reason": "single point-in-time snapshots without historical availability or capture timestamps; PhishTank/URLhaus contain only currently listed entries (survivorship); PhiUSIIL and OpenPhish/Phishing.Database have no times"}},
        "missingness": {"html_unavailable": included, "missing_capture_at": included,
                        "missing_label_event_at": sum(c for (co, v), c in counters["month"].items() if v == "missing_time"),
                        "missing_etld_plus_one": sum(c for (co, v), c in counters["etld_plus_one"].items() if v in ("missing_public_suffix_list", "ip_address_host", "host_is_public_suffix", "idna_error", "missing_host"))},
        "html_similarity": {"evaluable": False, "reason": "zero HTML artifacts acquired; duplicate/near-duplicate HTML hashes cannot be computed"},
        "summaries": summaries,
        "findings": {"counts": dict(findings_counts), "examples": examples},
        "leakage": {
            "split_assignment": "not_supplied: train/test URL, same-domain and same-campaign contamination not evaluable on real data (assertion controls executed)",
            "cross_feed_url_overlap_and_mirroring": mirror, "ancestry_clusters": ancestry,
            "cross_source_etld1_overlap": [{"a": a, "b": b2, "shared_etld_plus_one": n} for (a, b2), n in sorted(dom_pair.items())],
            "etld1_with_benign_and_malicious_assertions": benign_vs_mal_domains,
            "phishing_or_malware_etld1_in_tranco_top1m": popular_overlap,
            "graph_edges_after_decision": "no graph edges (no HTML) and no decision times supplied; not evaluable",
            "source_time_anomalies": findings_counts.get("source_timestamp_after_snapshot_acquisition", 0)},
        "controls": ctl,
        "pass_criteria": {"silent_label_flips": silent_flips, "conflicting_label_urls_flagged": len(conflict_urls), "unflagged_leakage": 0,
                          "status": "pass_with_flagged_data_quality_findings" if silent_flips == 0 else "fail",
                          "unevaluable_not_claimed_clean": ["split leakage", "domain/campaign contamination across splits", "HTML similarity", "graph edges after decision", "first-seen evaluation"]},
        "limitations": ["No URLTrust index or HTML archive is present; no benign cohort other than PhiUSIIL exists.",
                        "Popularity lists are never labels; feed absence is unknown, not benign.",
                        "Feed ancestry is unverified; overlap-based mirroring flags are heuristic, not proven lineage.",
                        "PSL includes the PRIVATE section, so e.g. *.pages.dev tenants are separate eTLD+1 values.",
                        "Per-cohort counts are assertion counts, not unique-URL counts; see flow.unique_canonical_urls and duplicates."]}
    if silent_flips: raise AssertionError("label conflicts present that were not flagged")
    (out / "audit.json").write_text(json.dumps(audit, indent=2, sort_keys=True), encoding="utf-8")
    return audit
