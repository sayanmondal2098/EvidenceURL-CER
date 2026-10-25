"""E05: shared-upstream provenance graph versus naive "N reports = N witnesses".

Edges point from a node to what it depends on (child -> parent):
``derived_from``, ``mirrors_feed``, ``collected_by``, ``aggregated_from``; the
undirected ``same_operator`` edge merges nodes into one controlled unit.

Fail-closed rules:
* attack units are same-operator components of non-report ancestors;
* a directed cycle is flagged, its members are collapsed into one unit and the
  graph is marked invalid (never counted as independent);
* a report whose ancestry does not end in a declared source/collector is
  "unknown"; all unknown ancestry shares ONE pooled unit.
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from itertools import combinations
from math import ceil
from pathlib import Path

import numpy as np

DIRECTED = ("derived_from", "mirrors_feed", "collected_by", "aggregated_from")
RELATIONS = DIRECTED + ("same_operator",)
ROOT_KINDS = ("source", "collector")
UNKNOWN = "UNKNOWN_POOL"
EXACT_LIMIT = 24


class ProvGraph:
    def __init__(self, name: str, description: str = ""):
        self.name, self.description = name, description
        self.kind: dict[str, str] = {}
        self.edges: list[tuple[str, str, str]] = []
        self.report_value: dict[str, int] = {}
        self.declared_feed: dict[str, str] = {}

    def node(self, nid: str, kind: str):
        self.kind[nid] = kind
        return nid

    def report(self, rid: str, feed: str | None = None, value: int = 1):
        self.kind[rid] = "report"; self.report_value[rid] = value
        self.declared_feed[rid] = feed or rid
        return rid

    def edge(self, child: str, parent: str, rel: str):
        if rel not in RELATIONS: raise ValueError(f"unknown relation {rel}")
        for n in (child, parent): self.kind.setdefault(n, "unknown_node")
        self.edges.append((child, parent, rel))

    @property
    def reports(self): return sorted(self.report_value)


def _sccs(nodes, adj):
    index, low, on, stack, out, counter = {}, {}, set(), [], [], [0]
    for root in nodes:
        if root in index: continue
        work = [(root, iter(adj[root]))]; index[root] = low[root] = counter[0]; counter[0] += 1; stack.append(root); on.add(root)
        while work:
            v, it = work[-1]
            for w in it:
                if w not in index:
                    index[w] = low[w] = counter[0]; counter[0] += 1; stack.append(w); on.add(w); work.append((w, iter(adj[w]))); break
                if w in on: low[v] = min(low[v], index[w])
            else:
                work.pop()
                if work: low[work[-1][0]] = min(low[work[-1][0]], low[v])
                if low[v] == index[v]:
                    comp = []
                    while True:
                        w = stack.pop(); on.discard(w); comp.append(w)
                        if w == v: break
                    out.append(comp)
    return out


def _bfs(start, adj):
    seen, todo = set(), [start]
    while todo:
        for w in adj[todo.pop()]:
            if w not in seen: seen.add(w); todo.append(w)
    return seen


def _closure_matrix(nodes, adj):
    ix = {n: i for i, n in enumerate(nodes)}
    m = np.zeros((len(nodes), len(nodes)), dtype=bool)
    for u in nodes:
        for v in adj[u]: m[ix[u], ix[v]] = True
    for _ in range(max(1, len(nodes).bit_length())):
        m = m | ((m.astype(np.uint8) @ m.astype(np.uint8)) > 0)
    return {u: {v for v in nodes if m[ix[u], ix[v]]} for u in nodes}


def analyse(g: ProvGraph) -> dict:
    nodes = sorted(g.kind)
    up = {n: [] for n in nodes}; down = {n: [] for n in nodes}; ops = []
    for c, p, rel in g.edges:
        if rel == "same_operator": ops.append((c, p))
        else: up[c].append(p); down[p].append(c)
    # cycles
    cycles = [sorted(c) for c in _sccs(nodes, up) if len(c) > 1 or c[0] in up[c[0]]]
    # union-find over same-operator edges and cycle members
    parent = {n: n for n in nodes}
    def find(x):
        while parent[x] != x: parent[x] = parent[parent[x]]; x = parent[x]
        return x
    def union(a, b): parent[find(a)] = find(b)
    for a, b in ops: union(a, b)
    for comp in cycles:
        for n in comp[1:]: union(comp[0], n)
    anc = {r: _bfs(r, up) for r in nodes}
    in_cycle = {n for c in cycles for n in c}
    report_units, unknown_reports = {}, []
    for r in g.reports:
        a = anc[r]; units = {f"unit:{find(n)}" for n in a if g.kind[n] != "report"}
        terminals = [n for n in a if not up[n] and g.kind[n] != "report"]
        reaches_cycle = bool(a & in_cycle) or r in in_cycle
        if not terminals and not reaches_cycle or any(g.kind[n] not in ROOT_KINDS for n in terminals):
            units.add(UNKNOWN); unknown_reports.append(r)
        report_units[r] = units
    # a unit is a same-operator component; label members for audit
    members = defaultdict(set)
    for n in nodes:
        if g.kind[n] != "report": members[f"unit:{find(n)}"].add(n)
    members[UNKNOWN] = {r for r in unknown_reports}
    reps = g.reports
    corrupted = {u: sorted(r for r in reps if u in report_units[r]) for u in set().union(*report_units.values()) if reps}
    # node-level compromise: exactly which descendants are corrupted
    node_corruption = {n: sorted(r for r in reps if n in anc[r]) for n in nodes if g.kind[n] != "report"}
    m = len(reps); need = ceil(m / 2) if m else 0
    packing, exact = _max_disjoint(reps, report_units)
    aware = _min_units_to_flip(corrupted, need)
    # independent cross-check of reachability: BFS vs transitive-closure matrix
    cl = _closure_matrix(nodes, up)
    reach_ok = all(cl[n] == anc[n] for n in nodes)
    comps = _weak_components(nodes, g.edges)
    # declared feed labels vs computed sharing
    by_unit_feed = defaultdict(set)
    for r in reps:
        for u in report_units[r]: by_unit_feed[u].add(g.declared_feed[r])
    shared_units = {u: sorted(f) for u, f in by_unit_feed.items() if len(f) > 1}
    group_rows = [{"report": r, "declared_feed": g.declared_feed[r], "naive_group": g.declared_feed[r],
                   "attack_units": "|".join(sorted(report_units[r])), "ancestry_status": "unknown_pooled" if r in unknown_reports else ("cycle_collapsed" if (anc[r] | {r}) & in_cycle else "known"),
                   "shares_unit_with": "|".join(sorted(o for o in reps if o != r and report_units[o] & report_units[r]))} for r in reps]
    return {
        "topology": g.name, "description": g.description, "valid": not cycles and not unknown_reports,
        "n_nodes": len(nodes), "n_edges": len(g.edges), "weak_components": len(comps), "largest_component": max(map(len, comps)) if comps else 0,
        "cycles": cycles, "unknown_reports": sorted(unknown_reports),
        "reports": m, "naive_independent_witnesses": m, "source_aware_independent_witnesses": packing, "witness_count_exact": exact,
        "attack_units": sorted(corrupted), "naive_budget_to_flip": need, "aware_budget_to_flip": aware,
        "robustness_inflation_abs": need - aware if aware is not None else None,
        "robustness_inflation_ratio": round(need / aware, 4) if aware else None,
        "declared_independent_feeds_sharing_units": shared_units,
        "reachability_bfs_equals_matrix_closure": reach_ok,
        "unit_members": {u: sorted(v) for u, v in members.items()}, "unit_corrupts_reports": corrupted,
        "node_compromise_corrupts": node_corruption, "group_assignments": group_rows}


def _weak_components(nodes, edges):
    adj = {n: set() for n in nodes}
    for c, p, _ in edges: adj[c].add(p); adj[p].add(c)
    seen, out = set(), []
    for n in nodes:
        if n in seen: continue
        comp = _bfs(n, adj) | {n}; seen |= comp; out.append(comp)
    return out


def _max_disjoint(reps, units):
    if len(reps) > EXACT_LIMIT:
        used, c = set(), 0
        for r in sorted(reps, key=lambda r: len(units[r])):
            if not units[r] & used: used |= units[r]; c += 1
        return c, False
    best = [0]
    def go(i, used, c):
        if c + (len(reps) - i) <= best[0]: return
        if i == len(reps): best[0] = max(best[0], c); return
        if not units[reps[i]] & used: go(i + 1, used | units[reps[i]], c + 1)
        go(i + 1, used, c)
    go(0, frozenset(), 0)
    return best[0], True


def _min_units_to_flip(corrupted, need):
    if need == 0: return None
    us = sorted(corrupted)
    for k in range(1, len(us) + 1):
        for combo in combinations(us, k):
            if len(set().union(*(corrupted[u] for u in combo))) >= need: return k
    return None


# ----------------------------- controlled topologies -----------------------------

def _feeds(g, n, parents_of):
    for i in range(1, n + 1):
        f = g.node(f"feed{i}", "feed"); r = g.report(f"r{i}", f"feed{i}")
        g.edge(r, f, "derived_from")
        for p, rel in parents_of(i): g.edge(f, p, rel)


def topologies() -> dict[str, ProvGraph]:
    out = {}
    g = ProvGraph("shared_five", "five feed labels all mirroring one source"); g.node("S", "source")
    _feeds(g, 5, lambda i: [("S", "mirrors_feed" if i % 2 else "derived_from")]); out[g.name] = g
    g = ProvGraph("independent_five", "five feeds with distinct sources and collectors")
    for i in range(1, 6): g.node(f"S{i}", "source"); g.node(f"C{i}", "collector")
    _feeds(g, 5, lambda i: [(f"S{i}", "derived_from"), (f"C{i}", "collected_by")]); out[g.name] = g
    g = ProvGraph("partial_overlap", "feeds 1-3 mirror S1; feed4 aggregates S1+S2; feed5 uses S3")
    for s in ("S1", "S2", "S3"): g.node(s, "source")
    _feeds(g, 5, lambda i: {1: [("S1", "mirrors_feed")], 2: [("S1", "mirrors_feed")], 3: [("S1", "derived_from")],
                           4: [("S1", "aggregated_from"), ("S2", "aggregated_from")], 5: [("S3", "derived_from")]}[i]); out[g.name] = g
    g = ProvGraph("bad_data_cycle", "feeds 1-3 derive from each other in a loop (bad data); feed4 is independent"); g.node("S4", "source")
    _feeds(g, 4, lambda i: {1: [("feed2", "derived_from")], 2: [("feed3", "derived_from")], 3: [("feed1", "mirrors_feed")], 4: [("S4", "derived_from")]}[i]); out[g.name] = g
    g = ProvGraph("unknown_ancestors", "three reports with no recorded ancestry plus two with known sources")
    for i in (4, 5): g.node(f"S{i}", "source")
    for i in (1, 2, 3): g.report(f"r{i}", f"feed{i}")
    _feeds_known = [(4, "S4"), (5, "S5")]
    for i, s in _feeds_known:
        f = g.node(f"feed{i}", "feed"); r = g.report(f"r{i}", f"feed{i}"); g.edge(r, f, "derived_from"); g.edge(f, s, "derived_from")
    out[g.name] = g
    g = ProvGraph("same_operator", "S1 and S2 are run by one operator; feeds 1-2 use S1, feed3 uses S2, feeds 4-5 independent")
    for s in ("S1", "S2", "S3", "S4"): g.node(s, "source")
    g.edge("S1", "S2", "same_operator")
    _feeds(g, 5, lambda i: [({1: "S1", 2: "S1", 3: "S2", 4: "S3", 5: "S4"}[i], "derived_from")]); out[g.name] = g
    g = ProvGraph("independent_five_with_copies", "independent_five plus a verbatim copy (derived_from) of every report")
    for i in range(1, 6): g.node(f"S{i}", "source"); g.node(f"C{i}", "collector")
    _feeds(g, 5, lambda i: [(f"S{i}", "derived_from"), (f"C{i}", "collected_by")])
    for i in range(1, 6):
        c = g.report(f"copy{i}", f"feed{i}-copy"); g.edge(c, f"r{i}", "derived_from")
    out[g.name] = g
    return out


# ----------------------------- plotting and output -----------------------------

def _layout(g: ProvGraph):
    nodes = sorted(g.kind); up = defaultdict(list)
    for c, p, rel in g.edges:
        if rel != "same_operator": up[c].append(p)
    depth = {}
    def d(n, path=()):
        if n in depth: return depth[n]
        if n in path: return 0
        depth[n] = 1 + max((d(p, path + (n,)) for p in up[n]), default=-1); return depth[n]
    for n in nodes: d(n)
    cols = defaultdict(list)
    for n in nodes: cols[depth[n]].append(n)
    return {n: (depth[n], i - (len(v) - 1) / 2) for v in cols.values() for i, n in enumerate(sorted(v))}


def plot_graph(g: ProvGraph, res: dict, path: Path):
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    pos = _layout(g); colors = {"source": "#2a9d8f", "collector": "#8ab17d", "feed": "#e9c46a", "report": "#9ecae1", "unknown_node": "#bbbbbb"}
    rel_style = {"derived_from": ("#264653", "-"), "mirrors_feed": ("#e76f51", "--"), "collected_by": ("#6a4c93", ":"), "aggregated_from": ("#f4a261", "-."), "same_operator": ("#d62828", "-")}
    cyc = {n for c in res["cycles"] for n in c}; fig, ax = plt.subplots(figsize=(8, 4.5))
    for c, p, rel in g.edges:
        (x1, y1), (x2, y2) = pos[c], pos[p]; col, ls = rel_style[rel]
        ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle="-" if rel == "same_operator" else "->", color=col, ls=ls, lw=1.2, shrinkA=10, shrinkB=10, connectionstyle="arc3,rad=0.12"))
    for n, (x, y) in pos.items():
        bad = n in cyc or n in res["unknown_reports"]
        ax.scatter([x], [y], s=520, c=colors[g.kind[n]], edgecolors="red" if bad else "black", linewidths=2.5 if bad else 0.8, zorder=3)
        ax.text(x, y, n, ha="center", va="center", fontsize=6.5, zorder=4)
    for rel, (col, ls) in rel_style.items(): ax.plot([], [], color=col, ls=ls, label=rel)
    ax.legend(fontsize=6, loc="upper right"); ax.axis("off")
    ax.set_title(f"{g.name}: naive={res['naive_independent_witnesses']} vs source-aware={res['source_aware_independent_witnesses']} witnesses"
                 + ("  [INVALID: cycle/unknown]" if not res["valid"] else ""), fontsize=9)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def plot_summary(results: list[dict], path: Path):
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    x = np.arange(len(results)); w = 0.27; fig, ax = plt.subplots(figsize=(9, 4))
    ax.bar(x - w, [r["naive_independent_witnesses"] for r in results], w, label="naive N reports")
    ax.bar(x, [r["source_aware_independent_witnesses"] for r in results], w, label="source-aware independent")
    ax.bar(x + w, [r["aware_budget_to_flip"] or 0 for r in results], w, label="units to flip majority")
    ax.set_xticks(x); ax.set_xticklabels([r["topology"] for r in results], rotation=25, ha="right", fontsize=7); ax.legend(fontsize=7)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def _csv(path, rows, cols):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore"); w.writeheader()
        for r in rows: w.writerow({c: json.dumps(r[c]) if isinstance(r.get(c), (list, dict)) else r.get(c) for c in cols})


EXPECTED = {"shared_five": 1, "independent_five": 5, "partial_overlap": 2, "bad_data_cycle": 2,
            "unknown_ancestors": 3, "same_operator": 3, "independent_five_with_copies": 5}


def run_e05(out_dir: str = "results/E05", table_dir: str = "tables", plots: bool = True) -> dict:
    out = Path(out_dir); tables = Path(table_dir); (out / "plots").mkdir(parents=True, exist_ok=True); tables.mkdir(parents=True, exist_ok=True)
    topo = topologies(); results = [analyse(g) for g in topo.values()]
    if plots:
        for g, r in zip(topo.values(), results): plot_graph(g, r, out / "plots" / f"{g.name}.png")
        plot_summary(results, out / "plots" / "witness_counts_summary.png")
    by = {r["topology"]: r for r in results}
    # copy-invariance: adding verbatim copies must not raise any count
    base, copied = by["independent_five"], by["independent_five_with_copies"]
    checks = {
        "expected_independent_counts_match": {k: by[k]["source_aware_independent_witnesses"] == v for k, v in EXPECTED.items()},
        "copying_reports_does_not_increase_source_count": copied["source_aware_independent_witnesses"] == base["source_aware_independent_witnesses"] and copied["naive_independent_witnesses"] > base["naive_independent_witnesses"],
        "cycle_flagged_and_graph_invalid": bool(by["bad_data_cycle"]["cycles"]) and not by["bad_data_cycle"]["valid"],
        "cycle_members_not_counted_as_independent": by["bad_data_cycle"]["source_aware_independent_witnesses"] < by["bad_data_cycle"]["naive_independent_witnesses"] - 1,
        "unknown_not_treated_as_independent": by["unknown_ancestors"]["source_aware_independent_witnesses"] == 3 and len(by["unknown_ancestors"]["unknown_reports"]) == 3,
        "reachability_bfs_matches_matrix_closure": all(r["reachability_bfs_equals_matrix_closure"] for r in results),
        "naive_never_below_aware": all(r["robustness_inflation_abs"] is None or r["robustness_inflation_abs"] >= 0 for r in results),
        "declared_independent_feeds_sharing_units_flagged": bool(by["shared_five"]["declared_independent_feeds_sharing_units"]) and not by["independent_five"]["declared_independent_feeds_sharing_units"],
    }
    ok = all(v if isinstance(v, bool) else all(v.values()) for v in checks.values())
    summary_cols = ["topology", "valid", "reports", "naive_independent_witnesses", "source_aware_independent_witnesses", "witness_count_exact", "naive_budget_to_flip", "aware_budget_to_flip",
                    "robustness_inflation_abs", "robustness_inflation_ratio", "weak_components", "largest_component", "n_nodes", "n_edges", "cycles", "unknown_reports"]
    _csv(out / "topology_summary.csv", results, summary_cols)
    _csv(out / "group_assignments.csv", [dict(topology=r["topology"], **row) for r in results for row in r["group_assignments"]],
         ["topology", "report", "declared_feed", "naive_group", "attack_units", "ancestry_status", "shares_unit_with"])
    _csv(out / "compromise_matrix.csv", [{"topology": r["topology"], "compromised_node": n, "corrupted_descendant_reports": c, "n_corrupted": len(c), "flips_majority": len(c) >= r["naive_budget_to_flip"] > 0}
                                        for r in results for n, c in sorted(r["node_compromise_corrupts"].items())],
         ["topology", "compromised_node", "corrupted_descendant_reports", "n_corrupted", "flips_majority"])
    tex = [r"\begin{tabular}{lrrrr}", r"Topology & N reports & source-aware & budget naive & budget aware \\", r"\hline"]
    tex += [f"{r['topology'].replace('_', chr(92) + '_')} & {r['reports']} & {r['source_aware_independent_witnesses']} & {r['naive_budget_to_flip']} & {r['aware_budget_to_flip']} \\\\" for r in results]
    (tables / "e05_independence.tex").write_text("\n".join(tex + [r"\end{tabular}"]) + "\n", encoding="utf-8")
    e01 = Path("results/E01/audit.json"); observed = {"status": "no_observed_lineage_available", "reason": "E01 recorded ancestry as unverified for every acquired feed; overlap is not lineage, so observed reports are treated as unknown-ancestry (pooled), never independent"}
    if e01.is_file():
        a = json.loads(e01.read_text(encoding="utf-8")); observed["e01_cross_source_duplicate_urls"] = a.get("findings", {}).get("counts", {}).get("duplicate_across_sources")
    audit = {"audit_version": "E05-1", "world_type": "controlled_synthetic", "model": {"relations": list(RELATIONS), "attack_unit": "same-operator component of non-report ancestors (feeds, sources, collectors); unknown ancestry pooled into one unit",
             "flip_rule": "attacker flips the verdict once corrupted agreeing reports >= ceil(N/2) (ties count as a flip)", "naive_budget": "ceil(N/2) independent reports", "aware_budget": "exact minimum number of attack units whose descendant closure covers ceil(N/2) reports"},
             "topologies": [{k: v for k, v in r.items() if k not in ("group_assignments",)} for r in results], "controls": checks,
             "observed_reports": observed,
             "pass_criteria": {"source_counts_do_not_increase_when_reports_copied": checks["copying_reports_does_not_increase_source_count"], "cycles_rejected_or_flagged": checks["cycle_flagged_and_graph_invalid"],
                               "unknown_not_silently_independent": checks["unknown_not_treated_as_independent"], "status": "pass" if ok else "fail"},
             "limitations": ["Controlled topologies only; they test the accounting, not real-world feed lineage.", "Majority-vote flip model; heterogeneous weights or dissenting reports are not modelled.",
                             "Cycle members are collapsed into one unit (conservative), which may under-count truly independent members."]}
    (out / "audit.json").write_text(json.dumps(audit, indent=2, sort_keys=True), encoding="utf-8")
    if not ok: raise AssertionError(f"E05 controls failed: {checks}")
    return audit
