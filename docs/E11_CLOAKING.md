# E11: controlled multi-vantage cloaking

Run from the repository root:

```powershell
python -m cerurl.cli run-e11 --out results/E11 --tables tables --n-per 20 --seed 20261111 --budgets 1,3,5
```

The default run executes 280 sites, 4,200 policy trials and 7,840 evaluator
condition probes. `--n-per 1 --no-plots` provides a small executable check.
No internet access, DNS changes, hosts-file edits or added dependencies are
required. The HTTP server is shut down when the run finishes.

## Scope and isolation

The testbed binds only to `127.0.0.1` on an ephemeral port. The collector always
connects directly to that address using `http.client`, with a generated
`e11-00000.test`-style Host header. It does not resolve those names or use system
HTTP proxies. Redirects are allowed only to registered paths on the same host.
There are no external links, scripts, images, credential inputs or submission
endpoints. POST is refused. The simulated credential-harvesting content is an
inert HTML metadata marker and an explicitly labelled explanation.

These are actual HTTP requests and saved response bytes. Browser UA strings
are sent, but there is no rendered browser or mobile device. Network identities
are controlled request headers, not real independent network routes. Observation
slots are a logical clock, not real historical timestamps. Actual capture start,
finish and server response timestamps are separately recorded in UTC.

## Controlled schedule and truth

The schedule is fixed before any collection. Seven collectors operate in four
slots at offsets 0, 15, 30 and 45 seconds. Two desktop collectors share the same
UA, network, operator and egress ancestors. Independent desktop and mobile
collectors use other networks and source roots. A mobile collector sharing the
original egress provides a correlated-UA control.

| Scenario | Controlled behavior |
| --- | --- |
| benign_static | Always harmless |
| benign_variants | Harmless HTML changes across conditions |
| benign_marker_mention | Harmless prose mentions the marker text |
| plain_marker | Marker at every condition |
| ua_cloak | Independent mobile requests see the marker |
| network_cloak | Independent residential/cellular networks see it |
| combined_cloak | Independent mobile cellular requests see it |
| delayed_cloak | Independent collectors see it after the switch slot |
| window_cloak | Independent collectors see it only at the switch slot |
| transient_outage | All sources initially unavailable; delayed cloaking after recovery |
| targeted_outage | Every condition that would reveal the marker is unavailable |
| full_outage | All conditions unavailable; latent behavior remains cloaked |
| benign_outage | Harmless site initially unavailable, then recovers |
| temporal_change | All collectors change from harmless to marker together |

The seeded replicates vary the switch slot, presence of a redirect and page
identifier. They are not independent real-world campaigns.

Truth is the server's explicit rule state before rendering, retained for every
condition. A site's positive label means that its schedule has a latent marker
at some condition during this declared window. It does not mean that its first
request was malicious. Unavailability does not change latent truth to benign.

The evaluator independently requests the entire condition grid and records
actual availability. Its results and the schedule are withheld from policy
selection. Each policy then executes its own HTTP requests. The audit joins
responses to server receipts and verifies artifact hashes, condition metadata,
source ancestors, semantic state, redirect hashes and availability. The shared
process is a software separation boundary, not hardware isolation or remote
attestation. Hashes establish artifact integrity, not remote-world truth.

## Policies and decisions

Every policy starts with `correlated_a@0`, paying one unit. Each subsequent
attempt costs one unit, including a 503 response or a transport failure.
Policies share the full condition inventory and the same total budget ceiling.
They cannot move backwards in logical time or repeat an identical action.

| Policy | Acquisition rule |
| --- | --- |
| one_vantage | Stop after the initial observation |
| fixed_three | Then collect correlated_b@0 and desktop_independent@0 if affordable |
| random_new | Uniformly choose an affordable future/current condition from collectors not previously attempted |
| diversity | Maximize new source ancestry, UA family, network and time slot |
| cer_challenge | Rank hypothetical source-certificate improvement, verdict change and diversity per acquisition/wait cost |

Diversity weights are 2 for disjoint source ancestry, 1 each for a new UA
family and network, and 0.5 for a new slot. CER evaluates hypothetical benign
and marker observations with fixed probabilities 0.5/0.5. Its surrogate uses
equal-weight collected witnesses on a one-node graph and the existing exact
source certificate at root budget 1. Its utility is interval-width reduction
plus surrogate verdict change plus diversity, divided by attempt cost plus
0.25 per waited slot. Ties favor the earlier slot and collector registry order.
These are predeclared heuristic settings, not fitted outcome probabilities.

The surrogate certificate helps select challenges. It does not certify unseen
website states. A benign surrogate certificate never stops acquisition. No
source is quarantined merely because it disagrees with another source.

All policies use the same final decision rule: any acquired marker yields
`malicious`; otherwise an acquired harmless template yields `benign`; only
missing evidence yields `abstain`. This transparent fixture parser has no
learned labels. Finding a harmless template never proves the absence of cloaking.

One-vantage always stops at one observation and fixed-three stops at three.
Consequently their actual costs differ at larger common budget ceilings.
`paired_comparisons.csv` reports both outcome and cost differences against
fixed-three, including a `same_actual_cost` flag. At budget 3, fixed-three and
the three adaptive policies spend the same three units. The evaluator's full
grid probe costs are separate from policy acquisition costs. HTTP request counts
also include redirect hops, and byte counts include error/redirect bodies.

## Metrics and denominators

| Metric | Definition |
| --- | --- |
| Cloaking exposure rate | Cloaked sites with an acquired marker / all latent cloaked sites, including unavailable ones |
| Exposure given available opportunity | Same numerator restricted to sites whose probe grid contains both available harmless and marker states in one slot, divided by those sites |
| True contradiction discoveries | Opposite acquired semantic states in the same slot, confirmed against two available server states; counts of pairs and sites |
| Independent contradiction pairs | True contradiction pairs with disjoint source ancestors |
| Temporal semantic changes | Opposite acquired states in different slots; reported separately from simultaneous contradictions |
| Repair successes | Initially incorrect or abstaining decisions that become correct against the window-level schedule truth |
| Repair success rate | Repair successes / initially incorrect or abstaining trials |
| Decision changes | Initial and final decisions differ; intermediate transitions and degradations are also retained |
| False positives | Final malicious decisions on controlled benign sites; rate denominator includes all benign sites |
| Time-to-evidence | Time to the first acquired marker, including scheduled waiting and one modeled second per attempt |
| Missing evidence | Every failed/unavailable collection; no benign observation is created |
| Cost | Collection attempts, including the initial request and failures; requests, bytes and measured collection latency separately recorded |

Logical collection completions satisfy
`finish = max(previous_finish, slot * 15) + 1` seconds. This is a deterministic
model, not measured network latency. `time_to_evidence_wall_ms` sums actual
HTTP collection time through the first marker; it excludes logical waits and
policy computation. Conditional p50/p95 time summaries include detections only.
Undetected positive sites have null detection times and an explicit censored
flag and last follow-up time. They are never treated as immediate detections.

Different hashes alone do not establish contradiction. The benign variation
and marker-mention controls test this distinction. The full and targeted outage
controls cannot earn an exposure or repair credit from an unseen latent marker.
Zero false positives in these fixtures is not an empirical phishing accuracy
claim. No statistical significance or real-world generalization is claimed.

## Artifacts and pass gate

Outputs under `results/E11`:

- `schedule.json`: sealed site schedules and public collector/action inventory.
- `ground_truth.jsonl`, `truth_probes.jsonl`: condition truth and executed evaluator probes.
- `server_requests.jsonl`: actual request conditions, served state, status, redirect and response hash.
- `observations.jsonl`: policy acquisitions, source ancestry, capture times, costs, bytes, redirects and selection traces.
- `artifacts/*.html`: content-addressed captured response bodies, including outage pages.
- `contradictions.jsonl`: observation-pair references and truth verification.
- `trial_results.csv`, `summary.csv`, `scenario_summary.csv`: trial and aggregate metrics.
- `paired_comparisons.csv`: per-site comparisons and realized cost differences.
- `audit.json`, `manifest_sha256.json`: pass checks, limitations and artifact hashes.
- `cloaking_exposure.png`: exposure against both budget and realized cost.

`tables/e11_cloaking.tex` contains the summary table. An integrity, availability,
missingness or budget violation fails the run and withholds/removes the known
table and plot. Policy superiority is not a pass requirement: weaker results,
unresolved sites and unavailable evidence remain in the output.

The implementation and regression tests are in `cerurl/e11.py`,
`cerurl/e11_testbed.py` and `tests/test_e11.py`.
