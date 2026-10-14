# Source acquisition registry

All entries are **not acquired**. They are controlled intake specifications, not evidence or permission to fetch.

| Source | What to collect | Why | Intake gate |
| --- | --- | --- | --- |
| [PhiUSIIL (UCI 967)](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) | URL/website tabular dataset and documented class-label convention | URL-only historical baseline cohort | retain the UCI release hash, citation and CC BY 4.0 attribution; preserve the existing local prepared CSV with its transformation manifest |
| [PhishTank](https://phishtank.net/developer_info.php) | verified phishing URLs, submission/verification timestamps, target brand, online state | prospective phishing observations | use descriptive User-Agent; register an application key for automated downloads; retain snapshot hash, retrieval time, response headers, and terms version |
| [PhishingEval](https://github.com/Fujiaoji/PhishingEval) | available HTML, screenshots, URL/brand reference data, failure cases, and controlled perturbation examples where released | content-level analysis and controlled perturbations | pin repository commit and every selected Zenodo dataset artifact hash; verify applicable dataset license and terms before acquisition |
| [Common Crawl](https://www.commoncrawl.org/get-started) | WARC/WAT/WET archived responses and observed crawler links | historical evidence and graph construction | record crawl ID, CDX/WARC record locator, WARC digest, fetch timestamp, HTTP metadata, and applicable access/usage terms; parse locally without executing page content |
| [Tranco](https://tranco-list.eu/) | versioned popular-domain ranking and permanent list identifier | candidate pool for independently screened benign observations | retain list ID, retrieval time, Last-Modified header, source attribution and component-provider terms |
| [PhiShark 2026](https://phishark2026dataset.com/) | scan metadata plus available HTML, screenshots, DNS/TLS/redirect/hosting evidence | optional academic-access multi-layer website evidence | restricted academic/nonprofit access: manual approval, signed Data Use Agreement, non-commercial use and no redistribution; retain approval/DUA and release hashes |

## Common rules

- A registry entry is not an acquired dataset.
- No live crawling, form submission, content execution, or contact with observed targets.
- Every acquired snapshot needs immutable bytes, SHA-256, receipt time, source/release identifier, and access-terms record.
- Feeds and popularity lists are not benign labels by absence or rank.
- Independent-source ancestry must be documented before robustness claims.
