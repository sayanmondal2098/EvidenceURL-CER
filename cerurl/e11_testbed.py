"""E11 loopback websites. Network identities and clock slots are controlled factors.

Only 127.0.0.1 is contacted; .test names are HTTP Host values, never DNS lookups.
There are no credential inputs, scripts, external resources, or POST endpoints.
The server-side schedule is ground truth, not an inference from a classifier.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from html.parser import HTMLParser
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import random
import threading
import time
from urllib.parse import urljoin, urlsplit


SLOTS = (0, 1, 2, 3)
SLOT_SECONDS = 15
MARKER = "simulated-credential-harvest"
SCENARIOS = (
    "benign_static", "benign_variants", "benign_marker_mention", "plain_marker",
    "ua_cloak", "network_cloak", "combined_cloak", "delayed_cloak",
    "window_cloak", "transient_outage", "targeted_outage", "full_outage",
    "benign_outage", "temporal_change",
)


def digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def canon(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Collector:
    collector_id: str
    user_agent: str
    ua_family: str
    network: str
    ancestors: tuple[str, ...]


DESKTOP = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
MOBILE = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36"
COLLECTORS = (
    Collector("correlated_a", DESKTOP, "desktop", "datacenter-main", ("operator-main", "egress-main")),
    Collector("correlated_b", DESKTOP, "desktop", "datacenter-main", ("operator-main", "egress-main")),
    Collector("desktop_independent", DESKTOP, "desktop", "residential-east", ("operator-desktop",)),
    Collector("mobile_east", MOBILE, "mobile", "cellular-east", ("operator-mobile-east",)),
    Collector("mobile_west", MOBILE, "mobile", "cellular-west", ("operator-mobile-west",)),
    Collector("desktop_alternate", DESKTOP, "desktop", "datacenter-west", ("operator-alternate",)),
    Collector("mobile_shared", MOBILE, "mobile", "datacenter-main", ("operator-main", "egress-main")),
)
COLLECTOR_MAP = {c.collector_id: c for c in COLLECTORS}


@dataclass(frozen=True)
class Action:
    collector_id: str
    slot: int
    cost: float = 1.0

    @property
    def action_id(self) -> str:
        return f"{self.collector_id}@{self.slot}"


ACTIONS = tuple(Action(c.collector_id, slot) for slot in SLOTS for c in COLLECTORS)


@dataclass(frozen=True)
class Site:
    site_id: str
    scenario: str
    switch_slot: int
    redirect: bool
    variant: int

    def __post_init__(self):
        if (self.scenario not in SCENARIOS or self.switch_slot not in SLOTS
                or not self.site_id.startswith("e11-") or not self.site_id[4:].isdigit()):
            raise ValueError("Unregistered site or schedule")

    @property
    def host(self) -> str:
        return f"{self.site_id}.test"

    @property
    def url(self) -> str:
        return f"http://{self.host}/"


def make_sites(n_per: int, seed: int) -> list[Site]:
    if not isinstance(n_per, int) or n_per < 1:
        raise ValueError("n_per must be a positive integer")
    rng = random.Random(seed)
    return [Site(f"e11-{i * n_per + j:05d}", scenario, rng.choice((1, 2)),
                 bool(rng.getrandbits(1)), rng.randrange(1000000))
            for i, scenario in enumerate(SCENARIOS) for j in range(n_per)]


def site_state(site: Site, user_agent: str, network: str, slot: int) -> dict:
    """Authoritative latent behavior and availability, before rendering bytes.

    Cloaked sites protect the correlated egress, regardless of collector name.
    An outage masks latent behavior; it never changes its truth to benign.
    """
    mobile = "Mobile" in user_agent
    independent = network != "datacenter-main"
    s = site.scenario
    marker = False
    if s == "plain_marker":
        marker = True
    elif s == "temporal_change":
        marker = slot >= site.switch_slot
    elif s == "ua_cloak":
        marker = independent and mobile
    elif s == "network_cloak":
        marker = independent and (network.startswith("residential") or network.startswith("cellular"))
    elif s in {"combined_cloak", "targeted_outage"}:
        marker = independent and mobile and network.startswith("cellular")
    elif s in {"delayed_cloak", "transient_outage"}:
        marker = independent and slot >= site.switch_slot
    elif s == "window_cloak":
        marker = independent and slot == site.switch_slot
    elif s == "full_outage":
        marker = independent
    available = not (
        s == "full_outage" or (s == "targeted_outage" and marker)
        or (s in {"transient_outage", "benign_outage"} and slot < site.switch_slot)
    )
    return {"latent_state": MARKER if marker else "benign", "available": available,
            "served_state": (MARKER if marker else "benign") if available else None}


def render_page(site: Site, state: dict, user_agent: str, network: str, slot: int) -> bytes:
    if not state["available"]:
        return b"<!doctype html><title>Controlled outage</title><p>Evidence unavailable.</p>"
    marker = state["served_state"] == MARKER
    title = "Simulated credential-harvesting marker" if marker else "Harmless information page"
    variation = f"{network}:{slot}:{'Mobile' in user_agent}" if site.scenario == "benign_variants" else "stable"
    mention = f"<p>Documentation mentions {MARKER}; this is a benign control.</p>" if site.scenario == "benign_marker_mention" else ""
    return (f'<!doctype html><html><head><meta name="e11-state" content="{state["served_state"]}">'
            f"<title>{title}</title></head><body><h1>{title}</h1>"
            "<p>Controlled E11 fixture. No credentials are requested or collected.</p>"
            f"<p>{site.site_id}:{site.variant}:{variation}</p>{mention}</body></html>").encode()


class _StateParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.states = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta" and attrs.get("name") == "e11-state":
            self.states.append(attrs.get("content"))


def classify(body: bytes, status: int | None) -> str | None:
    """A transparent fixture parser, not an ML phishing detector."""
    if status != 200:
        return None
    parser = _StateParser()
    parser.feed(body.decode("utf-8", errors="replace"))
    if parser.states == [MARKER]:
        return "malicious"
    if parser.states == ["benign"]:
        return "benign"
    return None


class Testbed:
    """Context-managed loopback HTTP server, with an evaluator-only request log."""
    __test__ = False

    def __init__(self, sites: list[Site]):
        self.sites = {s.host: s for s in sites}
        self.request_log: list[dict] = []
        self.server = None
        self.thread = None

    def __enter__(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            disable_nagle_algorithm = True

            def log_message(self, *_args):
                pass

            def do_POST(self):
                self.send_error(405, "This fixture has no submission endpoint")

            def do_GET(self):
                host = self.headers.get("Host", "")
                site = owner.sites.get(host)
                try:
                    slot = int(self.headers.get("X-E11-Slot", "-1"))
                except ValueError:
                    slot = -1
                network = self.headers.get("X-E11-Network", "")
                ua = self.headers.get("User-Agent", "")
                if (site is None or slot not in SLOTS or network not in {c.network for c in COLLECTORS}
                        or ua not in {c.user_agent for c in COLLECTORS}
                        or self.path not in {"/", "/template", "/simulation"}):
                    self.send_error(400, "Unregistered experiment condition")
                    return
                state = site_state(site, ua, network, slot)
                location = None
                if not state["available"]:
                    status = 503
                    body = render_page(site, state, ua, network, slot)
                elif self.path == "/" and site.redirect:
                    status = 302
                    location = "/simulation" if state["served_state"] == MARKER else "/template"
                    body = b""
                else:
                    status = 200
                    body = render_page(site, state, ua, network, slot)
                record = {"request_id": self.headers.get("X-E11-Request-ID"), "site_id": site.site_id,
                          "peer_ip": self.client_address[0], "peer_port": self.client_address[1],
                          "path": self.path, "user_agent": ua, "network": network, "slot": slot,
                          "status": status, "location": location, "body_sha256": digest(body),
                          "server_at_utc": utc_now(), **state}
                owner.request_log.append(record)
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Security-Policy", "default-src 'none'; form-action 'none'; frame-ancestors 'none'")
                if location:
                    self.send_header("Location", location)
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        self.thread.start()
        return self

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def __exit__(self, *_args):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=5)


def safe_redirect(current: str, location: str, host: str) -> str:
    target = urljoin(current, location)
    p = urlsplit(target)
    if (p.scheme != "http" or p.netloc != host or p.path not in {"/", "/template", "/simulation"}
            or p.query or p.fragment):
        raise ValueError("Redirect outside the registered .test site")
    return target


def collect(port: int, host: str, action: Action, request_id: str, artifact_dir: Path,
            connection: HTTPConnection | None = None) -> dict:
    """Fetch actual bytes without DNS, proxies, JS, or external redirect following.

    This function receives no Site, scenario, rule, ground-truth state or future
    response. Error pages are retained as artifacts, but never benign evidence.
    """
    if not host.startswith("e11-") or not host.endswith(".test") or not host[4:-5].isdigit():
        raise ValueError("Only generated E11 .test hosts may be collected")
    if action.slot not in SLOTS or action.collector_id not in COLLECTOR_MAP:
        raise ValueError("Unknown condition")
    if connection is not None and (connection.host != "127.0.0.1" or connection.port != port):
        raise ValueError("Reusable connection must target this loopback testbed")
    collector = COLLECTOR_MAP[action.collector_id]
    artifact_dir.mkdir(parents=True, exist_ok=True)
    url = f"http://{host}/"
    chain, body, status, error = [], b"", None, None
    started = utc_now()
    t0 = time.perf_counter()
    owned_connection = connection is None
    connection = connection or HTTPConnection("127.0.0.1", port, timeout=3)
    for hop in range(4):
        try:
            connection.request("GET", urlsplit(url).path, headers={
                "Host": host, "User-Agent": collector.user_agent,
                "X-E11-Network": collector.network, "X-E11-Slot": str(action.slot),
                "X-E11-Request-ID": f"{request_id}:{hop}",
            })
            response = connection.getresponse()
            status = response.status
            body = response.read(65537)
            if len(body) > 65536:
                raise ValueError("Fixture response exceeds size limit")
            location = response.getheader("Location")
            body_hash = digest(body)
            (artifact_dir / f"{body_hash}.html").write_bytes(body)
            chain.append({"url": url, "status": status, "location": location,
                          "body_sha256": body_hash, "bytes": len(body),
                          "request_id": f"{request_id}:{hop}"})
            if status not in {301, 302, 303, 307, 308}:
                break
            if not location:
                raise ValueError("Redirect lacks Location")
            url = safe_redirect(url, location, host)
        except (OSError, HTTPException, ValueError) as exc:
            error = f"{type(exc).__name__}: {exc}"
            connection.close()
            break
        finally:
            if owned_connection:
                connection.close()
    else:
        error = "redirect_limit"
    observed = None if error else classify(body, status)
    missing_reason = None
    if observed is None:
        missing_reason = error or (f"http_{status}" if status != 200 else "unrecognized_template")
    return {"observation_id": request_id, "site_id": host[:-5], "url": f"http://{host}/",
            "action_id": action.action_id, "collector_id": collector.collector_id,
            "user_agent": collector.user_agent, "ua_family": collector.ua_family,
            "network": collector.network, "source_ancestors": list(collector.ancestors),
            "slot": action.slot, "scheduled_offset_s": action.slot * SLOT_SECONDS,
            "capture_started_at_utc": started, "capture_finished_at_utc": utc_now(),
            "wall_latency_ms": (time.perf_counter() - t0) * 1000,
            "available": observed is not None, "observed": observed,
            "missing_reason": missing_reason,
            "status": status, "body_sha256": chain[-1]["body_sha256"] if chain else None,
            "redirect_chain": chain, "redirect_chain_sha256": digest(canon(chain)),
            "http_requests": hop + 1, "response_bytes": sum(h["bytes"] for h in chain),
            "acquisition_cost": action.cost}
