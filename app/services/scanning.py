from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from typing import Iterable, List, Optional
from urllib.parse import quote_plus, urlparse
from urllib.request import Request, urlopen

from app import config
from app.logger import get_logger
logger = get_logger("app.services.scanning")


@dataclass
class SubdomainResult:
    hostname: str
    source: str


@dataclass
class HttpxResult:
    host: str
    url: str
    ip: Optional[str]
    port: Optional[int]
    protocol: Optional[str]
    status_code: Optional[int]
    title: Optional[str]
    tech: List[str]


@dataclass
class NaabuResult:
    host: str
    ip: Optional[str]
    port: int
    protocol: str


@dataclass
class DnsxResult:
    host: str
    a: List[str]
    aaaa: List[str]
    cname: Optional[str]
    mx: List[str]
    ns: List[str]
    txt: List[str]


@dataclass
class ScanFinding:
    title: str
    severity: str
    description: str
    evidence: str
    tool: str
    target: str
    port: Optional[int] = None
    template_id: Optional[str] = None
    cvss: Optional[float] = None
    cve: Optional[str] = None


_SCAN_SEMAPHORE = threading.BoundedSemaphore(config.get_scan_concurrency()) if config.get_scan_concurrency() > 0 else None
_SCAN_WORKDIR: Optional[str] = None
_HEALTH_CACHE: dict[str, bool] = {}
_RATE_LOCK = threading.Lock()
_NEXT_ALLOWED_AT = 0.0


class ScannerCommandError(RuntimeError):
    def __init__(self, cmd: List[str], stderr: str, returncode: int) -> None:
        super().__init__(f"Scanner command failed ({returncode}): {' '.join(cmd)} :: {stderr}".strip())
        self.cmd = cmd
        self.stderr = stderr
        self.returncode = returncode


def _scan_workdir() -> str:
    global _SCAN_WORKDIR
    configured = config.get_scan_workdir()
    if configured:
        os.makedirs(configured, exist_ok=True)
        return configured
    if _SCAN_WORKDIR is None:
        _SCAN_WORKDIR = tempfile.mkdtemp(prefix="asm-scan-")
    return _SCAN_WORKDIR


def _use_container(tool: str) -> bool:
    if config.get_scan_isolation() != "container":
        return False
    return bool(config.get_scan_container_image(tool))


def _translate_arg_path(value: str, host_root: str, container_root: str) -> str:
    normalized = os.path.normpath(value)
    host_root = os.path.normpath(host_root)
    if normalized.startswith(host_root):
        rel = os.path.relpath(normalized, host_root)
        return os.path.join(container_root, rel).replace("\\", "/")
    return value


def _containerize_args(args: List[str], tool: str) -> List[str]:
    image = config.get_scan_container_image(tool)
    if not image:
        return args
    host_root = _scan_workdir()
    container_root = config.get_scan_container_workdir()
    volume = f"{host_root}:{container_root}"
    translated = [_translate_arg_path(arg, host_root, container_root) for arg in args]
    command = ["docker", "run", "--rm", "-v", volume, "-w", container_root]
    network = config.get_scan_container_network()
    if network:
        command.extend(["--network", network])
    extra = config.get_scan_container_args()
    if extra:
        command.extend(extra)
    command.append(image)
    command.extend(translated)
    return command


@contextmanager
def _rate_limit() -> Iterable[None]:
    if _SCAN_SEMAPHORE is None:
        _apply_rate_limit()
        yield
        return
    _SCAN_SEMAPHORE.acquire()
    try:
        _apply_rate_limit()
        yield
    finally:
        _SCAN_SEMAPHORE.release()


def _apply_rate_limit() -> None:
    global _NEXT_ALLOWED_AT
    rate = config.get_scan_rate()
    if rate <= 0:
        return
    interval = 1.0 / rate
    wait = 0.0
    with _RATE_LOCK:
        now = time.monotonic()
        scheduled = _NEXT_ALLOWED_AT if _NEXT_ALLOWED_AT > now else now
        wait = scheduled - now
        _NEXT_ALLOWED_AT = scheduled + interval
    if wait > 0:
        time.sleep(wait)


def _execute_command(args: List[str], timeout: int) -> str:
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise ScannerCommandError(args, result.stderr.strip(), result.returncode)
    return result.stdout


def _run_with_retry(args: List[str], timeout: int, retries: int) -> str:
    backoff = max(0.0, config.get_scan_retry_backoff())
    max_backoff = max(backoff, config.get_scan_retry_max_backoff())
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return _execute_command(args, timeout)
        except Exception as exc:
            last_exc = exc
            if attempt >= retries:
                raise
            if backoff > 0:
                time.sleep(min(backoff, max_backoff))
                backoff = min(backoff * 2, max_backoff)
    if last_exc:
        raise last_exc
    raise RuntimeError("Scanner command failed without exception.")


def _check_tool_health(tool: str, binary: str) -> None:
    if not config.get_scan_healthcheck_enabled():
        return
    if _HEALTH_CACHE.get(tool):
        return
    candidates = [[binary, "--version"], [binary, "-h"]]
    timeout = min(15, max(1, config.get_scanner_timeout()))
    for cmd in candidates:
        command = _containerize_args(cmd, tool) if _use_container(tool) else cmd
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        except Exception:
            result = None
        if result is not None and result.returncode == 0:
            _HEALTH_CACHE[tool] = True
            return
    raise RuntimeError(f"Health check failed for scanner {tool}.")

def _resolve_binary(tool: str, default: str) -> Optional[str]:
    if _use_container(tool):
        return default
    path = config.get_scanner_bin(tool, default)
    resolved = shutil.which(path) or (path if os.path.isfile(path) else None)
    if not resolved:
        if config.get_allow_stub_scans():
            return None
        raise RuntimeError(f"Missing scanner binary for {tool}. Set ASM_{tool.upper()}_BIN.")
    return resolved


def _run_command(args: List[str], timeout: int, tool: Optional[str] = None) -> str:
    command = args
    if tool:
        _check_tool_health(tool, args[0])
        if _use_container(tool):
            command = _containerize_args(args, tool)
    with _rate_limit():
        return _run_with_retry(command, timeout, config.get_scan_retries())


def _write_list(items: Iterable[str]) -> str:
    handle = tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8", dir=_scan_workdir())
    try:
        for item in items:
            handle.write(f"{item}\n")
        return handle.name
    finally:
        handle.close()


def _run_template_command(template: str, **tokens: str) -> str:
    rendered = template
    for key, value in tokens.items():
        rendered = rendered.replace(f"{{{key}}}", value)
    if tokens:
        first_value = next(iter(tokens.values()))
        if "{" not in template or rendered == template:
            rendered = f"{template} {first_value}"
    args = shlex.split(rendered)
    return _run_command(args, config.get_scanner_timeout())


def _extract_hosts(obj: object) -> List[str]:
    if obj is None:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, list):
        hosts: List[str] = []
        for item in obj:
            hosts.extend(_extract_hosts(item))
        return hosts
    if isinstance(obj, dict):
        hosts: List[str] = []
        for key in ("name", "hostname", "domain", "subdomain", "value", "host"):
            if key in obj:
                hosts.extend(_extract_hosts(obj[key]))
        for value in obj.values():
            if isinstance(value, (list, dict)):
                hosts.extend(_extract_hosts(value))
        return hosts
    return []


def _normalize_hosts(raw_hosts: Iterable[str], domain: str) -> List[str]:
    results: List[str] = []
    seen = set()
    limit = config.get_intel_host_limit()
    for host in raw_hosts:
        if not host:
            continue
        value = str(host).strip().lower().rstrip(".")
        if value.startswith("*."):
            value = value[2:]
        if domain and not value.endswith(domain):
            continue
        if value in seen:
            continue
        seen.add(value)
        results.append(value)
        if len(results) >= limit:
            break
    return results


def _parse_host_output(output: str, domain: str) -> List[str]:
    stripped = output.strip()
    if not stripped:
        return []
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None
        if parsed is not None:
            return _normalize_hosts(_extract_hosts(parsed), domain)
        hosts: List[str] = []
        for line in stripped.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            hosts.extend(_extract_hosts(entry))
        if hosts:
            return _normalize_hosts(hosts, domain)
    return _normalize_hosts(stripped.splitlines(), domain)


def _load_dns_bruteforce_words() -> List[str]:
    words: List[str] = []
    wordlist = config.get_dns_brute_wordlist()
    limit = config.get_dns_brute_limit()
    if wordlist and os.path.isfile(wordlist):
        try:
            with open(wordlist, "r", encoding="utf-8") as handle:
                for line in handle:
                    value = line.strip()
                    if not value or value.startswith("#"):
                        continue
                    words.append(value)
                    if len(words) >= limit:
                        break
        except OSError:
            words = []
    if not words:
        for value in config.get_dns_brute_words().split(","):
            cleaned = value.strip()
            if cleaned:
                words.append(cleaned)
        words = words[:limit]
    return words


def _load_ffuf_words() -> List[str]:
    words: List[str] = []
    wordlist = config.get_ffuf_wordlist()
    limit = config.get_ffuf_limit()
    if wordlist and os.path.isfile(wordlist):
        try:
            with open(wordlist, "r", encoding="utf-8") as handle:
                for line in handle:
                    value = line.strip()
                    if not value or value.startswith("#"):
                        continue
                    words.append(value)
                    if len(words) >= limit:
                        break
        except OSError:
            words = []
    if not words:
        for value in config.get_ffuf_words().split(","):
            cleaned = value.strip()
            if cleaned:
                words.append(cleaned)
        words = words[:limit]
    return words


def _load_dirsearch_words() -> List[str]:
    words: List[str] = []
    wordlist = config.get_dirsearch_wordlist() or config.get_ffuf_wordlist()
    limit = config.get_dirsearch_limit()
    if wordlist and os.path.isfile(wordlist):
        try:
            with open(wordlist, "r", encoding="utf-8") as handle:
                for line in handle:
                    value = line.strip()
                    if not value or value.startswith("#"):
                        continue
                    words.append(value)
                    if len(words) >= limit:
                        break
        except OSError:
            words = []
    if not words:
        for value in config.get_dirsearch_words().split(","):
            cleaned = value.strip()
            if cleaned:
                words.append(cleaned)
        words = words[:limit]
    return words


def run_dns_bruteforce_wordlist(domain: str) -> List[str]:
    words = _load_dns_bruteforce_words()
    if not words:
        return []
    candidates = [f"{word}.{domain}" for word in words]
    results = run_dnsx(candidates)
    hosts: List[str] = []
    for result in results:
        host = result.host or ""
        if not host:
            continue
        if result.a or result.aaaa or result.cname:
            hosts.append(host)
    return _normalize_hosts(hosts, domain)


def run_subfinder(domain: str) -> List[SubdomainResult]:
    binary = _resolve_binary("subfinder", "subfinder")
    if not binary:
        return []
    args = [binary, "-silent", "-d", domain]
    args.extend(config.get_scanner_args("subfinder"))
    output = _run_command(args, config.get_scanner_timeout(), tool="subfinder")
    return [SubdomainResult(hostname=line.strip(), source="subfinder") for line in output.splitlines() if line.strip()]


def run_amass(domain: str) -> List[SubdomainResult]:
    binary = _resolve_binary("amass", "amass")
    if not binary:
        return []
    args = [binary, "enum", "-passive", "-d", domain, "-silent"]
    args.extend(config.get_scanner_args("amass"))
    output = _run_command(args, config.get_scanner_timeout(), tool="amass")
    return [SubdomainResult(hostname=line.strip(), source="amass") for line in output.splitlines() if line.strip()]


def run_chaos(domain: str) -> List[SubdomainResult]:
    binary = _resolve_binary("chaos", "chaos")
    if not binary:
        return []
    args = [binary, "-silent", "-d", domain]
    args.extend(config.get_scanner_args("chaos"))
    output = _run_command(args, config.get_scanner_timeout(), tool="chaos")
    hosts = _parse_host_output(output, domain)
    return [SubdomainResult(hostname=host, source="chaos") for host in hosts]


def discover_subdomains(domain: str) -> List[SubdomainResult]:
    results = {entry.hostname: entry for entry in run_subfinder(domain)}
    for entry in run_amass(domain):
        results.setdefault(entry.hostname, entry)
    for entry in run_chaos(domain):
        results.setdefault(entry.hostname, entry)
    for hostname in run_cert_transparency(domain):
        results.setdefault(hostname, SubdomainResult(hostname=hostname, source="cert-transparency"))
    for hostname in run_certspotter(domain):
        results.setdefault(hostname, SubdomainResult(hostname=hostname, source="certspotter"))
    for hostname in run_pdns(domain):
        results.setdefault(hostname, SubdomainResult(hostname=hostname, source="passive-dns"))
    for hostname in run_censys_hosts(domain):
        results.setdefault(hostname, SubdomainResult(hostname=hostname, source="censys"))
    for hostname in run_dns_bruteforce_wordlist(domain):
        results.setdefault(hostname, SubdomainResult(hostname=hostname, source="dnsx-bruteforce"))
    for hostname in run_dns_bruteforce(domain):
        results.setdefault(hostname, SubdomainResult(hostname=hostname, source="dns-bruteforce"))
    for hostname in run_puredns(domain):
        results.setdefault(hostname, SubdomainResult(hostname=hostname, source="puredns"))
    for hostname in run_massdns(domain):
        results.setdefault(hostname, SubdomainResult(hostname=hostname, source="massdns"))
    for hostname in run_securitytrails_hosts(domain):
        results.setdefault(hostname, SubdomainResult(hostname=hostname, source="securitytrails"))
    for hostname in run_dnsdumpster_hosts(domain):
        results.setdefault(hostname, SubdomainResult(hostname=hostname, source="dnsdumpster"))
    for hostname in run_shodan_hosts(domain):
        results.setdefault(hostname, SubdomainResult(hostname=hostname, source="shodan"))
    for hostname in run_cloudflare_hosts(domain):
        results.setdefault(hostname, SubdomainResult(hostname=hostname, source="cloudflare"))
    return list(results.values())


def run_cert_transparency(domain: str) -> List[str]:
    if not config.get_ct_enabled():
        return []
    query = f"https://crt.sh/?q=%25.{domain}&output=json"
    request = Request(query, headers={"User-Agent": "asm-platform"})
    try:
        with urlopen(request, timeout=config.get_scanner_timeout()) as response:
            raw = response.read().decode("utf-8")
    except Exception:
        return []
    try:
        data = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    hosts: List[str] = []
    seen = set()
    for entry in data:
        name_value = entry.get("name_value") or ""
        for name in str(name_value).splitlines():
            name = name.strip().lower()
            if not name:
                continue
            if name.startswith("*."):
                name = name[2:]
            if not name.endswith(domain):
                continue
            if name in seen:
                continue
            seen.add(name)
            hosts.append(name)
            if len(hosts) >= config.get_ct_max():
                return hosts
    return hosts


def run_certspotter(domain: str) -> List[str]:
    if not config.get_certspotter_enabled():
        return []
    url = (
        "https://api.certspotter.com/v1/issuances"
        f"?domain={quote_plus(domain)}&include_subdomains=true&expand=dns_names"
    )
    headers = {"User-Agent": "asm-platform"}
    token = config.get_certspotter_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        request = Request(url, headers=headers)
        with urlopen(request, timeout=config.get_scanner_timeout()) as response:
            raw = response.read().decode("utf-8")
    except Exception:
        return []
    try:
        data = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    hosts: List[str] = []
    for entry in data:
        names = entry.get("dns_names") if isinstance(entry, dict) else []
        if isinstance(names, str):
            names = [names]
        for name in names or []:
            if not name:
                continue
            hosts.append(str(name))
            if len(hosts) >= config.get_certspotter_limit():
                return _normalize_hosts(hosts, domain)
    return _normalize_hosts(hosts, domain)


def run_pdns(domain: str) -> List[str]:
    template = config.get_pdns_command()
    if not template:
        return []
    try:
        output = _run_template_command(template, domain=domain)
    except Exception:
        return []
    return _parse_host_output(output, domain)


def run_censys_hosts(domain: str) -> List[str]:
    template = config.get_censys_command()
    if not template:
        return []
    try:
        output = _run_template_command(template, domain=domain)
    except Exception:
        return []
    return _parse_host_output(output, domain)


def run_dns_bruteforce(domain: str) -> List[str]:
    template = config.get_dns_brute_command()
    if not template:
        return []
    try:
        output = _run_template_command(template, domain=domain)
    except Exception:
        return []
    return _parse_host_output(output, domain)


def run_puredns(domain: str) -> List[str]:
    template = config.get_puredns_command()
    if not template:
        return []
    try:
        output = _run_template_command(template, domain=domain)
    except Exception:
        return []
    return _parse_host_output(output, domain)


def run_massdns(domain: str) -> List[str]:
    template = config.get_massdns_command()
    if not template:
        return []
    try:
        output = _run_template_command(template, domain=domain)
    except Exception:
        return []
    return _parse_host_output(output, domain)


def run_reverse_ip(ip: str) -> List[str]:
    template = config.get_reverse_ip_command()
    if not template:
        return []
    try:
        output = _run_template_command(template, ip=ip)
    except Exception:
        return []
    return _parse_host_output(output, "")


def run_securitytrails_hosts(domain: str) -> List[str]:
    template = config.get_securitytrails_command()
    if not template:
        return []
    try:
        output = _run_template_command(template, domain=domain)
    except Exception:
        return []
    return _parse_host_output(output, domain)


def run_dnsdumpster_hosts(domain: str) -> List[str]:
    template = config.get_dnsdumpster_command()
    if not template:
        return []
    try:
        output = _run_template_command(template, domain=domain)
    except Exception:
        return []
    return _parse_host_output(output, domain)


def run_shodan_hosts(domain: str) -> List[str]:
    template = config.get_shodan_command()
    if not template:
        return []
    try:
        output = _run_template_command(template, domain=domain)
    except Exception:
        return []
    return _parse_host_output(output, domain)


def run_cloudflare_hosts(domain: str) -> List[str]:
    template = config.get_cloudflare_command()
    if not template:
        return []
    try:
        output = _run_template_command(template, domain=domain)
    except Exception:
        return []
    return _parse_host_output(output, domain)


def run_httpx(hosts: Iterable[str]) -> List[HttpxResult]:
    binary = _resolve_binary("httpx", "httpx")
    if not binary:
        return []
    host_list = list({host.strip() for host in hosts if host and host.strip()})
    if not host_list:
        return []
    host_file = _write_list(host_list)
    args = [binary, "-silent", "-json", "-l", host_file]
    extra_args = config.get_scanner_args("httpx")
    if config.get_httpx_tech_detect() and "-tech-detect" not in extra_args and "-td" not in extra_args:
        args.append("-tech-detect")
    args.extend(extra_args)
    try:
        output = _run_command(args, config.get_scanner_timeout(), tool="httpx")
    finally:
        try:
            os.unlink(host_file)
        except OSError:
            pass
    results: List[HttpxResult] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            port = data.get("port")
            if isinstance(port, str) and port.isdigit():
                port = int(port)
            results.append(
                HttpxResult(
                    host=data.get("host") or data.get("input") or data.get("url") or "",
                    url=data.get("url") or "",
                    ip=data.get("ip"),
                    port=port if isinstance(port, int) else None,
                    protocol=data.get("scheme"),
                    status_code=data.get("status_code"),
                    title=data.get("title"),
                    tech=data.get("tech") or [],
                )
            )
        except json.JSONDecodeError:
            results.append(HttpxResult(host=line, url=line, ip=None, port=None, protocol=None, status_code=None, title=None, tech=[]))
    return results


def run_naabu(hosts: Iterable[str]) -> List[NaabuResult]:
    binary = _resolve_binary("naabu", "naabu")
    if not binary:
        return []
    host_list = list({host.strip() for host in hosts if host and host.strip()})
    if not host_list:
        return []
    host_file = _write_list(host_list)
    args = [binary, "-silent", "-json", "-l", host_file]
    args.extend(config.get_scanner_args("naabu"))
    try:
        output = _run_command(args, config.get_scanner_timeout(), tool="naabu")
    finally:
        try:
            os.unlink(host_file)
        except OSError:
            pass
    results: List[NaabuResult] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            port = data.get("port")
            if isinstance(port, str) and port.isdigit():
                port = int(port)
            if not isinstance(port, int):
                continue
            results.append(
                NaabuResult(
                    host=data.get("host") or "",
                    ip=data.get("ip"),
                    port=port,
                    protocol=(data.get("protocol") or "tcp").lower(),
                )
            )
        except json.JSONDecodeError:
            parts = line.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                results.append(NaabuResult(host=parts[0], ip=None, port=int(parts[1]), protocol="tcp"))
    return results


def run_dnsx(hosts: Iterable[str]) -> List[DnsxResult]:
    binary = _resolve_binary("dnsx", "dnsx")
    if not binary:
        return []
    host_list = list({host.strip() for host in hosts if host and host.strip()})
    if not host_list:
        return []
    host_file = _write_list(host_list)
    args = [binary, "-silent", "-json", "-l", host_file, "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt"]
    args.extend(config.get_scanner_args("dnsx"))
    try:
        output = _run_command(args, config.get_scanner_timeout(), tool="dnsx")
    finally:
        try:
            os.unlink(host_file)
        except OSError:
            pass
    results: List[DnsxResult] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            host = data.get("host") or data.get("hostname") or data.get("input") or ""
            a_records = data.get("a") or data.get("A") or []
            aaaa_records = data.get("aaaa") or data.get("AAAA") or []
            cname_value = data.get("cname") or data.get("CNAME") or None
            mx_records = data.get("mx") or data.get("MX") or []
            ns_records = data.get("ns") or data.get("NS") or []
            txt_records = data.get("txt") or data.get("TXT") or []
            if isinstance(a_records, str):
                a_records = [a_records]
            if isinstance(aaaa_records, str):
                aaaa_records = [aaaa_records]
            if isinstance(mx_records, str):
                mx_records = [mx_records]
            if isinstance(ns_records, str):
                ns_records = [ns_records]
            if isinstance(txt_records, str):
                txt_records = [txt_records]
            if isinstance(cname_value, list):
                cname_value = cname_value[0] if cname_value else None
            results.append(
                DnsxResult(
                    host=str(host).strip(),
                    a=[str(item) for item in a_records if item],
                    aaaa=[str(item) for item in aaaa_records if item],
                    cname=str(cname_value).strip() if cname_value else None,
                    mx=[str(item) for item in mx_records if item],
                    ns=[str(item) for item in ns_records if item],
                    txt=[str(item) for item in txt_records if item],
                )
            )
        except json.JSONDecodeError:
            results.append(DnsxResult(host=line, a=[], aaaa=[], cname=None, mx=[], ns=[], txt=[]))
    return results


def run_nuclei(targets: Iterable[str], tags: Optional[List[str]] = None) -> List[ScanFinding]:
    binary = _resolve_binary("nuclei", "nuclei")
    if not binary:
        return []
    target_list = list({target.strip() for target in targets if target and target.strip()})
    if not target_list:
        return []
    target_file = _write_list(target_list)
    args = [binary, "-silent", "-json", "-l", target_file]
    if tags:
        args.extend(["-tags", ",".join(tags)])
    args.extend(config.get_scanner_args("nuclei"))
    try:
        output = _run_command(args, config.get_scanner_timeout(), tool="nuclei")
    finally:
        try:
            os.unlink(target_file)
        except OSError:
            pass
    findings: List[ScanFinding] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
            classification = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}
            cve_value = classification.get("cve-id")
            if isinstance(cve_value, list):
                cve_value = cve_value[0] if cve_value else None
            cvss_score = classification.get("cvss-score")
            if isinstance(cvss_score, str):
                try:
                    cvss_score = float(cvss_score)
                except ValueError:
                    cvss_score = None
            target = data.get("matched-at") or data.get("host") or ""
            port = None
            parsed = urlparse(target) if target else None
            if parsed and parsed.port:
                port = parsed.port
            findings.append(
                ScanFinding(
                    title=info.get("name") or data.get("template-id") or "Nuclei finding",
                    severity=info.get("severity", "info"),
                    description=info.get("description") or "",
                    evidence=data.get("template-id") or "",
                    tool="nuclei",
                    target=target,
                    port=port,
                    template_id=data.get("template-id"),
                    cvss=cvss_score,
                    cve=cve_value,
                )
            )
        except json.JSONDecodeError:
            findings.append(
                ScanFinding(
                    title="Nuclei finding",
                    severity="info",
                    description="Nuclei output detected.",
                    evidence=line,
                    tool="nuclei",
                    target="",
                )
            )
    return findings


def run_katana(targets: Iterable[str]) -> List[str]:
    binary = _resolve_binary("katana", "katana")
    if not binary:
        return []
    target_list = list({target.strip() for target in targets if target and target.strip()})
    if not target_list:
        return []
    target_file = _write_list(target_list)
    args = [binary, "-silent", "-json", "-list", target_file, "-depth", str(config.get_katana_depth())]
    args.extend(config.get_scanner_args("katana"))
    try:
        output = _run_command(args, config.get_scanner_timeout(), tool="katana")
    finally:
        try:
            os.unlink(target_file)
        except OSError:
            pass
    urls: List[str] = []
    seen = set()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        url = None
        try:
            data = json.loads(line)
            url = data.get("url") or data.get("input")
        except json.JSONDecodeError:
            url = line
        if not url:
            continue
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
        if len(urls) >= config.get_endpoint_limit():
            break
    return urls


def run_gau(domain: str) -> List[str]:
    binary = _resolve_binary("gau", "gau")
    if not binary:
        return []
    args = [binary, "--subs", domain]
    args.extend(config.get_scanner_args("gau"))
    output = _run_command(args, config.get_scanner_timeout(), tool="gau")
    urls: List[str] = []
    seen = set()
    for line in output.splitlines():
        url = line.strip()
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
        if len(urls) >= config.get_gau_limit():
            break
    return urls


def run_waybackurls(domain: str) -> List[str]:
    binary = _resolve_binary("waybackurls", "waybackurls")
    if not binary:
        return []
    args = [binary, domain]
    args.extend(config.get_scanner_args("waybackurls"))
    output = _run_command(args, config.get_scanner_timeout(), tool="waybackurls")
    urls: List[str] = []
    seen = set()
    for line in output.splitlines():
        url = line.strip()
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
        if len(urls) >= config.get_wayback_limit():
            break
    return urls


def run_ffuf(targets: Iterable[str]) -> List[str]:
    binary = _resolve_binary("ffuf", "ffuf")
    if not binary:
        return []
    target_list = list({target.strip() for target in targets if target and target.strip()})
    if not target_list:
        return []
    words = _load_ffuf_words()
    if not words:
        return []
    wordlist_path = _write_list(words)
    results: List[str] = []
    seen = set()
    limit = config.get_ffuf_limit()

    def _base_url(raw: str) -> Optional[str]:
        if raw.startswith("http://") or raw.startswith("https://"):
            parsed = urlparse(raw)
            if not parsed.scheme or not parsed.netloc:
                return None
            return f"{parsed.scheme}://{parsed.netloc}"
        if "." in raw:
            return f"https://{raw}"
        return None

    try:
        for target in target_list:
            base = _base_url(target)
            if not base:
                continue
            output_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json", dir=_scan_workdir())
            output_file.close()
            url = f"{base.rstrip('/')}/FUZZ"
            args = [
                binary,
                "-u",
                url,
                "-w",
                wordlist_path,
                "-of",
                "json",
                "-o",
                output_file.name,
                "-s",
                "-ac",
                "-mc",
                config.get_ffuf_match_codes(),
                "-rate",
                str(config.get_ffuf_rate()),
                "-timeout",
                str(config.get_ffuf_timeout()),
            ]
            args.extend(config.get_scanner_args("ffuf"))
            try:
                _run_command(args, config.get_scanner_timeout(), tool="ffuf")
                try:
                    with open(output_file.name, "r", encoding="utf-8") as handle:
                        data = json.load(handle)
                except (OSError, json.JSONDecodeError):
                    data = {}
                for entry in data.get("results", []) if isinstance(data, dict) else []:
                    url = entry.get("url") if isinstance(entry, dict) else None
                    if not url or url in seen:
                        continue
                    seen.add(url)
                    results.append(url)
                    if len(results) >= limit:
                        return results
            except Exception:
                continue
            finally:
                try:
                    os.unlink(output_file.name)
                except OSError:
                    pass
    finally:
        try:
            os.unlink(wordlist_path)
        except OSError:
            pass
    return results


def _extract_dirsearch_urls(data: object, base: str) -> List[str]:
    entries: List[object] = []
    if isinstance(data, dict):
        value = data.get("results") or data.get("paths") or data.get("entries") or data.get("data") or []
        if isinstance(value, list):
            entries = value
    elif isinstance(data, list):
        entries = data
    urls: List[str] = []
    for entry in entries:
        url: Optional[str] = None
        if isinstance(entry, str):
            url = entry
        elif isinstance(entry, dict):
            url = entry.get("url") or entry.get("link")
            if not url:
                path = entry.get("path") or entry.get("uri") or entry.get("endpoint")
                if isinstance(path, str) and path:
                    url = f"{base.rstrip('/')}/{path.lstrip('/')}"
        if not url:
            continue
        urls.append(url)
    return urls


def run_dirsearch(targets: Iterable[str]) -> List[str]:
    binary = _resolve_binary("dirsearch", "dirsearch")
    if not binary:
        return []
    target_list = list({target.strip() for target in targets if target and target.strip()})
    if not target_list:
        return []
    words = _load_dirsearch_words()
    if not words:
        return []
    wordlist_path = _write_list(words)
    results: List[str] = []
    seen = set()
    limit = config.get_dirsearch_limit()

    def _base_url(raw: str) -> Optional[str]:
        if raw.startswith("http://") or raw.startswith("https://"):
            parsed = urlparse(raw)
            if not parsed.scheme or not parsed.netloc:
                return None
            return f"{parsed.scheme}://{parsed.netloc}"
        if "." in raw:
            return f"https://{raw}"
        return None

    try:
        for target in target_list:
            base = _base_url(target)
            if not base:
                continue
            output_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json", dir=_scan_workdir())
            output_file.close()
            args = [
                binary,
                "-u",
                base,
                "-w",
                wordlist_path,
                "--format",
                "json",
                "-o",
                output_file.name,
                "-q",
            ]
            rate = config.get_dirsearch_rate()
            if rate > 0:
                args.extend(["--max-rate", str(rate)])
            timeout = config.get_dirsearch_timeout()
            if timeout > 0:
                args.extend(["--timeout", str(timeout)])
            args.extend(config.get_scanner_args("dirsearch"))
            try:
                _run_command(args, config.get_scanner_timeout(), tool="dirsearch")
                try:
                    with open(output_file.name, "r", encoding="utf-8") as handle:
                        data = json.load(handle)
                except (OSError, json.JSONDecodeError):
                    data = {}
                for url in _extract_dirsearch_urls(data, base):
                    if not url or url in seen:
                        continue
                    seen.add(url)
                    results.append(url)
                    if len(results) >= limit:
                        return results
            except Exception:
                continue
            finally:
                try:
                    os.unlink(output_file.name)
                except OSError:
                    pass
    finally:
        try:
            os.unlink(wordlist_path)
        except OSError:
            pass
    return results


def is_public_url(url: str) -> bool:
    try:
        request = Request(url, headers={"User-Agent": "asm-platform"}, method="HEAD")
    except TypeError:
        request = Request(url, headers={"User-Agent": "asm-platform"})
    try:
        with urlopen(request, timeout=config.get_scanner_timeout()) as response:
            status = response.status if hasattr(response, "status") else response.getcode()
            return status is not None and status < 400
    except Exception:
        return False


def _secret_patterns() -> List[tuple[str, str, str]]:
    patterns = [
        (r"AKIA[0-9A-Z]{16}", "high", "AWS access key"),
        (r"ASIA[0-9A-Z]{16}", "high", "AWS temporary key"),
        (r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]", "high", "AWS secret key"),
        (r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----", "high", "Private key material"),
        (r"(?i)(api_key|apikey|token|secret)[\"']?\s*[:=]\s*[\"'][0-9a-zA-Z-_]{16,}[\"']", "medium", "API token"),
    ]
    extra = config.get_secret_regex()
    if extra:
        for raw in extra.split(";"):
            pattern = raw.strip()
            if pattern:
                patterns.append((pattern, "medium", "Custom secret pattern"))
    return patterns


def _mask_secret(value: str) -> str:
    stripped = value.strip()
    if len(stripped) <= 8:
        return "***"
    return f"{stripped[:4]}***{stripped[-4:]}"


def run_endpoint_secret_scan(urls: Iterable[str]) -> List[ScanFinding]:
    url_list = [url for url in urls if url]
    if not url_list:
        return []
    limit = config.get_secret_scan_limit()
    max_bytes = config.get_secret_max_bytes()
    patterns = [(re.compile(pattern), severity, title) for pattern, severity, title in _secret_patterns()]
    findings: List[ScanFinding] = []
    for idx, url in enumerate(url_list):
        if idx >= limit:
            break
        try:
            request = Request(url, headers={"User-Agent": "asm-platform"})
            with urlopen(request, timeout=config.get_scanner_timeout()) as response:
                content_type = response.headers.get("Content-Type", "")
                raw = response.read(max_bytes)
        except Exception:
            continue
        if not raw:
            continue
        url_lower = url.lower()
        if not (
            "text" in content_type
            or "html" in content_type
            or "javascript" in content_type
            or "json" in content_type
            or url_lower.endswith((".js", ".json", ".html", ".htm"))
        ):
            continue
        text = raw.decode("utf-8", errors="ignore")
        for regex, severity, title in patterns:
            match = regex.search(text)
            if not match:
                continue
            snippet = match.group(0)
            evidence = _mask_secret(snippet)
            findings.append(
                ScanFinding(
                    title=f"{title} exposed",
                    severity=severity,
                    description="Potential secret detected in endpoint response.",
                    evidence=evidence,
                    tool="secret-scan",
                    target=url,
                )
            )
            if len(findings) >= limit:
                return findings
    return findings


def run_github_leaks() -> List[ScanFinding]:
    binary = _resolve_binary("trufflehog", "trufflehog")
    if not binary:
        return []
    org = config.get_github_org()
    repo = config.get_github_repo()
    token = config.get_github_token()
    if not org and not repo:
        return []
    args = [binary, "github", "--json"]
    if token:
        args.extend(["--token", token])
    if org:
        args.extend(["--org", org])
    if repo:
        args.extend(["--repo", repo])
    output = _run_command(args, config.get_scanner_timeout(), tool="trufflehog")
    findings: List[ScanFinding] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        detector = data.get("DetectorName") or "GitHub Secret"
        metadata = data.get("SourceMetadata", {}) or {}
        data_meta = metadata.get("Data", {}) if isinstance(metadata.get("Data"), dict) else {}
        repo_name = data_meta.get("Repo") or data_meta.get("RepoName") or ""
        target = repo_name
        findings.append(
            ScanFinding(
                title=f"GitHub leak: {detector}",
                severity="high",
                description="Potential secret leaked in GitHub repository.",
                evidence=repo_name or detector,
                tool="trufflehog",
                target=target,
            )
        )
    return findings


def run_public_repo_scan() -> List[ScanFinding]:
    binary = _resolve_binary("trufflehog", "trufflehog")
    if not binary:
        return []
    repo_url = config.get_public_repo_url()
    if not repo_url:
        return []
    args = [binary, "git", "--json", "--repo", repo_url]
    output = _run_command(args, config.get_scanner_timeout(), tool="trufflehog")
    findings: List[ScanFinding] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        detector = data.get("DetectorName") or "Secret"
        metadata = data.get("SourceMetadata", {}) or {}
        data_meta = metadata.get("Data", {}) if isinstance(metadata.get("Data"), dict) else {}
        repo_name = data_meta.get("Repo") or data_meta.get("RepoName") or repo_url
        findings.append(
            ScanFinding(
                title=f"Public repo leak: {detector}",
                severity="high",
                description="Potential secret leaked in public repository.",
                evidence=repo_name or detector,
                tool="trufflehog",
                target=repo_name,
            )
        )
    return findings


def run_github_code_search(domain: str) -> List[ScanFinding]:
    query = config.get_github_search_query() or f'"{domain}"'
    token = config.get_github_token()
    if not query:
        return []
    url = f"https://api.github.com/search/code?q={quote_plus(query)}&per_page=100"
    headers = {"User-Agent": "asm-platform", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        request = Request(url, headers=headers)
        with urlopen(request, timeout=config.get_scanner_timeout()) as response:
            raw = response.read().decode("utf-8")
    except Exception:
        return []
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return []
    items = data.get("items") or []
    findings: List[ScanFinding] = []
    limit = config.get_github_search_limit()
    for item in items[:limit]:
        repo = (item.get("repository") or {}).get("full_name") or ""
        path = item.get("path") or ""
        html_url = item.get("html_url") or ""
        findings.append(
            ScanFinding(
                title=f"GitHub code reference: {path or 'match'}",
                severity="medium",
                description="Potential asset exposure found via GitHub code search.",
                evidence=html_url or repo,
                tool="github-search",
                target=repo or html_url,
            )
        )
    return findings


def run_gitlab_code_search(domain: str) -> List[ScanFinding]:
    base = config.get_gitlab_base().rstrip("/")
    query = config.get_gitlab_search_query() or f'"{domain}"'
    if not query:
        return []
    url = f"{base}/api/v4/search?scope=blobs&search={quote_plus(query)}"
    headers = {"User-Agent": "asm-platform"}
    token = config.get_gitlab_token()
    if token:
        headers["PRIVATE-TOKEN"] = token
    try:
        request = Request(url, headers=headers)
        with urlopen(request, timeout=config.get_scanner_timeout()) as response:
            raw = response.read().decode("utf-8")
    except Exception:
        return []
    try:
        data = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    findings: List[ScanFinding] = []
    limit = config.get_gitlab_search_limit()
    for item in data[:limit]:
        filename = item.get("filename") or item.get("path") or "match"
        project = item.get("project_id") or ""
        findings.append(
            ScanFinding(
                title=f"GitLab code reference: {filename}",
                severity="medium",
                description="Potential asset exposure found via GitLab code search.",
                evidence=filename,
                tool="gitlab-search",
                target=str(project),
            )
        )
    return findings


def run_bitbucket_code_search(domain: str) -> List[ScanFinding]:
    template = config.get_bitbucket_command()
    if not template:
        return []
    query = config.get_bitbucket_search_query() or domain
    if not query:
        return []
    try:
        output = _run_template_command(template, query=query)
    except Exception:
        return []
    findings: List[ScanFinding] = []
    limit = config.get_bitbucket_search_limit()
    for line in output.splitlines():
        value = line.strip()
        if not value:
            continue
        findings.append(
            ScanFinding(
                title="Bitbucket code reference",
                severity="medium",
                description="Potential asset exposure found via Bitbucket search.",
                evidence=value,
                tool="bitbucket-search",
                target=value,
            )
        )
        if len(findings) >= limit:
            break
    return findings
