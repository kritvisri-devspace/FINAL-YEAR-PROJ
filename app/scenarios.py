"""Controlled security scenarios. `ground_truth` is for evaluation only and is NEVER sent to an agent."""

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0"


def _ev(ts, ip, user="", etype="", status="", url="", ua="", dns=""):
    e = {"timestamp": ts, "src_ip": ip, "username": user, "event_type": etype,
         "status": status, "url": url, "user_agent": ua, "dns_query": dns}
    return {k: v for k, v in e.items() if v != ""}


def _brute_force():
    ip = "203.0.113.45"
    ev = [_ev(f"2026-03-14T02:11:{10 + i * 4:02d}Z", ip, "admin", "ssh_login", "failed", ua="libssh2_1.9") for i in range(7)]
    ev.append(_ev("2026-03-14T02:11:44Z", ip, "admin", "ssh_login", "success", ua="libssh2_1.9"))
    ev.append(_ev("2026-03-14T02:12:03Z", ip, "admin", "sudo_exec", "success", url="/etc/shadow"))
    return ev


def _sqli():
    ip = "198.51.100.23"
    paths = ["/products?id=1", "/products?id=1'", "/products?id=1' OR '1'='1'--",
             "/products?id=1 UNION SELECT username,password FROM users--", "/admin/export?table=users"]
    return [_ev(f"2026-03-14T09:30:{i * 7:02d}Z", ip, "", "http_request", str(200 if i in (0, 4) else 500),
                url=p, ua="sqlmap/1.7.2#stable") for i, p in enumerate(paths)]


def _benign():
    return [
        _ev("2026-03-14T08:58:02Z", "10.0.4.17", "priya.s", "vpn_login", "success", ua=UA),
        _ev("2026-03-14T08:59:20Z", "10.0.4.17", "priya.s", "http_request", "200", url="/intranet/home", ua=UA),
        _ev("2026-03-14T09:03:41Z", "10.0.4.17", "priya.s", "http_request", "200", url="/intranet/timesheet", ua=UA),
        _ev("2026-03-14T09:12:09Z", "10.0.4.22", "rahul.m", "ssh_login", "failed", ua="OpenSSH_8.9"),
        _ev("2026-03-14T09:12:31Z", "10.0.4.22", "rahul.m", "ssh_login", "success", ua="OpenSSH_8.9"),
        _ev("2026-03-14T09:20:00Z", "10.0.4.17", "priya.s", "dns_query", "ok", ua=UA, dns="docs.google.com"),
    ]


def _port_scan():
    ip = "192.0.2.77"
    ports = [21, 22, 23, 25, 80, 110, 443, 445, 3306, 3389]
    return [_ev(f"2026-03-14T11:05:{i:02d}Z", ip, "", "port_probe", "blocked" if p not in (22, 80, 443) else "open",
                url=f"tcp://10.0.0.5:{p}", ua="nmap-syn") for i, p in enumerate(ports)]


def _phishing():
    ip = "10.0.4.31"
    return [
        _ev("2026-03-14T14:20:11Z", ip, "anita.k", "email_click", "ok", url="http://paypa1-secure-login.xyz/verify?u=anita", ua=UA),
        _ev("2026-03-14T14:20:12Z", ip, "anita.k", "dns_query", "ok", ua=UA, dns="paypa1-secure-login.xyz"),
        _ev("2026-03-14T14:20:15Z", ip, "anita.k", "http_request", "200", url="http://paypa1-secure-login.xyz/login", ua=UA),
        _ev("2026-03-14T14:20:48Z", ip, "anita.k", "http_post", "200", url="http://paypa1-secure-login.xyz/submit", ua=UA),
        _ev("2026-03-14T14:31:02Z", "45.33.12.9", "anita.k", "vpn_login", "success", ua="python-requests/2.31"),
    ]


SCENARIOS = {
    "brute_force": {"name": "SSH brute force then success", "build": _brute_force,
                    "ground_truth": {"threat_class": "brute_force", "severity": "high"}},
    "sql_injection": {"name": "SQL injection against /products", "build": _sqli,
                      "ground_truth": {"threat_class": "sql_injection", "severity": "high"}},
    "benign": {"name": "Normal office activity", "build": _benign,
               "ground_truth": {"threat_class": "benign", "severity": "none"}},
    "port_scan": {"name": "Port scan from external host", "build": _port_scan,
                  "ground_truth": {"threat_class": "port_scan", "severity": "medium"}},
    "phishing": {"name": "Phishing click then credential reuse", "build": _phishing,
                 "ground_truth": {"threat_class": "phishing", "severity": "high"}},
}


def load(scenario_id: str) -> tuple[list[dict], dict]:
    s = SCENARIOS[scenario_id]
    logs = s["build"]()
    for i, e in enumerate(logs, 1):
        e["id"] = f"e{i}"
    return logs, s["ground_truth"]
