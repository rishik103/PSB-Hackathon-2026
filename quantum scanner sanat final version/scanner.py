import ssl
import socket
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa


COMMON_TLS_PORTS = [443, 8443, 9443]
VPN_PORTS = [1194, 443]

COMMON_SUBDOMAINS = [
    "api",
    "dev",
    "test",
    "portal",
    "login",
    "gateway"
]


# ----------------------------
# Normalize target
# ----------------------------

def normalize_target(target):

    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)

    hostname = parsed.hostname
    port = parsed.port if parsed.port else 443

    return hostname, port


# ----------------------------
# Detect cipher strength
# ----------------------------

def detect_cipher_strength(cipher):

    cipher = cipher.upper()

    if "CHACHA20" in cipher or "GCM" in cipher:
        return "strong"

    if "CBC" in cipher:
        return "medium"

    if any(w in cipher for w in ["RC4", "DES", "3DES"]):
        return "weak"

    return "unknown"


# ----------------------------
# Detect Forward Secrecy
# ----------------------------

def detect_forward_secrecy(cipher):

    if any(k in cipher for k in ["ECDHE", "DHE"]):
        return True

    return False


# ----------------------------
# CIDR Range Expansion
# ----------------------------

def expand_cidr(target):

    hosts = []

    try:
        network = ipaddress.ip_network(target, strict=False)

        for ip in network.hosts():
            hosts.append(str(ip))

    except:
        hosts.append(target)

    return hosts


# ----------------------------
# Port scanning
# ----------------------------

def scan_ports(host):

    open_ports = []

    for port in COMMON_TLS_PORTS + VPN_PORTS:

        try:
            with socket.create_connection((host, port), timeout=2):
                open_ports.append(port)

        except:
            pass

    return open_ports


# ----------------------------
# Subdomain discovery
# ----------------------------

def discover_subdomains(domain):

    found = []

    for sub in COMMON_SUBDOMAINS:

        candidate = f"{sub}.{domain}"

        try:
            socket.gethostbyname(candidate)
            found.append(candidate)

        except:
            pass

    return found


# ----------------------------
# API Detection
# ----------------------------

def detect_api(endpoint):

    patterns = ["/api", "/v1", "/v2", "/graphql"]

    for p in patterns:
        if p in endpoint.lower():
            return True

    return False


# ----------------------------
# TLS vulnerability heuristics
# ----------------------------

def detect_vulnerabilities(protocol, cipher):

    vulns = []

    if protocol in ["SSLv3"]:
        vulns.append("POODLE")

    if "RC4" in cipher:
        vulns.append("RC4 Bias Vulnerability")

    if protocol == "TLSv1":
        vulns.append("Possible BEAST vulnerability")

    return vulns


# ----------------------------
# Detect VPN services
# ----------------------------

def detect_vpn_ports(open_ports):

    for p in open_ports:
        if p in VPN_PORTS:
            return True

    return False


# ----------------------------
# Scan TLS endpoint
# ----------------------------

def scan_single_target(target):

    hostname, port = normalize_target(target)

    result = {
        "endpoint": target,
        "status": "Failed",
        "protocol": None,
        "cipher": None,
        "certificate": {},
        "error": None
    }

    try:

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=6) as sock:

            with context.wrap_socket(sock, server_hostname=hostname) as ssock:

                cipher_tuple = ssock.cipher()

                if cipher_tuple:
                    result["cipher"] = cipher_tuple[0]
                    result["protocol"] = cipher_tuple[1]

                der_cert = ssock.getpeercert(binary_form=True)

                cert = x509.load_der_x509_certificate(
                    der_cert,
                    default_backend()
                )

                public_key = cert.public_key()

                key_algo = "Unknown"
                key_size = getattr(public_key, "key_size", 0)

                if isinstance(public_key, rsa.RSAPublicKey):
                    key_algo = "RSA"

                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    key_algo = "ECC"

                elif isinstance(public_key, dsa.DSAPublicKey):
                    key_algo = "DSA"

                result["certificate"] = {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "valid_from": cert.not_valid_before_utc.isoformat(),
                    "valid_until": cert.not_valid_after_utc.isoformat(),
                    "key_algorithm": key_algo,
                    "key_size": key_size
                }

                result["status"] = "Success"

    except Exception as e:
        result["error"] = str(e)

    return result


# ----------------------------
# Analyze security
# ----------------------------

def analyze_result(scan):

    if scan["status"] != "Success":
        return {"endpoint": scan["endpoint"], "error": scan["error"]}

    cipher = scan["cipher"]
    protocol = scan["protocol"]
    cert = scan["certificate"]

    key_algo = cert["key_algorithm"]
    key_size = cert["key_size"]

    cipher_strength = detect_cipher_strength(cipher)
    forward_secrecy = detect_forward_secrecy(cipher)

    expiry = datetime.fromisoformat(cert["valid_until"])
    now = datetime.now(timezone.utc)

    days_left = (expiry - now).days

    vulnerabilities = detect_vulnerabilities(protocol, cipher)

    score = 50
    recommendations = []

    if protocol == "TLSv1.3":
        score += 15
    elif protocol == "TLSv1.2":
        score += 8
    else:
        score -= 20
        recommendations.append("Upgrade TLS version")

    if cipher_strength == "strong":
        score += 15
    elif cipher_strength == "medium":
        score += 5
    else:
        score -= 20
        recommendations.append("Weak cipher")

    if forward_secrecy:
        score += 10
    else:
        score -= 10
        recommendations.append("Enable Forward Secrecy")

    if key_algo == "ECC":
        score += 10

    elif key_algo == "RSA":

        if key_size >= 4096:
            score += 8
        elif key_size >= 3072:
            score += 6
        elif key_size >= 2048:
            score += 3
        else:
            score -= 15
            recommendations.append("Weak RSA key")

    if days_left < 30:
        score -= 10
        recommendations.append("Certificate expiring soon")

    pqc_ready = False

    if any(pqc in cipher.upper() for pqc in ["KYBER", "ML-KEM", "DILITHIUM"]):
        pqc_ready = True
        score += 10

    score = max(0, min(score, 100))

    if score >= 85:
        tier = "Elite"
    elif score >= 65:
        tier = "Standard"
    elif score >= 40:
        tier = "Legacy"
    else:
        tier = "Critical"

    if pqc_ready and protocol == "TLSv1.3":
        pqc_label = "Fully Quantum Safe"
    elif pqc_ready:
        pqc_label = "PQC Ready"
    else:
        pqc_label = "Not PQC Ready"

    return {
        "endpoint": scan["endpoint"],
        "score": score,
        "tier": tier,
        "protocol": protocol,
        "cipher": cipher,
        "key_algorithm": key_algo,
        "key_size": key_size,
        "pqc_label": pqc_label,
        "vulnerabilities": ",".join(vulnerabilities),
        "recommendations": ",".join(recommendations)
    }


# ----------------------------
# Enterprise PQC score
# ----------------------------

def enterprise_score(results):

    scores = [r["score"] for r in results if "score" in r]

    if not scores:
        return 0

    return int(sum(scores) / len(scores) * 10)


# ----------------------------
# Bulk scan
# ----------------------------

def bulk_scan(targets):

    results = []

    expanded = []

    for t in targets:

        expanded.extend(expand_cidr(t))

        try:
            expanded.extend(discover_subdomains(t))
        except:
            pass

    expanded = list(set(expanded))

    for target in expanded:

        raw = scan_single_target(target)

        analyzed = analyze_result(raw)

        results.append(analyzed)

    return results