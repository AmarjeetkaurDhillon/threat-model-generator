from flask import Flask, render_template, request
from datetime import datetime

app = Flask(__name__)

STRIDE_THREATS = {
    "web_app": [
        {
            "category": "Spoofing",
            "threat": "Attacker impersonates legitimate user via stolen session token",
            "mitre": "T1539 — Steal Web Session Cookie",
            "risk": "HIGH",
            "control": "Implement MFA, short session timeouts, and secure cookie flags (HttpOnly, Secure, SameSite)"
        },
        {
            "category": "Tampering",
            "threat": "Attacker modifies HTTP request parameters to manipulate business logic",
            "mitre": "T1190 — Exploit Public-Facing Application",
            "risk": "HIGH",
            "control": "Server-side input validation, parameterised queries, integrity checks on all inputs"
        },
        {
            "category": "Repudiation",
            "threat": "User denies performing malicious actions due to insufficient logging",
            "mitre": "T1562.002 — Disable Windows Event Logging",
            "risk": "MEDIUM",
            "control": "Implement tamper-proof audit logging with timestamps and user identifiers"
        },
        {
            "category": "Information Disclosure",
            "threat": "Sensitive data exposed via verbose error messages or insecure transmission",
            "mitre": "T1040 — Network Sniffing",
            "risk": "HIGH",
            "control": "Enforce TLS 1.3, suppress verbose errors in production, encrypt sensitive fields at rest"
        },
        {
            "category": "Denial of Service",
            "threat": "Attacker floods application with requests causing service disruption",
            "mitre": "T1498 — Network Denial of Service",
            "risk": "MEDIUM",
            "control": "Implement rate limiting, WAF rules, auto-scaling, and DDoS protection"
        },
        {
            "category": "Elevation of Privilege",
            "threat": "Attacker exploits broken access control to gain admin privileges",
            "mitre": "T1548 — Abuse Elevation Control Mechanism",
            "risk": "CRITICAL",
            "control": "Enforce least privilege, implement RBAC, validate authorisation on every request server-side"
        }
    ],
    "api": [
        {
            "category": "Spoofing",
            "threat": "Attacker uses forged or stolen API keys to authenticate as legitimate service",
            "mitre": "T1528 — Steal Application Access Token",
            "risk": "HIGH",
            "control": "Use short-lived JWT tokens with rotation, implement API key scoping and rate limiting"
        },
        {
            "category": "Tampering",
            "threat": "Man-in-the-middle attack modifies API request or response payload",
            "mitre": "T1557 — Adversary-in-the-Middle",
            "risk": "HIGH",
            "control": "Enforce mutual TLS (mTLS), implement request signing, validate payload integrity with HMAC"
        },
        {
            "category": "Information Disclosure",
            "threat": "API returns excessive data exposing sensitive fields not needed by client",
            "mitre": "T1530 — Data from Cloud Storage",
            "risk": "MEDIUM",
            "control": "Implement response filtering, use allowlists for returned fields, audit API responses regularly"
        },
        {
            "category": "Denial of Service",
            "threat": "Attacker sends malformed or oversized payloads to crash API service",
            "mitre": "T1499 — Endpoint Denial of Service",
            "risk": "MEDIUM",
            "control": "Enforce payload size limits, implement circuit breakers, validate all input schemas"
        },
        {
            "category": "Elevation of Privilege",
            "threat": "Broken object level authorisation allows access to other users resources",
            "mitre": "T1548 — Abuse Elevation Control Mechanism",
            "risk": "CRITICAL",
            "control": "Validate object ownership on every API call, implement BOLA/IDOR protection"
        }
    ],
    "database": [
        {
            "category": "Tampering",
            "threat": "SQL injection allows attacker to modify or delete database records",
            "mitre": "T1190 — Exploit Public-Facing Application",
            "risk": "CRITICAL",
            "control": "Use parameterised queries exclusively, implement stored procedures, apply least privilege to DB accounts"
        },
        {
            "category": "Information Disclosure",
            "threat": "Unencrypted database exposes sensitive records if storage is compromised",
            "mitre": "T1530 — Data from Cloud Storage",
            "risk": "CRITICAL",
            "control": "Enable encryption at rest (AES-256), encrypt sensitive columns, implement TDE"
        },
        {
            "category": "Denial of Service",
            "threat": "Attacker executes expensive queries to exhaust database resources",
            "mitre": "T1499 — Endpoint Denial of Service",
            "risk": "MEDIUM",
            "control": "Implement query timeouts, connection pooling limits, and read replicas for load distribution"
        },
        {
            "category": "Elevation of Privilege",
            "threat": "Application uses overprivileged DB account allowing schema modification",
            "mitre": "T1078 — Valid Accounts",
            "risk": "HIGH",
            "control": "Create separate DB accounts per service with minimum required permissions, never use root DB account"
        }
    ],
    "auth": [
        {
            "category": "Spoofing",
            "threat": "Brute force or credential stuffing attack compromises user accounts",
            "mitre": "T1110 — Brute Force",
            "risk": "HIGH",
            "control": "Implement account lockout, MFA, CAPTCHA, and monitor for credential stuffing patterns"
        },
        {
            "category": "Information Disclosure",
            "threat": "Authentication system reveals whether username exists via different error messages",
            "mitre": "T1589 — Gather Victim Identity Information",
            "risk": "LOW",
            "control": "Return identical error messages for invalid username and invalid password"
        },
        {
            "category": "Elevation of Privilege",
            "threat": "Weak password reset flow allows account takeover without knowing current password",
            "mitre": "T1078 — Valid Accounts",
            "risk": "CRITICAL",
            "control": "Implement secure password reset with time-limited tokens, verify identity through secondary factor"
        }
    ]
}

RISK_SCORES = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def generate_threat_model(system_name, components, data_sensitivity):
    all_threats = []
    for component in components:
        if component in STRIDE_THREATS:
            for threat in STRIDE_THREATS[component]:
                t = threat.copy()
                t["component"] = component.replace("_", " ").title()
                if data_sensitivity == "high" and t["risk"] == "MEDIUM":
                    t["risk"] = "HIGH"
                all_threats.append(t)

    all_threats.sort(key=lambda x: RISK_SCORES.get(x["risk"], 0), reverse=True)

    summary = {
        "CRITICAL": len([t for t in all_threats if t["risk"] == "CRITICAL"]),
        "HIGH": len([t for t in all_threats if t["risk"] == "HIGH"]),
        "MEDIUM": len([t for t in all_threats if t["risk"] == "MEDIUM"]),
        "LOW": len([t for t in all_threats if t["risk"] == "LOW"]),
    }

    return all_threats, summary


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/generate", methods=["POST"])
def generate():
    system_name = request.form.get("system_name", "Unnamed System")
    components = request.form.getlist("components")
    data_sensitivity = request.form.get("data_sensitivity", "medium")

    if not components:
        return render_template("index.html", error="Please select at least one component.")

    threats, summary = generate_threat_model(system_name, components, data_sensitivity)

    return render_template(
        "report.html",
        system_name=system_name,
        components=components,
        data_sensitivity=data_sensitivity,
        threats=threats,
        summary=summary,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


if __name__ == "__main__":
    app.run(debug=True)