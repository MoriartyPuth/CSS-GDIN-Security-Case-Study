# 🛡️ Case Study: API Broken Access Control & PII Remediation
**Target System:** [Government Complaint Support System (CSS)](https://css-gdin.interior.gov.kh/home)

**Status:** ✅ COMPLETED, FIXED, & VERIFIED  

**Vulnerability:** Insecure Direct Object Reference (IDOR) / Broken Access Control (BAC)  

**Severity:** 🔴 Critical (9.1/10)

![Security Status](https://img.shields.io/badge/Security-Verified_Patch-success?style=for-the-badge&logo=github)
![Vulnerability](https://img.shields.io/badge/Vulnerability-IDOR-red?style=for-the-badge)

---

## 📋 Executive Summary
This repository documents the discovery, reporting, and successful remediation of a critical security flaw in a live government-tier API. The vulnerability allowed for unauthenticated bulk extraction of **Personally Identifiable Information (PII)** of citizens filing legal and administrative complaints. 

Through coordinated disclosure and professional collaboration with IT stakeholders, the vulnerability was patched and verified within 24 hours of discovery.

---

## 🔬 Research Methodology
The assessment followed a structured "Proactive Threat Hunting" approach:

- Automated Reconnaissance: Deployed custom tooling to map the attack surface and discover hidden endpoints within the Spring Boot API architecture.

- Traffic Analysis: Analyzed the discrepancy between the authenticated administrative UI and the unauthenticated backend API routes.

- Vulnerability Exploitation: Confirmed an Insecure Direct Object Reference (IDOR) vulnerability on the /api/v1/complaints collection, allowing bulk data extraction via HTTP GET.

- Coordinated Disclosure: Provided a technical Root Cause Analysis (RCA) to the IT stakeholders, identifying the lack of method-level security.

- Post-Remediation Verification: Conducted regression testing to ensure the patch successfully restricted access without disrupting public submission functionality.

## 🛠️ Custom Tooling:
A core component of this research was the development and deployment of [Bubble-Scanner](https://github.com/MoriartyPuth/bubble-scanner), a proprietary shell-based security scanner designed for high-speed reconnaissance and vulnerability discovery.

Key Technical Features:
- Bubble-Dive Engine: A recursive fuzzing engine that identifies active endpoints and immediately triggers sub-scanners upon receiving 200 OK status codes.

- Source Code Scavenging: Uses regex patterns to scan HTML and JavaScript for leaked secrets, including API keys, tokens, and hardcoded credentials.

- RCE Vector Identification: Proactively hunts for file upload forms and input fields to identify potential Remote Code Execution (RCE) entry points.

- SQLi Probing: Automates basic error-based SQL injection testing on all discovered parameters.

- Automated Looting: Generates structured, timestamped reports and isolated files for sensitive data found during the "dive."

### Technical Logic Snippet:

```
bubble_dive() {
    head -n 1000 "$WORDLIST" | while read -r path; do
        url="${base_url%/}/${path}"
        res=$(curl -s -o /dev/null -w "%{http_code}" "$url")

        if [ "$res" == "200" ]; then
            # Trigger deep-scan subroutines
            scan_source_code "$url"
            check_upload_vuln "$url"
        fi
    done
}
```

## 🔍 Technical Vulnerability Analysis

### 1. Root Cause Analysis (RCA)
The system utilized a "Default Allow" posture on the `/api/v1/complaints` collection endpoint. While administrative dashboard paths were correctly guarded, the application failed to distinguish between **Submission (POST)** and **Extraction (GET)** permissions at the API layer.

* **Logic Flaw:** The application permitted `ROLE_ANONYMOUS` to access the endpoint to facilitate public submissions but failed to restrict the `HTTP GET` method.
* **CWE-284:** Improper Access Control.
* **CWE-200:** Exposure of Sensitive Information to an Unauthorized Actor.

### 2. Risk Rating (CVSS v3.1)
**Score: 9.1 (Critical)** **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

---

## 🕵️ Discovery & Proof of Concept (PoC)
*Note: Sensitive domains and identifiers have been redacted.*

### Initial Discovery
An unauthenticated `GET` request to the complaints endpoint returned a full JSON database dump instead of the expected `403 Forbidden`:
```bash
# Probing the collection endpoint
curl -i -k 'https://[TARGET_REDACTED]/api/v1/complaints'
```

### Data Exposure Sample
The response contained structured data for over 1,000 entries:
```
[
  {
    "id": 7,
    "plaintiffName": "ហុង [REDACTED]",
    "phoneNumber": "086******",
    "description": "Sensitive allegation description...",
    "status": "PENDING"
  }
]
```

## 🛠️ Remediation Process
I provided the technical stakeholders with a root-cause analysis. The vulnerability was caused by a missing method-level restriction in the Spring Security configuration. 

**The recommended (and implemented) fix involved:**
1. Restricting `HTTP GET` to `ROLE_ADMIN`.
2. Maintaining `HTTP POST` as `permitAll()` to allow citizen submissions.

## 🧪 Post-Patch Verification (Final Results)
Verification was completed on Feb 19, 2026. All attack vectors previously used to extract data were confirmed to be successfully blocked by the server with an `HTTP 403 Forbidden` response.

## 🎖️ Final Project Status
> **Security Audit:** Complete  
> **Data Integrity:** Secured  
> **PII Exposure:** Eliminated

Disclaimer: This research was conducted for educational and security-hardening purposes. All activities complied with responsible disclosure standards.
