# 🛡️ Case Study: API Broken Access Control & PII Remediation
**Target System:** Government Complaint Support System (CSS)  
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

Disclaimer: This research was conducted for educational and security improvement purposes only. All testing was performed responsibly following coordinated disclosure protocols.
