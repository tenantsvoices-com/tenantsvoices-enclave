# TenantVoices Enclave

**Trusted Execution Environment (TEE) / Enclave for TenantVoices**

This repository contains the **enclave logic** for TenantVoices’ encrypted review ingestion system.  
It is intended for transparency.
---

## Overview

The enclave’s current responsibility is **anonymizing reviewer identity**:

1. Take the reviewer’s email (or other identifier).  
2. Compute a deterministic, non-reversible hash using HMAC-SHA256 with a secret PEPPER.  
3. Return the `reviewer_hash` to the backend to be stored alongside the review.  

> The `reviewer_hash` allows linking multiple reviews from the same user **without storing any real email or PII**.  
> The displayed reviewer name is a pseudonym; no real names are stored or displayed.

> In production, the enclave runs inside a secure environment such as **AWS Nitro Enclaves**, **Cloud HSM**, or **Vault**, and **never exposes private keys or secrets in the filesystem**.

---

## Features (Public-Friendly)

- HMAC-SHA256 hashing of reviewer emails (with secret PEPPER)  
- Deterministic, non-reversible `reviewer_hash`  
- Public-friendly test client to simulate encrypted email submission  
