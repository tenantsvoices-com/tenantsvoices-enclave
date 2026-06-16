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

---

## Secrets & configuration

The enclave guards two secrets:

| Secret         | Env var        | Purpose                                            |
|----------------|----------------|----------------------------------------------------|
| JWE key        | `JWE_KEY`      | AES-256 key (exactly 32 bytes) encrypting session tokens |
| Email pepper   | `EMAIL_PEPPER` | Mixed into the deterministic `email_key` so a leaked accounts table can't be enumerated by guessing emails |

Behavior is selected by `ENV`:

- **`ENV=dev` (or unset)** — local dev mode. Fixed, well-known dev values are used for both secrets. **Never use this in production.**
- **`ENV` = anything else** — production mode. Both `JWE_KEY` and `EMAIL_PEPPER` are **required**; the process **refuses to start** (exits non-zero) if either is missing or `JWE_KEY` is not 32 bytes. There is no hardcoded fallback, so a misconfigured deploy fails loudly instead of silently using a publicly known key.

### Production (Nitro Enclave) key path

For the MVP there is no real enclave, so production mode reads both secrets from the environment. The intended production deployment replaces the env reads in `fetchJWEKeyProd` / `fetchEmailPepperProd` with a **KMS Decrypt call (or a read from sealed enclave memory) gated on a successful attestation document**, so each secret is released only to a verified enclave image and never transits an env var, disk, or the host. The required-and-fail-closed contract stays the same — only the source of the bytes changes.

---

## Flow diagrams

> Rendered with [Mermaid](https://mermaid.js.org/), which GitHub displays inline.

### Secret confinement

`JWE_KEY` and `EMAIL_PEPPER` never leave the enclave. The API holds no secrets — it
asks the enclave to use them over HTTP and only ever handles the opaque results
(an encrypted token, or a derived hash).

```mermaid
flowchart LR
    Client["Web client<br/>(holds opaque token only)"]
    API["API (Gin)<br/>holds: no secrets"]

    subgraph Enclave["Enclave — trust boundary (Nitro/TEE in prod)"]
        Secrets["JWE_KEY · EMAIL_PEPPER<br/>(never cross this line)"]
    end

    Client -->|"Bearer token"| API
    API -->|"POST /token, /verify, /email-key,<br/>/hash-password, /verify-password"| Enclave
    Enclave -->|"token · reviewer_hash · email_key · ok"| API
    API -->|"results only"| Client
```

### Minting a token (`POST /token`)

The enclave derives the salted `reviewer_hash = H("rev", email, password, salt)`
and seals it (plus an expiry) inside an AES-256-GCM JWE. The `reviewer_hash` is
returned to the API so it can be stored on review rows; the `token` is what the
client receives.

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    participant E as Enclave (JWE_KEY)

    C->>A: login (email, password)
    A->>E: POST /token {email, password, salt}
    Note over E: rh = H("rev", email, password, salt)
    Note over E: token = JWE_enc(JWE_KEY, {rh, exp})
    E-->>A: {reviewer_hash, token}
    A-->>C: token (opaque blob)
    Note over C: cannot read rh or exp
```

### Verifying a token (`POST /verify`)

Every authenticated request, the API hands the opaque token back to the enclave,
which decrypts it with `JWE_KEY`, checks expiry, and returns the `reviewer_hash`.
That hash — derived server-side, never sent by the client — is what scopes
ownership in the database (`WHERE hashed_user_id = reviewer_hash`).

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    participant E as Enclave (JWE_KEY)
    participant DB as Postgres

    C->>A: request + Authorization: Bearer <token>
    A->>E: POST /verify {token}
    alt valid & unexpired
        Note over E: rh = JWE_dec(JWE_KEY, token)
        E-->>A: {reviewer_hash}
        A->>DB: query WHERE hashed_user_id = rh
        DB-->>A: rows owned by this user
        A-->>C: 200 + data
    else tampered / expired
        E-->>A: 401
        A-->>C: 401 (client must re-login)
    end
```

### Deriving the email key (`POST /email-key`)

`email_key` is the deterministic account-lookup key. The pepper is HMAC'd in
*inside* the enclave so a leaked `accounts` table can't be enumerated by guessing
emails — the attacker would also need `EMAIL_PEPPER`.

```mermaid
flowchart LR
    Email["email"] --> N["normalize<br/>(lowercase, trim)"]
    N --> H["HMAC-SHA256<br/>key = EMAIL_PEPPER"]
    H --> A["argon2id<br/>(fixed salt → deterministic)"]
    A --> K["email_key<br/>(account lookup key)"]
```
