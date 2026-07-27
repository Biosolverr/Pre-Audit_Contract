# SecurityAuditor

GenLayer Intelligent Contract for automated auditing of Solidity and Python smart contracts.

## Architecture

The project consists of two main components:

### Intelligent Contract

The GenLayer Intelligent Contract performs repository audits, stores audit results on-chain, maintains audit history, and aggregates statistics.

Analysis is performed via LLM within GenLayer's nondeterministic execution model. The final result is determined by validator consensus, which must agree on the exact pinned commit (`commit_sha`), file path (`file_path`), language, risk level, and score bucket.

Main responsibilities:

- Normalize GitHub repository URLs (removes trailing slash, `.git`).
- Retrieve repository metadata via the GitHub API.
- **Select a single file** (`.sol` or `.py`) from the repository using a heuristic and analyze its contents via LLM.
- Store the latest audit result.
- Maintain a full audit history (up to 20 entries per repository).
- Aggregate global statistics across all audits.
- Apply spam protection for repeated submissions.

### Frontend

A lightweight application built with HTML, CSS, and JavaScript.

Allows users to:

- Connect a wallet.
- Submit GitHub repositories for auditing.
- View audit reports.
- Browse previous audit history.
- Display repository risk statistics.

The frontend communicates directly with the deployed Intelligent Contract.

---

## Current Deployment

Deployed Intelligent Contract:

`0x78297e3128e3d4B997C08eC3a0277055Ea088eE4`

The frontend is currently configured to interact with this deployment.

---

## Public Contract Methods

### `audit_contract(repo_url: str)`

Starts a new repository audit.

The contract:

- normalizes the repository URL,
- resolves the link to an exact `commit_sha` and file path,
- **selects one file** (`.sol` or `.py`) from the repository tree using a heuristic (prefers a file matching the repo name, then the shallowest path, then the largest size),
- sends the **first 5000 characters** of the code to the LLM for analysis,
- stores the resulting report,
- updates statistics (on re-audit, the old contribution is backed out first),
- appends the audit to the history.

**Anti-spam:** re-auditing **your own** previous submission is allowed immediately. Re-auditing **someone else's** fresh submission requires at least 2 other audits of any repository to have occurred since the last audit of this repo.

---

### `get_audit(repo_url: str) -> str`

Returns the latest stored audit for a repository as a JSON string. Returns an empty string if no audit exists.

---

### `get_audit_trend(repo_url: str) -> str`

Returns the audit history for the specified repository as a JSON array. Each entry contains `seq`, `score`, and `overall_risk`. History is capped at the last 20 entries.

---

### `get_audit_stats() -> str`

Returns aggregated statistics across all audits:

- `total_audits` — total number of audits,
- `unique_repos` — number of unique repositories,
- `risk_counts` — distribution by risk level (Critical, High, Medium, Low, Info),
- `top_categories` — top 8 vulnerability categories by frequency.

---

### `get_audit_count() -> str`

Returns the total number of successful `audit_contract` calls as a string.

---

### `get_recent_audits() -> str`

Returns a JSON array of the last 10 audit URLs in reverse chronological order.

---

### `get_all_audits(limit: int = 50) -> str`

Returns a deduplicated list of recent audits (a repository re-audited multiple times appears only once, at its most recent position). The result is limited to `limit` entries (default 50; maximum scan depth is capped to prevent unbounded loops).

---

### `set_github_token(token: str)`

Owner-only method. Updates the GitHub Personal Access Token used for GitHub API requests.

---

## Statistics

The contract maintains aggregated statistics across all processed repositories.

Currently tracked information:

- number of unique repositories,
- total number of audits,
- Critical findings,
- High findings,
- Medium findings,
- Low findings,
- Informational findings,
- issue category counts.

Statistics are updated whenever a new audit is successfully completed. On re-audit, the old contribution is backed out first to avoid double-counting.

---

## Audit History

Each repository maintains an audit history.

The contract stores:

- the latest audit result,
- previous audit entries (up to 20),
- audit ordering information.

This allows users to review earlier reports while keeping quick access to the latest audit.

---

## Anti-Spam Protection

The contract includes spam protection for repeated submissions:

- **Self re-audit** — if the same address submits an audit for a repository it previously audited, there are no restrictions (needed for iterative testing).
- **Cross-sender re-audit** — if a different address attempts to immediately re-audit someone else's fresh submission, the call is blocked until at least 2 other audits of any repository have occurred.

---

## GitHub Token

Repository metadata is retrieved through the GitHub API.

The GitHub Personal Access Token can be updated only by the contract owner through the `set_github_token()` method.

The token is intended to increase GitHub API reliability and rate limits. It should not be considered confidential once used by a decentralized contract — contract state is readable by anyone.

---

## LLM Audit Limitations

Repository analysis is generated by an LLM.

The audit should be considered an automated assessment rather than a formal security audit.

Results may:

- miss vulnerabilities,
- produce false positives,
- depend on repository contents available during analysis,
- change as LLM models evolve.

The generated report is intended to assist repository review rather than replace manual security analysis.

---

## Supported Languages and Files

The contract analyzes only files with extensions **`.sol`** (Solidity) and **`.py`** (Python/GenLayer).

When auditing a bare repo URL, the contract:

1. Excludes files containing `test` in the path, `node_modules`, `/lib/`.
2. Selects one file using a heuristic.
3. Analyzes **only the first 5000 characters** of the selected file (the rest is truncated).

To audit a specific file or the entire repository, use a direct link: `github.com/.../blob/<ref>/<path>` or `raw.githubusercontent.com/...`.

---

## Repository Size Limitations

If the repository tree is too large to fully list via the GitHub API (`truncated: true`), the `audit_contract()` call **will revert with an error**. In this case, use a direct file URL (`github.com/.../blob/<ref>/<path>`).

---

## Revision Pinning

All audits are bound to a specific commit (`commit_sha`). Even if new commits are added to the repository later, the saved report remains immutable and contains the fields `pinned_commit` and `pinned_file`.

---

## Closed Vulnerability Category List

The contract uses a fixed category list to prevent synonym drift in on-chain statistics:

- Reentrancy
- Access Control
- Integer Overflow/Underflow
- Unchecked External Call
- Denial of Service
- Front-Running
- Timestamp Dependence
- Weak Randomness
- Gas Griefing
- Logic Error
- Input Validation
- Centralization Risk
- Upgradability Risk
- Prompt Injection Attempt
- Other

---

## Prompt Injection Protection

The LLM system prompt contains an explicit instruction to ignore any text inside the `<source_code>` block as potential prompt injection attempts. If embedded instructions are detected in the code, they are reported as a vulnerability of category **"Prompt Injection Attempt"** with severity **High**.

---

## Frontend

The frontend is implemented as a lightweight client using HTML, CSS, and JavaScript.

Features include:

- wallet connection,
- repository submission,
- audit report display,
- audit history viewing,
- statistics visualization,
- interaction with the deployed Intelligent Contract.

No backend server is required for normal operation.

---

## Known Limitations

Current limitations include:

- GitHub API availability and rate limits may affect repository retrieval.
- LLM analysis cannot guarantee complete vulnerability detection.
- Only **one file** (`.sol` or `.py`) is analyzed, not the entire repository.
- Only the **first 5000 characters** of the file are sent to the LLM.
- Very large repositories (truncated tree) are **not supported** — a direct file URL is required.
- The latest audit is stored separately from historical records.
- The audit is bound to a specific `commit_sha` and does not change when the repository is updated.
- The GitHub token improves API access but should not be treated as a secret after deployment.
