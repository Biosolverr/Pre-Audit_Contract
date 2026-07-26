Security Pre-Auditor on GenLayer

> AI-powered security analysis of Solidity and GenLayer (Python) contracts.  
> Validators independently fetch source code, run LLM analysis, and reach on-chain consensus via GenLayer Optimistic Democracy.

---

## How it works

1. User submits a GitHub repo / blob / raw file URL via the frontend
2. The frontend calls `audit_contract(repo_url)` on the deployed intelligent contract
3. Every GenLayer validator node independently:
   - Resolves the reference to a **pinned commit SHA** via the GitHub API (`/commits/{ref}`), and — for a bare repo URL — walks the actual repository tree (`/git/trees/{sha}?recursive=1`) to pick a **verified** `.sol`/`.py` file instead of guessing a path
   - Fetches that exact file at that exact commit from `raw.githubusercontent.com`
   - Sends it to an LLM with a structured security audit prompt
   - Returns a JSON report: vulnerabilities, severity scores, test coverage, documentation rating
4. Validators reach consensus — they must agree on the resolved `commit_sha` and `file_path` (the pinned revision), plus `overall_risk` and score bucket
5. The finalized report — including the pinned commit + file — is stored on-chain and rendered in the frontend

---

## Project structure

```
smart-contract-auditor/
├── Contract/
│   └── auditor.py             ← GenLayer Intelligent Contract
├── frontend/
│   └── index.html             ← Single-file frontend (no build step)
├── vercel.json                ← Vercel static deploy config
└── README.md
```

---

## Deploy: Intelligent Contract

### 1. Open GenLayer Studio

Go to **[https://studio.genlayer.com](https://studio.genlayer.com)**

### 2. Load the contract

- Click **"Load Contract"**
- Upload `Contract/auditor.py`
  - Or paste the code directly into the editor

### 3. Deploy

- Click **"Deploy"**
- Confirm deployment in the Studio UI
- Copy the deployed **contract address** (e.g. `0xabc…`)

### 4. Test in Studio

Use the Studio's **"Execute Transaction"** panel to call:

| Method | Type | Args |
|--------|------|------|
| `audit_contract` | write | `repo_url` = `https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/master/contracts/token/ERC20/ERC20.sol` |
| `get_audit` | read | `repo_url` = same URL |
| `get_audit_count` | read | — |
| `get_recent_audits` | read | — |
| `get_all_audits` | read | — |

Wait for consensus (Finalized status), then call `get_audit` to verify the JSON report is stored.

---

## Deploy: Frontend (Vercel)

### 1. Push to GitHub

```bash
git init
git add .
git commit -m "init: contract auditor"
git remote add origin https://github.com/YOUR_USERNAME/smart-contract-auditor
git push -u origin main
```

### 2. Import on Vercel

- Go to **[vercel.com/new](https://vercel.com/new)**
- Import your GitHub repo
- Vercel auto-detects `vercel.json` — no settings needed
- Click **Deploy**

### 3. Configure the contract address

After the frontend is live:

1. Open the deployed Vercel URL
2. In the form, paste your GenLayer contract address into **"GenLayer Contract Address"**
3. Click **Save** — address is stored in `localStorage`

The frontend now talks directly to the GenLayer studionet node via `genlayer-js`.

---

## Audit report structure (on-chain JSON)

```json
{
  "language": "Solidity",
  "overall_risk": "High",
  "score": 61,
  "vulnerabilities": [
    {
      "id": "V001",
      "severity": "High",
      "category": "Reentrancy",
      "title": "Reentrancy in withdraw()",
      "description": "The withdraw function sends ETH before zeroing the balance, allowing recursive calls.",
      "recommendation": "Apply the Checks-Effects-Interactions pattern: zero the balance before sending ETH."
    }
  ],
  "test_coverage": {
    "rating": "Minimal",
    "notes": "No test files detected in the repository."
  },
  "documentation": {
    "rating": "Partial",
    "notes": "NatSpec comments present on public functions but missing on internal helpers."
  },
  "summary": "The contract contains a high-severity reentrancy vulnerability in the withdraw path..."
}
```

---

## Vulnerability categories detected

- Reentrancy
- Integer Overflow / Underflow
- Access Control
- Unchecked Return Values
- Front-Running
- Timestamp Dependence
- Gas Limit / Denial of Service
- Logic Errors

---

## Pinned repository revision

`audit_contract` never trusts a guessed file path. For every input it resolves,
inside the nondet leader/validator functions, a concrete `(commit_sha, file_path)`
pair via the GitHub REST API:

- `raw.githubusercontent.com/.../<ref>/<path>` → resolves `<ref>` to its commit SHA
- `github.com/.../blob/<ref>/<path>` → same, using the blob's ref
- `github.com/<owner>/<repo>` (bare) → reads the repo's default branch HEAD SHA,
  then lists the full tree at that commit and picks a real `.sol`/`.py` file that
  exists in it

Validators must agree on the exact `commit_sha` + `file_path`, not just the audit
scores — so the stored report is reproducible against one immutable revision,
not a moving branch head. The pinned commit and file are stored in the report and
shown in the frontend, with a link to the exact file at that commit.

## GenLayer SDK note

The frontend imports `genlayer-js` via ESM CDN (no build step required):

```js
import { createClient, chains } from 'https://esm.sh/genlayer-js@latest';
const client = createClient({ chain: chains.studionet });
```

All reads (`get_audit`, `get_all_audits`) call `client.readContract`.  
Audit submission calls `client.writeContract` → polls `getTransactionReceipt` until `FINALIZED`.

---

## New contract methods

| Method | Type | Purpose |
|--------|------|---------|
| `get_audit_trend` | view | Per-repo history of `{seq, score, overall_risk}` across re-audits (last 20) |
| `get_audit_stats` | view | Aggregate totals: audit count, unique repos, risk-level distribution, top vulnerability categories |
| `get_all_audits(limit)` | view | Now deduplicated by repo (a re-audited repo appears once, at its most recent position) and depth-capped, so it can't turn into an unbounded scan as history grows. Existing calls with no `limit` still work — defaults to 50 |

## Security fixes (July 2026 review)

- **Prompt injection**: the audited source is now wrapped in explicit `<source_code>` markers with an instruction to the LLM to treat it strictly as data, never as commands — and to flag any embedded injection attempt as its own "Prompt Injection Attempt" finding.
- **Consensus granularity**: `validator_fn` now also requires agreement on `vuln_count` (within tolerance) — this field was already collected but never actually checked.
- **URL validation**: `resolve_source` now rejects anything that isn't an exact `https://github.com/` or `https://raw.githubusercontent.com/` prefix, closing a domain-confusion edge case (e.g. `raw.githubusercontent.com.evil.com`) and giving a clean error for non-GitHub URLs instead of falling through to the bare-repo branch.
- **`get_all_audits` DoS**: bounded to a hard scan-depth ceiling regardless of total audit count (previously unbounded).
- **Duplicate history entries**: re-auditing the same repo no longer produces duplicate rows in `get_all_audits`.
- **Frontend XSS**: the history list is now built with DOM APIs instead of `innerHTML` + string interpolation inside an `onclick` attribute, which could previously be broken out of with a crafted `repo_url` containing a double quote. The pinned-revision link is now consistently HTML-escaped like the rest of the report.
- **Duplicate document bug**: the shipped `frontend/index.html` had an accidental second `<!DOCTYPE html><html><head>...` block spliced into the middle of the form, and a duplicated `id="stat-count"` element — meaning the visible "audits on-chain" counter was silently bound to the wrong, invisible element. The file is now a single well-formed document.
- `github_token` remaining in plaintext contract state is a known, intentional tradeoff (documented in `Contract/auditor.py`) — GenLayer is a public chain, so there's no way to raise GitHub's rate limit from a contract without exposing *some* credential to on-chain reads. Use a read-only, public-repo-scoped token.

## New frontend features

- **Score trend** — per-repo chart under each report (`get_audit_trend`), showing how score/risk changed across re-audits.
- **Aggregate stats dashboard** — total audits, unique repos, risk-level distribution, and most common vulnerability categories (`get_audit_stats`), shown as its own section.
- **Filter/search on history** — filter the on-chain audit list by risk level or search by URL, client-side.
- **Export report** — download any report as JSON or Markdown.
- **Embeddable badge** — generates an SVG score badge + a Markdown snippet to paste into the audited repo's own README.
- **Permalink** — `?repo=<url>&contract=<address>` in the frontend URL auto-loads that contract/report on page load.

## Second pass (post-live-testing)

Found by running the actual test protocol above against a live Studio deployment:

- **Category vocabulary drift**: the same finding ("owner changeable via `tx.origin`") came back tagged `"Access Control"` in one run and `"Authorization"` in another — free-text categories fragment `get_audit_stats.top_categories`. Fixed: the LLM must now pick from a fixed `VULN_CATEGORIES` list; anything off-list is normalized to `"Other"` as a fallback.
- **Cross-sender re-audit spam**: `set_github_token` is now live with a real credential attached, so unrestricted re-audits burn the owner's personal GitHub quota. Fixed with a **sender-aware cooldown**: re-auditing your *own* previous submission is always instant (doesn't break iterative testing), but a *different* address re-auditing someone else's just-submitted repo has to wait `MIN_REAUDIT_GAP` (2) other audits first.
- **`repo_url` fragmentation**: trailing slash / `.git` suffix variants of the same URL were treated as different keys. Fixed with `_normalize_repo_url()`, applied consistently on write and on every read (`get_audit`, `get_audit_trend`).
- **Bare-repo file selection picked a small/unrepresentative file** (observed live: `openzeppelin-contracts` resolved to a small `RLP.sol` utility instead of a more central contract). Sort order now also prefers the larger file (by GitHub tree API `size`) as a tertiary key, after name-match and path depth.
- **Score precision**: consensus tolerates a ±1 score-bucket disagreement (a bucket is 20 points wide), so an exact-looking number like `55/100` can hide real spread between validators. Frontend now says so next to the score.
- **Frontend couldn't tell you *why* an audit failed** (UNDETERMINED vs. revert vs. still finalizing) — it just said "no report found." Now distinguishes UNDETERMINED (validators' AI disagreed too much), the ACCEPTED→FINALIZED transition (shown as expected, not stuck), and the anti-spam cooldown message from the contract, in the status text.



## Disclaimer

This is a **pre-audit tool** — a fast automated first-pass. It does not replace a professional manual audit before mainnet deployment.
