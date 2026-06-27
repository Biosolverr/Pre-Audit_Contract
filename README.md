# Contract Auditor — Smart Contract Security Pre-Auditor on GenLayer

> AI-powered security analysis of Solidity and GenLayer (Python) contracts.  
> Validators independently fetch source code, run LLM analysis, and reach on-chain consensus via GenLayer Optimistic Democracy.

---

## How it works

1. User submits a GitHub repo / raw file URL via the frontend
2. The frontend calls `audit_contract(repo_url)` on the deployed intelligent contract
3. Every GenLayer validator node independently:
   - Fetches the contract source from `raw.githubusercontent.com`
   - Sends it to an LLM with a structured security audit prompt
   - Returns a JSON report: vulnerabilities, severity scores, test coverage, documentation rating
4. Validators reach consensus (non-comparative equivalence: same `overall_risk`, score within ±10 points)
5. The finalized report is stored on-chain and rendered in the frontend

---

## Project structure

```
smart-contract-auditor/
├── contract/
│   └── security_auditor.py   ← GenLayer Intelligent Contract
├── frontend/
│   └── index.html            ← Single-file frontend (no build step)
├── vercel.json               ← Vercel static deploy config
└── README.md
```

---

## Deploy: Intelligent Contract

### 1. Open GenLayer Studio

Go to **[https://studio.genlayer.com](https://studio.genlayer.com)**

### 2. Load the contract

- Click **"Load Contract"**
- Upload `contract/security_auditor.py`
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

## GenLayer SDK note

The frontend imports `genlayer-js` via ESM CDN (no build step required):

```js
import { createClient, chains } from 'https://esm.sh/genlayer-js@latest';
const client = createClient({ chain: chains.studionet });
```

All reads (`get_audit`, `get_all_audits`) call `client.readContract`.  
Audit submission calls `client.writeContract` → polls `getTransactionReceipt` until `FINALIZED`.

---

## Disclaimer

This is a **pre-audit tool** — a fast automated first-pass. It does not replace a professional manual audit before mainnet deployment.
