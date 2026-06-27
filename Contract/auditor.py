# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
import json


class SecurityAuditor(gl.Contract):

    audits: TreeMap[str, str]
    audit_count: u256
    audit_index: TreeMap[str, str]

    def __init__(self) -> None:
        self.audits = TreeMap()
        self.audit_count = u256(0)
        self.audit_index = TreeMap()

    @gl.public.write
    def audit_contract(self, repo_url: str) -> None:
        repo_url = repo_url.strip()
        if not repo_url:
            raise Exception("repo_url cannot be empty.")

        # Build raw URL outside nondet (no self access inside nondet)
        url = repo_url
        if url.startswith("https://raw.githubusercontent.com"):
            raw_url = url
        elif "github.com" in url and "/blob/" in url:
            raw_url = (
                url.replace("https://github.com", "https://raw.githubusercontent.com")
                   .replace("/blob/", "/")
            )
        else:
            base = url.rstrip("/").replace("https://github.com/", "")
            parts = base.split("/")
            if len(parts) < 2:
                raise Exception("Invalid GitHub URL.")
            owner, repo = parts[0], parts[1]
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/contracts/{repo}.sol"

        PROMPT = """You are a senior smart-contract security auditor.
Analyze the contract source code below and return ONLY a JSON object — no markdown fences, no explanation, nothing else.

SOURCE CODE:
{source}

Required JSON structure:
{{
  "language": "Solidity",
  "overall_risk": "High",
  "score": 55,
  "vulnerabilities": [
    {{
      "id": "V001",
      "severity": "High",
      "category": "Reentrancy",
      "title": "Short title",
      "description": "Description.",
      "recommendation": "Fix."
    }}
  ],
  "test_coverage": {{"rating": "None", "notes": "Notes."}},
  "documentation": {{"rating": "Partial", "notes": "Notes."}},
  "summary": "Executive summary."
}}

Rules:
- language: "Solidity", "Python/GenLayer", or "Other"
- overall_risk: "Critical", "High", "Medium", "Low", or "Info"
- score: integer 0-100
- rating: "Good", "Partial", "Minimal", or "None"
- vulnerabilities: [] if none found
- Output ONLY the JSON object, nothing else"""

        def leader_fn() -> str:
            response = gl.nondet.web.get(raw_url)
            source = response.body.decode("utf-8")
            if not source.strip():
                raise Exception("Fetched file is empty.")

            snippet = source[:5000]
            if len(source) > 5000:
                snippet += "\n[TRUNCATED]"

            result = gl.nondet.exec_prompt(PROMPT.format(source=snippet))

            clean = result.strip()
            if clean.startswith("```"):
                lines = clean.split("\n")
                lines = lines[1:]
                if lines and lines[-1].strip().startswith("```"):
                    lines = lines[:-1]
                clean = "\n".join(lines).strip()

            parsed = json.loads(clean)

            for field in ("language", "overall_risk", "score", "vulnerabilities", "summary"):
                if field not in parsed:
                    raise Exception(f"Missing field: {field}")

            # Normalize score to bucket for stable consensus
            # 0-20=1, 21-40=2, 41-60=3, 61-80=4, 81-100=5
            score = int(parsed["score"])
            score_bucket = (score - 1) // 20 if score > 0 else 0

            # Canonical form: only fields that must agree across LLMs
            canonical = json.dumps({
                "language": parsed["language"],
                "overall_risk": parsed["overall_risk"],
                "score_bucket": score_bucket,
                "vuln_count": len(parsed.get("vulnerabilities", [])),
            }, sort_keys=True)

            return json.dumps({
                "canonical": canonical,
                "report": json.dumps(parsed, sort_keys=True),
            }, sort_keys=True)

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            try:
                validator_output = leader_fn()
                lc = json.loads(json.loads(leader_result.calldata)["canonical"])
                vc = json.loads(json.loads(validator_output)["canonical"])
                # Must agree on language, overall_risk, and score bucket
                return (
                    lc["language"] == vc["language"]
                    and lc["overall_risk"] == vc["overall_risk"]
                    and abs(lc["score_bucket"] - vc["score_bucket"]) <= 1
                )
            except Exception:
                return False

        raw = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

        parsed = json.loads(raw)
        full_report = parsed["report"]

        idx = int(self.audit_count)
        self.audits[repo_url] = full_report
        self.audit_index[str(idx)] = repo_url
        self.audit_count = u256(idx + 1)

    @gl.public.view
    def get_audit(self, repo_url: str) -> str:
        repo_url = repo_url.strip()
        if repo_url in self.audits:
            return self.audits[repo_url]
        return ""

    @gl.public.view
    def get_audit_count(self) -> str:
        return str(int(self.audit_count))

    @gl.public.view
    def get_recent_audits(self) -> str:
        count = int(self.audit_count)
        start = max(0, count - 10)
        result = []
        for i in range(count - 1, start - 1, -1):
            result.append(self.audit_index[str(i)])
        return json.dumps(result)

    @gl.public.view
    def get_all_audits(self) -> str:
        count = int(self.audit_count)
        summaries = []
        for i in range(count - 1, -1, -1):
            url = self.audit_index[str(i)]
            try:
                report = json.loads(self.audits[url])
                summaries.append({
                    "repo_url": url,
                    "overall_risk": report.get("overall_risk", "?"),
                    "score": report.get("score", 0),
                    "language": report.get("language", "?"),
                })
            except Exception:
                summaries.append({"repo_url": url, "overall_risk": "?", "score": 0, "language": "?"})
        return json.dumps(summaries)
