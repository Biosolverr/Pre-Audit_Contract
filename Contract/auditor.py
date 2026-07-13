# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
import json
import re


class SecurityAuditor(gl.Contract):

    audits: TreeMap[str, str]
    audit_count: u256
    audit_index: TreeMap[str, str]
    owner: Address
    github_token: str

    def __init__(self) -> None:
        self.audits = TreeMap()
        self.audit_count = u256(0)
        self.audit_index = TreeMap()
        self.owner = gl.message.sender_address
        self.github_token = ""

    @gl.public.write
    def set_github_token(self, token: str) -> None:
        # Owner-only: raises the unauthenticated GitHub API limit (60/hr per IP —
        # shared across ALL studionet validators) to 5000/hr for this contract's
        # calls. NOTE: this is a public chain — anyone can read contract state,
        # so this is NOT a real secret. Use a fine-grained PAT with read-only
        # public-repo access, nothing else, and rotate it if you're unsure.
        if gl.message.sender_address != self.owner:
            raise Exception("Only the contract owner can set the GitHub token.")
        self.github_token = token.strip()

    @gl.public.write
    def audit_contract(self, repo_url: str) -> None:
        repo_url = repo_url.strip()
        if not repo_url:
            raise Exception("repo_url cannot be empty.")

        # Storage is inaccessible inside nondet blocks, so read it into a plain
        # local variable here, before leader_fn/validator_fn are defined below.
        github_token = self.github_token

        GITHUB_HEADERS = {
            "User-Agent": "GenLayer-SecurityAuditor",
            "Accept": "application/vnd.github+json",
        }
        if github_token:
            GITHUB_HEADERS["Authorization"] = f"Bearer {github_token}"

        def github_api_get(url: str) -> dict:
            resp = gl.nondet.web.get(url, headers=GITHUB_HEADERS)
            try:
                data = json.loads(resp.body.decode("utf-8"))
            except Exception:
                raise Exception(f"GitHub API returned a non-JSON response for {url}.")
            if isinstance(data, dict) and "message" in data and (
                "sha" not in data and "tree" not in data and "default_branch" not in data
            ):
                # GitHub error payload, e.g. rate limit or missing User-Agent
                raise Exception(f"GitHub API error for {url}: {data['message'][:200]}")
            return data

        def resolve_commit_sha(owner: str, repo: str, ref: str) -> str:
            # Already a pinned commit SHA — nothing to resolve, no API call needed.
            if re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                return ref.lower()
            # "HEAD" resolves to whatever the repo's default branch currently is,
            # in a single call — avoids a separate /repos/{owner}/{repo} lookup.
            data = github_api_get(f"https://api.github.com/repos/{owner}/{repo}/commits/{ref}")
            if "sha" not in data:
                raise Exception(f"Could not resolve ref '{ref}' for {owner}/{repo}.")
            return data["sha"]

        def resolve_source(url: str):
            """
            Resolves ANY GitHub reference (raw file / blob file / bare repo) to a
            pinned commit SHA + a verified file path. Never guesses a path that
            hasn't been confirmed to exist in the repository tree.
            Returns (raw_url, owner, repo, commit_sha, file_path).
            """
            if url.startswith("https://raw.githubusercontent.com"):
                parts = url.replace("https://raw.githubusercontent.com/", "").split("/")
                if len(parts) < 4:
                    raise Exception("Invalid raw.githubusercontent.com URL.")
                owner, repo, ref = parts[0], parts[1], parts[2]
                file_path = "/".join(parts[3:])
                commit_sha = resolve_commit_sha(owner, repo, ref)
                return (
                    f"https://raw.githubusercontent.com/{owner}/{repo}/{commit_sha}/{file_path}",
                    owner, repo, commit_sha, file_path,
                )

            if "github.com" in url and "/blob/" in url:
                base = url.replace("https://github.com/", "")
                repo_part, rest = base.split("/blob/", 1)
                owner_repo = repo_part.split("/")
                owner, repo = owner_repo[0], owner_repo[1]
                rest_parts = rest.split("/", 1)
                if len(rest_parts) < 2:
                    raise Exception("Invalid GitHub blob URL: missing file path.")
                ref, file_path = rest_parts[0], rest_parts[1]
                commit_sha = resolve_commit_sha(owner, repo, ref)
                return (
                    f"https://raw.githubusercontent.com/{owner}/{repo}/{commit_sha}/{file_path}",
                    owner, repo, commit_sha, file_path,
                )

            # Bare repo URL: pin the default branch HEAD, then pick a *verified*
            # contract file from the actual repository tree at that commit.
            base = url.rstrip("/").replace("https://github.com/", "")
            parts = base.split("/")
            if len(parts) < 2:
                raise Exception("Invalid GitHub URL.")
            owner, repo = parts[0], parts[1]

            # "HEAD" resolves directly to the current default branch's commit —
            # no separate /repos/{owner}/{repo} metadata call needed.
            commit_sha = resolve_commit_sha(owner, repo, "HEAD")

            tree = github_api_get(
                f"https://api.github.com/repos/{owner}/{repo}/git/trees/{commit_sha}?recursive=1"
            )
            if tree.get("truncated"):
                raise Exception(
                    f"{owner}/{repo} tree is too large to list fully via the GitHub API. "
                    "Use a direct file URL (github.com/.../blob/<ref>/<path>) instead."
                )

            candidates = [
                t["path"] for t in tree.get("tree", [])
                if t.get("type") == "blob"
                and t["path"].endswith((".sol", ".py"))
                and "test" not in t["path"].lower()
                and "node_modules" not in t["path"]
                and "/lib/" not in t["path"]
            ]
            if not candidates:
                raise Exception(
                    f"No .sol or .py contract file found in {owner}/{repo}@{commit_sha[:7]}."
                )

            # Prefer a file whose name matches the repo; otherwise the shortest
            # path (top-level files rank above deeply nested ones).
            candidates.sort(key=lambda p: (repo.lower() not in p.lower(), p.count("/"), len(p)))
            file_path = candidates[0]

            return (
                f"https://raw.githubusercontent.com/{owner}/{repo}/{commit_sha}/{file_path}",
                owner, repo, commit_sha, file_path,
            )

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
            raw_url, owner, repo, commit_sha, file_path = resolve_source(repo_url)

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

            # Canonical form: only fields that must agree across LLMs.
            # commit_sha + file_path must match EXACTLY — this is what binds
            # the audit to one pinned repository revision instead of a guess.
            canonical = json.dumps({
                "language": parsed["language"],
                "overall_risk": parsed["overall_risk"],
                "score_bucket": score_bucket,
                "vuln_count": len(parsed.get("vulnerabilities", [])),
                "commit_sha": commit_sha,
                "file_path": file_path,
            }, sort_keys=True)

            full_report = {
                **parsed,
                "owner": owner,
                "repo": repo,
                "pinned_commit": commit_sha,
                "pinned_file": file_path,
            }

            return json.dumps({
                "canonical": canonical,
                "report": json.dumps(full_report, sort_keys=True),
            }, sort_keys=True)

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            try:
                validator_output = leader_fn()
                lc = json.loads(json.loads(leader_result.calldata)["canonical"])
                vc = json.loads(json.loads(validator_output)["canonical"])
                # Must agree on the exact pinned revision, plus language,
                # overall_risk, and score bucket.
                return (
                    lc["commit_sha"] == vc["commit_sha"]
                    and lc["file_path"] == vc["file_path"]
                    and lc["language"] == vc["language"]
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
                    "pinned_commit": report.get("pinned_commit", "?"),
                    "pinned_file": report.get("pinned_file", "?"),
                })
            except Exception:
                summaries.append({"repo_url": url, "overall_risk": "?", "score": 0, "language": "?"})
        return json.dumps(summaries)
