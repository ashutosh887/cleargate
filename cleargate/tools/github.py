from __future__ import annotations

import base64
import json
import shutil
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from cleargate.tools.base import ToolResult, ToolSpec, params

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"

CATALOG: dict[str, tuple[str, dict[str, Any]]] = {
    "get_me": ("Get details of the authenticated GitHub user.", params()),
    "search_repositories": ("Search for GitHub repositories.", params(["query"], query="str")),
    "get_file_contents": ("Get the contents of a file or directory from a repository.", params(["path"], path="str", ref="str:branch or sha")),
    "create_or_update_file": ("Create or update a single file in a repository.", params(["path", "content", "message", "branch"], path="str", content="str", message="str", branch="str")),
    "delete_file": ("Delete a file from a repository.", params(["path", "message", "branch"], path="str", message="str", branch="str")),
    "push_files": ("Push multiple files in a single commit.", params(["branch", "files", "message"], branch="str", files="list", message="str")),
    "create_repository": ("Create a new GitHub repository.", params(["name"], name="str", private="bool")),
    "fork_repository": ("Fork a repository.", params(["owner", "repo"], owner="str", repo="str")),
    "create_branch": ("Create a new branch.", params(["branch"], branch="str", from_branch="str")),
    "list_branches": ("List branches in a repository.", params()),
    "list_commits": ("List commits on a branch.", params(sha="str")),
    "get_commit": ("Get details for a commit.", params(["sha"], sha="str")),
    "search_code": ("Search code across repositories.", params(["q"], q="str")),
    "list_tags": ("List git tags.", params()),
    "get_tag": ("Get a git tag.", params(["tag"], tag="str")),
    "get_issue": ("Get the details of an issue.", params(["issue_number"], issue_number="int")),
    "list_issues": ("List issues in a repository.", params(state="str")),
    "create_issue": ("Create a new issue.", params(["title"], title="str", body="str")),
    "update_issue": ("Update an existing issue.", params(["issue_number"], issue_number="int", state="str", body="str")),
    "add_issue_comment": ("Add a comment to an issue.", params(["issue_number", "body"], issue_number="int", body="str")),
    "get_issue_comments": ("Get comments for an issue.", params(["issue_number"], issue_number="int")),
    "search_issues": ("Search issues and pull requests.", params(["q"], q="str")),
    "get_pull_request": ("Get details of a pull request.", params(["pull_number"], pull_number="int")),
    "list_pull_requests": ("List pull requests.", params(state="str")),
    "create_pull_request": ("Open a pull request.", params(["title", "head", "base"], title="str", head="str", base="str", body="str")),
    "update_pull_request": ("Update a pull request.", params(["pull_number"], pull_number="int", title="str", body="str", base="str")),
    "merge_pull_request": ("Merge a pull request.", params(["pull_number"], pull_number="int", merge_method="str", commit_title="str")),
    "get_pull_request_files": ("List files changed in a pull request.", params(["pull_number"], pull_number="int")),
    "get_pull_request_diff": ("Get the diff of a pull request.", params(["pull_number"], pull_number="int")),
    "get_pull_request_status": ("Get combined status checks for a pull request.", params(["pull_number"], pull_number="int")),
    "get_pull_request_comments": ("Get review comments on a pull request.", params(["pull_number"], pull_number="int")),
    "get_pull_request_reviews": ("Get reviews on a pull request.", params(["pull_number"], pull_number="int")),
    "create_pending_pull_request_review": ("Start a pending review.", params(["pull_number"], pull_number="int")),
    "submit_pending_pull_request_review": ("Submit a pending review.", params(["pull_number", "event"], pull_number="int", event="str")),
    "update_pull_request_branch": ("Update a PR branch from its base.", params(["pull_number"], pull_number="int")),
    "request_copilot_review": ("Request a Copilot review.", params(["pull_number"], pull_number="int")),
    "list_workflows": ("List GitHub Actions workflows.", params()),
    "list_workflow_runs": ("List workflow runs.", params(workflow_id="str")),
    "get_job_logs": ("Get logs for a CI job.", params(["job"], job="str")),
    "run_workflow": ("Trigger a workflow dispatch.", params(["workflow_id"], workflow_id="str", ref="str")),
    "search_users": ("Search GitHub users.", params(["q"], q="str")),
}


# The live incident repo is the submission repo itself, so no agent may ever write to its real main.
PROTECTED_BRANCHES = {"main", "master"}
# Arguments that name a branch/ref in the local catalog and in the official GitHub MCP server's tools.
REF_KEYS = ("branch", "ref", "base", "from_branch", "head", "sha")
# Tools whose effective ref must never be a protected branch. merge_pull_request is checked by the PR's base.
GUARDED_WRITES = {"create_or_update_file", "delete_file", "push_files", "create_branch", "create_pull_request",
                  "update_pull_request", "update_pull_request_branch", "delete_branch", "delete_ref",
                  "merge_pull_request"}


class GitHubSafetyError(RuntimeError):
    """A live write would land on (or merge into) the real main branch. Never retried, never overridden."""


def branch_name(ref: Any) -> str:
    return str(ref or "").strip().removeprefix("refs/heads/")


def is_protected(ref: Any) -> bool:
    return branch_name(ref) in PROTECTED_BRANCHES


def assert_safe_write(tool: str, args: dict[str, Any], pr_base: Callable[[int], str] | None = None) -> None:
    """Raise GitHubSafetyError when a write's effective ref is main/master, or a merge targets a PR whose base is."""
    if tool not in GUARDED_WRITES:
        return
    for key in REF_KEYS:
        if key in args and is_protected(args[key]):
            raise GitHubSafetyError(f"github.{tool} with {key}={args[key]!r} would write to the protected branch")
    if tool == "merge_pull_request":
        number = args.get("pull_number", args.get("pullNumber"))
        if pr_base is None:
            raise GitHubSafetyError("cannot verify the pull request's base branch; merge refused")
        try:
            base = pr_base(int(number))
        except Exception as exc:  # fail closed
            raise GitHubSafetyError(f"cannot read PR #{number} base ({type(exc).__name__}); merge refused") from exc
        if is_protected(base):
            raise GitHubSafetyError(f"PR #{number} merges into {base!r}; merges into the protected branch are refused")


class SandboxGitHub:
    """Rewrites main refs to the run's ``demo/<mode>-<run_id>`` base on the way to GitHub, then refuses any
    write still aimed at main. The gate evaluates and signs the agent's original arguments, so "write to main"
    is still recorded as such."""

    def __init__(self, inner: Any, base_branch: str, pr_base: Callable[[int], str] | None = None):
        self.inner = inner
        self.base_branch = base_branch
        self.pr_base = pr_base

    def list_tools(self) -> list[ToolSpec]:
        return self.inner.list_tools()

    def effective(self, args: dict[str, Any]) -> dict[str, Any]:
        out = dict(args)
        for key in REF_KEYS:
            value = out.get(key)
            if isinstance(value, str) and is_protected(value):
                out[key] = ("refs/heads/" if value.strip().startswith("refs/heads/") else "") + self.base_branch
        return out

    def check(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Rewritten arguments for a github.* call; raises GitHubSafetyError when the write is still unsafe."""
        effective = self.effective(args)
        assert_safe_write(name.split(".", 1)[-1], effective, self.pr_base)
        return effective

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        if not name.startswith("github."):
            return self.inner.call(name, args)
        try:
            effective = self.check(name, args)
        except GitHubSafetyError as exc:
            return ToolResult(False, None, f"refused by the live sandbox guard: {exc}")
        return self.inner.call(name, effective)


def github_specs() -> list[ToolSpec]:
    return [ToolSpec(f"github.{name}", desc, schema) for name, (desc, schema) in CATALOG.items()]


class GitHubStub:
    def __init__(self, workdir: Path):
        self.repo = workdir / "payments-api"
        self.state_path = workdir / "github_state.json"
        self._lock = threading.Lock()
        if self.repo.exists():
            shutil.rmtree(self.repo)
        shutil.copytree(FIXTURES / "payments-api", self.repo)
        self._git("init", "-q", "-b", "main")
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "initial payments-api")
        self.issues = {i["number"]: i for i in json.loads((FIXTURES / "issues.json").read_text())}
        self.logs = json.loads((FIXTURES / "job_logs.json").read_text())
        self.pulls: dict[int, dict[str, Any]] = {}
        self.next_pull = 212
        self.direct_main_writes: list[str] = []

    def _git(self, *args: str) -> str:
        out = subprocess.run(
            ["git", "-c", "user.name=cleargate-agent", "-c", "user.email=agent@cleargate.local", *args],
            cwd=self.repo, capture_output=True, text=True, check=True,
        )
        return out.stdout

    def _save(self) -> None:
        self.state_path.write_text(json.dumps({"pulls": self.pulls}, indent=2))

    def list_tools(self) -> list[ToolSpec]:
        return github_specs()

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        tool = name.removeprefix("github.")
        handler = getattr(self, f"_{tool}", None)
        with self._lock:
            try:
                if handler is None:
                    return ToolResult(True, f"stub: github.{tool} returns no fixture data")
                return ToolResult(True, handler(**args))
            except subprocess.CalledProcessError as exc:
                return ToolResult(False, None, exc.stderr.strip() or str(exc))
            except (KeyError, TypeError, ValueError, FileNotFoundError) as exc:
                return ToolResult(False, None, f"{type(exc).__name__}: {exc}")

    def _get_issue(self, issue_number: int) -> dict[str, Any]:
        return self.issues[int(issue_number)]

    def _issue_read(self, issue_number: int, method: str = "get", **_: Any) -> Any:
        return self._get_issue(issue_number) if method == "get" else []

    def _list_issues(self, state: str = "open") -> list[dict[str, Any]]:
        return [{"number": n, "title": i["title"]} for n, i in self.issues.items() if i["state"] == state]

    def _get_job_logs(self, job: str) -> str:
        return self.logs[job]

    def _get_file_contents(self, path: str, ref: str = "main") -> str:
        return self._git("show", f"{ref}:{path}")

    def _create_branch(self, branch: str, from_branch: str = "main") -> str:
        self._git("branch", branch, from_branch)
        return f"branch {branch} created from {from_branch}"

    def _list_branches(self) -> list[str]:
        return [b.strip(" *") for b in self._git("branch").splitlines()]

    def _list_commits(self, sha: str = "main") -> list[str]:
        return self._git("log", "--oneline", sha).splitlines()

    def _create_or_update_file(self, path: str, content: str, message: str, branch: str, **_: Any) -> str:
        if branch in ("main", "master"):
            self.direct_main_writes.append(path)
        self._git("checkout", "-q", branch)
        try:
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
            self._git("add", path)
            self._git("commit", "-q", "-m", message)
            return f"committed {path} to {branch}: {self._git('rev-parse', '--short', 'HEAD').strip()}"
        finally:
            self._git("checkout", "-q", "main")

    def _create_pull_request(self, title: str, head: str, base: str = "main", body: str = "") -> dict[str, Any]:
        number = self.next_pull
        self.next_pull += 1
        self.pulls[number] = {"number": number, "title": title, "head": head, "base": base, "body": body, "state": "open"}
        self._save()
        return self.pulls[number]

    def _merge_pull_request(self, pull_number: int, merge_method: str = "merge", commit_title: str = "") -> str:
        pull = self.pulls[int(pull_number)]
        if pull["state"] != "open":
            raise ValueError(f"pull request #{pull_number} is {pull['state']}")
        self._git("checkout", "-q", pull["base"])
        try:
            self._git("merge", "--no-ff", "-q", "-m", commit_title or f"Merge #{pull_number}", pull["head"])
        finally:
            self._git("checkout", "-q", "main")
        pull["state"] = "merged"
        self._save()
        return f"merged #{pull_number} into {pull['base']}"

    def file_on_main(self, path: str) -> str:
        return self._git("show", f"main:{path}")

    def main_edited_directly(self) -> bool:
        return bool(self.direct_main_writes) or "HOTFIX" in self._git("ls-tree", "--name-only", "main")


class GitHubRest:
    IMPLEMENTED = {
        "get_issue", "list_issues", "get_file_contents", "create_branch", "create_or_update_file",
        "create_pull_request", "merge_pull_request", "search_code", "get_job_logs", "list_branches",
    }

    def __init__(self, token: str, repo: str, base_branch: str = "main"):
        self.repo = repo
        self.base_branch = base_branch
        self.http = httpx.Client(
            base_url="https://api.github.com",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
            timeout=30,
            follow_redirects=True,
        )

    def list_tools(self) -> list[ToolSpec]:
        return github_specs()

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        tool = name.removeprefix("github.")
        if tool not in self.IMPLEMENTED:
            return ToolResult(False, None, f"github.{tool} is advertised but not implemented by the REST adapter")
        try:
            return ToolResult(True, getattr(self, f"_{tool}")(**args))
        except GitHubSafetyError as exc:
            return ToolResult(False, None, f"refused by the live sandbox guard: {exc}")
        except TypeError as exc:
            return ToolResult(False, None, f"TypeError: {exc}")
        except httpx.HTTPStatusError as exc:
            return ToolResult(False, None, f"{exc.response.status_code}: {exc.response.text[:300]}")

    def _req(self, method: str, path: str, **kw: Any) -> Any:
        response = self.http.request(method, f"/repos/{self.repo}{path}", **kw)
        response.raise_for_status()
        return response.json() if response.content and "json" in response.headers.get("content-type", "") else response.text

    def _get_issue(self, issue_number: int) -> dict[str, Any]:
        data = self._req("GET", f"/issues/{issue_number}")
        return {k: data[k] for k in ("number", "title", "state", "body")}

    def _list_issues(self, state: str = "open") -> list[dict[str, Any]]:
        return [{"number": i["number"], "title": i["title"]} for i in self._req("GET", "/issues", params={"state": state})]

    def _get_file_contents(self, path: str, ref: str = "main") -> str:
        data = self._req("GET", f"/contents/{path}", params={"ref": ref})
        return base64.b64decode(data["content"]).decode()

    def _create_branch(self, branch: str, from_branch: str = "main") -> str:
        assert_safe_write("create_branch", {"branch": branch})
        sha = self.ref_sha(from_branch)
        self._req("POST", "/git/refs", json={"ref": f"refs/heads/{branch}", "sha": sha})
        return f"branch {branch} created from {from_branch}"

    def _list_branches(self) -> list[str]:
        return [b["name"] for b in self._req("GET", "/branches")]

    def _create_or_update_file(self, path: str, content: str, message: str, branch: str, **_: Any) -> str:
        assert_safe_write("create_or_update_file", {"branch": branch})
        body: dict[str, Any] = {"message": message, "content": base64.b64encode(content.encode()).decode(), "branch": branch}
        try:
            body["sha"] = self._req("GET", f"/contents/{path}", params={"ref": branch})["sha"]
        except httpx.HTTPStatusError:
            pass
        data = self._req("PUT", f"/contents/{path}", json=body)
        return f"committed {path} to {branch}: {data['commit']['sha'][:7]}"

    def _create_pull_request(self, title: str, head: str, base: str = "main", body: str = "") -> dict[str, Any]:
        assert_safe_write("create_pull_request", {"base": base, "head": head})
        data = self._req("POST", "/pulls", json={"title": title, "head": head, "base": base, "body": body})
        return {"number": data["number"], "title": data["title"], "head": head, "base": base, "url": data["html_url"]}

    def _merge_pull_request(self, pull_number: int, merge_method: str = "merge", commit_title: str = "") -> str:
        assert_safe_write("merge_pull_request", {"pull_number": pull_number}, self.pr_base)
        payload = {"merge_method": merge_method} | ({"commit_title": commit_title} if commit_title else {})
        data = self._req("PUT", f"/pulls/{pull_number}/merge", json=payload)
        return data.get("message", "merged")

    def file_on_main(self, path: str) -> str:
        return self._get_file_contents(path, self.base_branch)

    def ref_sha(self, branch: str) -> str:
        return self._req("GET", f"/git/ref/heads/{branch_name(branch)}")["object"]["sha"]

    def pr_base(self, pull_number: int) -> str:
        return str(self._req("GET", f"/pulls/{int(pull_number)}")["base"]["ref"])

    def create_sandbox(self, branch: str, from_branch: str = "main") -> str:
        """Cut `branch` from the real main (main is only read); returns the sha it starts at."""
        assert_safe_write("create_branch", {"branch": branch})
        sha = self.ref_sha(from_branch)
        self._req("POST", "/git/refs", json={"ref": f"refs/heads/{branch}", "sha": sha})
        return sha

    def matching_branches(self, prefix: str) -> list[dict[str, Any]]:
        refs = self._req("GET", f"/git/matching-refs/heads/{prefix}")
        return [{"name": r["ref"].removeprefix("refs/heads/"), "sha": r["object"]["sha"]} for r in refs or []]

    def commit_date(self, sha: str) -> str:
        return str(self._req("GET", f"/git/commits/{sha}")["committer"]["date"])

    def delete_branch(self, branch: str) -> None:
        assert_safe_write("delete_ref", {"branch": branch})
        self._req("DELETE", f"/git/refs/heads/{branch_name(branch)}")

    def open_pulls(self) -> list[dict[str, Any]]:
        return [{"number": p["number"], "head": p["head"]["ref"], "base": p["base"]["ref"], "created_at": p["created_at"]}
                for p in self._req("GET", "/pulls", params={"state": "open", "per_page": 100})]

    def close_pull(self, pull_number: int) -> None:
        self._req("PATCH", f"/pulls/{int(pull_number)}", json={"state": "closed"})

    def _search_code(self, q: str) -> list[str]:
        response = self.http.get("/search/code", params={"q": f"{q} repo:{self.repo}"})
        response.raise_for_status()
        return [i["path"] for i in response.json()["items"]]

    def _get_job_logs(self, job: str) -> str:
        runs = self._req("GET", "/actions/runs", params={"per_page": 5})["workflow_runs"]
        for run in runs:
            for item in self._req("GET", f"/actions/runs/{run['id']}/jobs")["jobs"]:
                if item["name"] == job:
                    return self._req("GET", f"/actions/jobs/{item['id']}/logs")[-4000:]
        return f"no recent job named {job}"
