import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field
from openai import OpenAI

from prompts import (
    PROMPT_NAME,
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    build_user_prompt,
)

DEFAULT_TEMPERATURE = 0


# ---- 1) Structured Outputs schema ----
class Evidence(BaseModel):
    line: Optional[int] = Field(None, description="Line number if available")
    snippet: str = Field(..., description="Exact code snippet from the source that supports the claim.")


class RiskResult(BaseModel):
    risk_level: Literal["High", "Medium", "Low"]
    risk_score: int = Field(..., ge=0, le=100, description="A numerical score from 0 (safe) to 100 (critical).")
    vulnerability_types: List[str] = Field(..., description="List of potential vulnerability categories.")
    reasons: List[str] = Field(..., min_length=1, description="Concise reasons explaining why this risk score was assigned.")
    evidence: List[Evidence] = Field(default_factory=list, description="List of evidence snippets.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence level in this assessment (0.0 to 1.0).")


# ---- 2) Git context (file-level) ----
def is_git_repo(path: str) -> bool:
    return os.path.isdir(os.path.join(path, ".git"))


def get_git_context(repo: str, file_path: str, n: int) -> dict:
    """
    File-level git log summary (MVP):
    - last n commit messages touching this file
    - commit count returned
    """
    rel = os.path.relpath(file_path, repo)
    cmd = ["git", "-C", repo, "log", f"-n{n}", "--pretty=format:%s", "--", rel]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return {"commit_count": 0, "recent_messages": []}

    msgs = [line.strip() for line in out.splitlines() if line.strip()]
    return {"commit_count": len(msgs), "recent_messages": msgs[:n]}


# ---- 3) Utility: stable cache key ----
def record_key(rec: dict) -> str:
    h = hashlib.sha256((rec.get("code") or "").encode("utf-8")).hexdigest()[:16]
    return f"{rec.get('file','')}::{rec.get('func_name','')}::{rec.get('line_start','?')}-{rec.get('line_end','?')}::{h}"


def load_done_keys(out_path: str) -> set:
    done = set()
    if not os.path.exists(out_path):
        return done

    with open(out_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                key = obj.get("_key")
                if key:
                    done.add(key)
            except Exception:
                continue
    return done


def write_score_json(report_path: str, score_json_path: str) -> None:
    score_items = []

    with open(report_path, "r", encoding="utf-8") as fin:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            analysis = obj.get("analysis") or {}
            score_items.append(
                {
                    "file": obj.get("file"),
                    "func_name": obj.get("func_name"),
                    "line_start": obj.get("line_start"),
                    "line_end": obj.get("line_end"),
                    "baseline": obj.get("baseline"),
                    "risk_level": analysis.get("risk_level"),
                    "risk_score": analysis.get("risk_score"),
                    "confidence": analysis.get("confidence"),
                    "vulnerability_types": analysis.get("vulnerability_types", []),
                }
            )

    avg_score = (
        sum(item["risk_score"] for item in score_items if isinstance(item.get("risk_score"), int)) / len(score_items)
        if score_items
        else 0.0
    )

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_report": report_path,
        "total_functions": len(score_items),
        "average_risk_score": round(avg_score, 2),
        "scores": score_items,
    }

    with open(score_json_path, "w", encoding="utf-8") as fout:
        json.dump(payload, fout, ensure_ascii=False, indent=2)


# ---- 4) Call GPT-4o via Responses API (Structured Outputs) ----
def call_llm(client: OpenAI, model: str, user_prompt: str, max_retries: int = 5) -> RiskResult:
    backoff = 1.0
    last_err = None

    for attempt in range(1, max_retries + 1):
        try:
            resp = client.responses.parse(
                model=model,
                input=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                text_format=RiskResult,
                temperature=DEFAULT_TEMPERATURE,
            )
            result: RiskResult = resp.output_parsed
            return result
        except Exception as e:
            last_err = e
            time.sleep(backoff)
            backoff = min(backoff * 2, 20)

    raise RuntimeError(f"LLM call failed after retries: {last_err}")


# ---- 5) Optional: cheap baseline score (for Top-K prefilter) ----
DANGEROUS_TOKENS = [
    "system(", "gets(", "strcpy(", "sprintf(", "vsprintf(", "scanf(", "sscanf(",
    "memcpy(", "strcat(", "strncpy(", "snprintf(", "malloc(", "free(", "new ", "delete "
]


def baseline_score(code: str) -> int:
    if not code:
        return 0

    s = 0
    lowered = code.lower()

    for t in DANGEROUS_TOKENS:
        if t in lowered:
            s += 15

    if "while(" in lowered or "for(" in lowered:
        s += 5
    if "*" in code and ("char" in lowered or "int" in lowered):
        s += 5

    return min(s, 100)


# ---- 6) Main ----
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", default="functions.jsonl")
    ap.add_argument("--out", dest="out_path", default="risk_report.jsonl")
    ap.add_argument("--model", default="gpt-4o-2024-08-06", help="GPT-4o model id")
    ap.add_argument("--topk", type=int, default=0, help="Only analyze top-k by baseline score (0 = analyze all)")
    ap.add_argument("--git", action="store_true", help="Include git commit messages (file-level) in prompt")
    ap.add_argument("--repo", default=".", help="Path to git repo root (used when --git is set)")
    ap.add_argument("--git-n", type=int, default=20, help="Number of recent commit messages per file")
    ap.add_argument("--resume", action="store_true", help="Resume: skip records already written to out_path")
    ap.add_argument("--score-json", default="", help="Optional path to write score summary as a JSON file")
    args = ap.parse_args()

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY not set in environment", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.in_path):
        print(f"ERROR: input file not found: {args.in_path}", file=sys.stderr)
        sys.exit(1)

    if args.git and not is_git_repo(args.repo):
        print(f"ERROR: --repo is not a git repo: {args.repo}", file=sys.stderr)
        sys.exit(1)

    client = OpenAI(api_key=api_key)

    records = []
    with open(args.in_path, "r", encoding="utf-8") as fin:
        for i, line in enumerate(fin, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                rec["_lineno"] = i
                rec["_baseline"] = baseline_score(rec.get("code", ""))
                rec["_key"] = record_key(rec)
                records.append(rec)
            except json.JSONDecodeError:
                print(f"WARNING: skip invalid JSON at line {i}", file=sys.stderr)

    if args.topk and args.topk > 0:
        records.sort(key=lambda r: r["_baseline"], reverse=True)
        records = records[: args.topk]

    done_keys = load_done_keys(args.out_path) if args.resume else set()
    git_cache: Dict[str, dict] = {}

    mode = "a" if args.resume else "w"
    with open(args.out_path, mode, encoding="utf-8") as fout:
        for idx, rec in enumerate(records, 1):
            if args.resume and rec["_key"] in done_keys:
                continue

            file_path = rec.get("file", "")
            git_ctx = None
            if args.git and file_path:
                if file_path not in git_cache:
                    git_cache[file_path] = get_git_context(args.repo, file_path, args.git_n)
                git_ctx = git_cache[file_path]

            prompt = build_user_prompt(rec, git_ctx)

            print(
                f"[{idx}/{len(records)}] Analyzing {rec.get('func_name')} "
                f"(baseline={rec['_baseline']}) ...",
                end="",
                flush=True,
            )

            try:
                risk = call_llm(client, args.model, prompt)
                out = {
                    **{k: v for k, v in rec.items() if not k.startswith("_")},
                    "_key": rec["_key"],
                    "analysis": risk.model_dump(),
                    "baseline": rec["_baseline"],
                    "prompt_name": PROMPT_NAME,
                    "prompt_version": PROMPT_VERSION,
                }
                if git_ctx is not None:
                    out["git_context"] = git_ctx

                fout.write(json.dumps(out, ensure_ascii=False) + "\n")
                fout.flush()
                print(f" V {risk.risk_level} ({risk.risk_score})")
            except Exception as e:
                print(f" X Failed: {e}", file=sys.stderr)

    if args.score_json:
        write_score_json(args.out_path, args.score_json)
        print(f"Wrote score JSON: {args.score_json}")

    print(f"\nDone. Wrote: {args.out_path}")


if __name__ == "__main__":
    main()
