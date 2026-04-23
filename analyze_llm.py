import argparse
import hashlib
import json
import math
import os
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Literal, Optional, Tuple

from openai import OpenAI
from pydantic import BaseModel, Field

from prompts import (
    PROMPT_NAME,
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    build_user_prompt,
)

DEFAULT_TEMPERATURE = 0

# =========================
# LLM 輸出格式定義
# =========================
class Evidence(BaseModel):
    line: Optional[int] = Field(None, description="Line number if available")
    snippet: str = Field(..., description="Exact code snippet from the source that supports the claim.")


class RiskResult(BaseModel):
    risk_level: Literal["Critical", "High", "Medium", "Low", "None"]
    risk_score: float = Field(..., ge=0.0, le=10.0, description="Estimated CVSS v3.1 Base Score from 0.0 to 10.0.")
    cvss_vector: str = Field(..., description="Estimated CVSS v3.1 vector string, for example CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H.")
    vulnerability_types: List[str] = Field(..., description="List of potential vulnerability categories.")
    reasons: List[str] = Field(..., min_length=1, description="Concise reasons explaining why this risk score was assigned.")
    evidence: List[Evidence] = Field(default_factory=list, description="List of evidence snippets.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence level in this assessment (0.0 to 1.0).")


# =========================
# Git 相關工具
# =========================
def is_git_repo(path: str) -> bool:
    return os.path.isdir(os.path.join(path, ".git"))


def get_git_context(repo: str, file_path: str, n: int) -> dict:
    """
    取得某個檔案最近 n 筆 commit message（只抓 subject）。
    這些訊息可作為額外上下文提供給 LLM。
    """
    rel = os.path.relpath(file_path, repo)
    cmd = ["git", "-C", repo, "log", f"-n{n}", "--pretty=format:%s", "--", rel]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return {"commit_count": 0, "recent_messages": []}

    msgs = [line.strip() for line in out.splitlines() if line.strip()]
    return {"commit_count": len(msgs), "recent_messages": msgs[:n]}

# =========================
# Record / JSONL 工具
# =========================
# File + func_name + line range + code hash
def record_key(rec: dict) -> str:
    h = hashlib.sha256((rec.get("code") or "").encode("utf-8")).hexdigest()[:16]
    return f"{rec.get('file','')}::{rec.get('func_name','')}::{rec.get('line_start','?')}-{rec.get('line_end','?')}::{h}"


def load_done_keys(out_path: str) -> set:
    """
    讀取既有輸出檔中的 _key，供 --resume 模式跳過已完成項目。
    """
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
            except Exception:
                continue
            key = obj.get("_key")
            if key:
                done.add(key)
    return done


def read_jsonl(path: str) -> List[dict]:
    items = []
    with open(path, "r", encoding="utf-8") as fin:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return items


def write_json(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as fout:
        json.dump(payload, fout, ensure_ascii=False, indent=2)


# =========================
# 統計工具
# =========================
def mean_or_zero(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


# 標準差
def stdev_or_zero(values: List[float]) -> float:
    if len(values) <= 1:
        return 0.0
    return statistics.stdev(values)

# 輸出數值四捨五入到小數點後四位
def round_metric(value: float) -> float:
    return round(value, 4)

# 從單次 run 的報告檔中擷取重點欄位，輸出一份較精簡的 score summary JSON。
def write_score_json(report_path: str, score_json_path: str) -> None:
    score_items = []

    for obj in read_jsonl(report_path):
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
                "cvss_vector": analysis.get("cvss_vector"),
                "confidence": analysis.get("confidence"),
                "vulnerability_types": analysis.get("vulnerability_types", []),
            }
        )

    avg_score = mean_or_zero(
        [item["risk_score"] for item in score_items if isinstance(item.get("risk_score"), (int, float))]
    )

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_report": report_path,
        "total_functions": len(score_items),
        "average_risk_score": round(avg_score, 2),
        "scores": score_items,
    }
    write_json(score_json_path, payload)

# =========================
# LLM 呼叫
# =========================
def call_llm(client: OpenAI, model: str, user_prompt: str, max_retries: int = 5) -> RiskResult:
    backoff = 1.0
    last_err = None

    for _attempt in range(1, max_retries + 1):
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



# =========================
# Baseline heuristic
# =========================
# 簡單的高風險 token 清單；只是一個粗略 heuristic，不代表真的有漏洞
DANGEROUS_TOKENS = [
    "system(", "gets(", "strcpy(", "sprintf(", "vsprintf(", "scanf(", "sscanf(",
    "memcpy(", "strcat(", "strncpy(", "snprintf(", "malloc(", "free(", "new ", "delete ",
]


def baseline_score(code: str) -> int:
    if not code:
        return 0

    s = 0
    lowered = code.lower()

    for token in DANGEROUS_TOKENS:
        if token in lowered:
            s += 15

    if "while(" in lowered or "for(" in lowered:
        s += 5
    if "*" in code and ("char" in lowered or "int" in lowered):
        s += 5

    return min(s, 100)


def load_records(in_path: str, topk: int) -> List[dict]:
    """
    讀取輸入 JSONL（每行一個 function record），並為每筆補上：
    - _lineno: 原始 JSONL 行號
    - _baseline: baseline heuristic 分數
    - _key: 唯一識別碼
    若指定 topk，則只保留 baseline 分數最高的前 k 筆。
    """
    records = []
    with open(in_path, "r", encoding="utf-8") as fin:
        for lineno, line in enumerate(fin, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                print(f"WARNING: skip invalid JSON at line {lineno}", file=sys.stderr)
                continue

            rec["_lineno"] = lineno
            rec["_baseline"] = baseline_score(rec.get("code", ""))
            rec["_key"] = record_key(rec)
            records.append(rec)

    if topk and topk > 0:
        records.sort(key=lambda item: item["_baseline"], reverse=True)
        return records[:topk]
    return records

# =========================
# 輸出路徑相關
# =========================
# 決定輸出資料夾
def get_output_dir(args: argparse.Namespace) -> str:
    if args.out_dir:
        return args.out_dir

    out_base = os.path.splitext(args.out_path)[0]
    if args.runs > 1:
        return f"{out_base}_runs"
    return os.path.dirname(args.out_path) or "."

# 決定每次 run 的輸出檔名
def run_report_path(out_dir: str, run_idx: int, total_runs: int, default_out_path: str) -> str:
    if total_runs == 1:
        filename = os.path.basename(default_out_path)
    else:
        filename = f"run_{run_idx:03d}.jsonl"
    return os.path.join(out_dir, filename)

# 把原始 function record 與 LLM 分析結果合併成最終輸出格式。
def build_output_record(rec: dict, risk: RiskResult, git_ctx: Optional[dict], run_idx: int) -> dict:
    out = {
        **{k: v for k, v in rec.items() if not k.startswith("_")},
        "_key": rec["_key"],
        "run_id": run_idx,
        "analysis": risk.model_dump(),
        "baseline": rec["_baseline"],
        "prompt_name": PROMPT_NAME,
        "prompt_version": PROMPT_VERSION,
    }
    if git_ctx is not None:
        out["git_context"] = git_ctx
    return out


# =========================
# 單次 run 分析流程
# =========================
def analyze_single_run(
    client: OpenAI,
    model: str,
    records: List[dict],
    out_path: str,
    git_enabled: bool,
    repo: str,
    git_n: int,
    resume: bool,
    run_idx: int,
    total_runs: int,
) -> List[dict]:
    done_keys = load_done_keys(out_path) if resume else set()
    git_cache: Dict[str, dict] = {}
    mode = "a" if resume else "w"
    run_results: List[dict] = []

    with open(out_path, mode, encoding="utf-8") as fout:
        for idx, rec in enumerate(records, 1):
            if resume and rec["_key"] in done_keys:
                continue

            file_path = rec.get("file", "")
            git_ctx = None
            if git_enabled and file_path:
                if file_path not in git_cache:
                    git_cache[file_path] = get_git_context(repo, file_path, git_n)
                git_ctx = git_cache[file_path]

            prompt = build_user_prompt(rec, git_ctx)
            print(
                f"[run {run_idx}/{total_runs}] [{idx}/{len(records)}] "
                f"Analyzing {rec.get('func_name')} (baseline={rec['_baseline']}) ...",
                end="",
                flush=True,
            )

            try:
                risk = call_llm(client, model, prompt)
                out = build_output_record(rec, risk, git_ctx, run_idx)
                fout.write(json.dumps(out, ensure_ascii=False) + "\n")
                fout.flush()
                run_results.append(out)
                print(f" V {risk.risk_level} ({risk.risk_score})")
            except Exception as e:
                print(f" X Failed: {e}", file=sys.stderr)

    if resume:
        return read_jsonl(out_path)
    return run_results


# =========================
# 排名 / 多 run 彙整
# ========================
def assign_ranks(entries: List[dict]) -> Dict[str, int]:
    sortable: List[Tuple[str, float]] = []
    for item in entries:
        analysis = item.get("analysis") or {}
        score = analysis.get("risk_score")
        if isinstance(score, (int, float)) and not math.isnan(score):
            sortable.append((item["_key"], float(score)))

    sortable.sort(key=lambda pair: (-pair[1], pair[0]))
    return {key: index for index, (key, _score) in enumerate(sortable, 1)}


def write_runs_jsonl(runs_jsonl_path: str, all_run_results: List[dict]) -> None:
    with open(runs_jsonl_path, "w", encoding="utf-8") as fout:
        for item in all_run_results:
            fout.write(json.dumps(item, ensure_ascii=False) + "\n")


def summarize_runs(records: List[dict], all_run_results: List[dict], runs: int, out_dir: str) -> dict:
    """
    針對多次 runs 做統計彙整，輸出：
    - 每個 function 的平均風險分數
    - 分數標準差
    - 平均排名
    - 排名波動（stddev）
    - 各 run 的分數與排名
    """
    by_key = {rec["_key"]: rec for rec in records}

    # 每個 function 準備一個容器收集所有 run 的結果
    by_function: Dict[str, dict] = {
        key: {
            "record": rec,
            "scores": [],
            "ranks": [],
            "risk_levels": [],
            "runs_present": [],
        }
        for key, rec in by_key.items()
    }

    # 先依 run_id 分組
    grouped_by_run: Dict[int, List[dict]] = {}
    for item in all_run_results:
        grouped_by_run.setdefault(item["run_id"], []).append(item)

    # run by run 地收集分數與排名
    for run_id, items in grouped_by_run.items():
        ranks = assign_ranks(items)
        for item in items:
            key = item["_key"]
            analysis = item.get("analysis") or {}
            score = analysis.get("risk_score")
            if isinstance(score, (int, float)) and not math.isnan(score):
                by_function[key]["scores"].append(float(score))
            if key in ranks:
                by_function[key]["ranks"].append(float(ranks[key]))
            by_function[key]["risk_levels"].append(analysis.get("risk_level"))
            by_function[key]["runs_present"].append(run_id)

    summary_rows = []
    for key, info in by_function.items():
        rec = info["record"]
        avg_score = mean_or_zero(info["scores"])
        score_stdev = stdev_or_zero(info["scores"])
        avg_rank = mean_or_zero(info["ranks"])
        rank_stdev = stdev_or_zero(info["ranks"])

        summary_rows.append(
            {
                "_key": key,
                "file": rec.get("file"),
                "func_name": rec.get("func_name"),
                "line_start": rec.get("line_start"),
                "line_end": rec.get("line_end"),
                "baseline": rec.get("_baseline"),
                "runs_expected": runs,
                "runs_completed": len(info["runs_present"]),
                "average_risk_score": round_metric(avg_score),
                "risk_score_stddev": round_metric(score_stdev),
                "average_rank": round_metric(avg_rank),
                "rank_volatility": round_metric(rank_stdev),
                "run_scores": [round_metric(v) for v in info["scores"]],
                "run_ranks": [round_metric(v) for v in info["ranks"]],
                "risk_levels": info["risk_levels"],
            }
        )

    # 先照平均風險分數高到低排序；若同分，再看平均排名；再同則看函式名 
    summary_rows.sort(
        key=lambda row: (
            -row["average_risk_score"],
            row["average_rank"] if row["average_rank"] else float("inf"),
            row["func_name"] or "",
        )
    )

    overall_avg = mean_or_zero([row["average_risk_score"] for row in summary_rows])
    overall_rank_volatility = mean_or_zero([row["rank_volatility"] for row in summary_rows])

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runs": runs,
        "total_functions": len(summary_rows),
        "overall_average_risk_score": round_metric(overall_avg),
        "overall_average_rank_volatility": round_metric(overall_rank_volatility),
        "functions": summary_rows,
    }

    write_json(os.path.join(out_dir, "baseline_summary.json"), payload)
    write_baseline_summary_table(os.path.join(out_dir, "baseline_summary.md"), payload)
    return payload


# 生成 markdown summary table
def write_baseline_summary_table(path: str, payload: dict) -> None:
    lines = [
        "# Baseline Summary",
        "",
        f"- Generated at: {payload['generated_at']}",
        f"- Runs: {payload['runs']}",
        f"- Total functions: {payload['total_functions']}",
        f"- Overall average risk score: {payload['overall_average_risk_score']}",
        f"- Overall average rank volatility: {payload['overall_average_rank_volatility']}",
        "",
        "| Rank | Function | Avg Score | Score Stddev | Avg Rank | Rank Volatility | Completed Runs |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]

    for idx, row in enumerate(payload["functions"], 1):
        function_label = f"{row['func_name']} ({row['line_start']}-{row['line_end']})"
        lines.append(
            f"| {idx} | {function_label} | {row['average_risk_score']:.4f} | "
            f"{row['risk_score_stddev']:.4f} | {row['average_rank']:.4f} | "
            f"{row['rank_volatility']:.4f} | {row['runs_completed']}/{row['runs_expected']} |"
        )

    with open(path, "w", encoding="utf-8") as fout:
        fout.write("\n".join(lines) + "\n")


# =========================
# 參數驗證
# =========================
def validate_args(args: argparse.Namespace) -> None:
    if args.runs < 1:
        print("ERROR: --runs must be >= 1", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.in_path):
        print(f"ERROR: input file not found: {args.in_path}", file=sys.stderr)
        sys.exit(1)

    if args.git and not is_git_repo(args.repo):
        print(f"ERROR: --repo is not a git repo: {args.repo}", file=sys.stderr)
        sys.exit(1)

    if args.resume and args.runs > 1:
        print("ERROR: --resume is only supported for single-run mode", file=sys.stderr)
        sys.exit(1)


# =========================
# main function
# =========================
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", default="functions.jsonl")
    ap.add_argument("--out", dest="out_path", default="risk_report.jsonl")
    ap.add_argument("--out-dir", default="", help="Output directory for multi-run artifacts")
    ap.add_argument("--model", default="gpt-4o-2024-08-06", help="GPT-4o model id")
    ap.add_argument("--topk", type=int, default=0, help="Only analyze top-k by baseline score (0 = analyze all)")
    ap.add_argument("--git", action="store_true", help="Include git commit messages (file-level) in prompt")
    ap.add_argument("--repo", default=".", help="Path to git repo root (used when --git is set)")
    ap.add_argument("--git-n", type=int, default=20, help="Number of recent commit messages per file")
    ap.add_argument("--resume", action="store_true", help="Resume: skip records already written to out_path")
    ap.add_argument("--score-json", default="", help="Optional path to write score summary as a JSON file")
    ap.add_argument("--runs", type=int, default=1, help="Number of repeated runs for the same batch")
    args = ap.parse_args()

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY not set in environment", file=sys.stderr)
        sys.exit(1)

    validate_args(args)
    records = load_records(args.in_path, args.topk)
    client = OpenAI(api_key=api_key)

    out_dir = get_output_dir(args)
    os.makedirs(out_dir, exist_ok=True)

    all_run_results: List[dict] = []
    # 主迴圈：重複跑多次同一批 function
    for run_idx in range(1, args.runs + 1):
        out_path = run_report_path(out_dir, run_idx, args.runs, args.out_path)
        run_results = analyze_single_run(
            client=client,
            model=args.model,
            records=records,
            out_path=out_path,
            git_enabled=args.git,
            repo=args.repo,
            git_n=args.git_n,
            resume=args.resume,
            run_idx=run_idx,
            total_runs=args.runs,
        )
        all_run_results.extend(run_results)

        if args.runs == 1 and args.score_json:
            write_score_json(out_path, args.score_json)
            print(f"Wrote score JSON: {args.score_json}")

    # 多次 run 模式下，整合原始結果並做 summary
    if args.runs > 1:
        runs_jsonl_path = os.path.join(out_dir, "runs.jsonl")
        write_runs_jsonl(runs_jsonl_path, all_run_results)
        summary = summarize_runs(records, all_run_results, args.runs, out_dir)
        print(f"Wrote runs JSONL: {runs_jsonl_path}")
        print(f"Wrote baseline summary JSON: {os.path.join(out_dir, 'baseline_summary.json')}")
        print(f"Wrote baseline summary table: {os.path.join(out_dir, 'baseline_summary.md')}")
        
        # 若有指定 --score-json，就把 aggregate summary 也輸出一份
        if args.score_json:
            write_json(args.score_json, summary)
            print(f"Wrote aggregate summary JSON: {args.score_json}")

    final_target = os.path.join(out_dir, "runs.jsonl") if args.runs > 1 else run_report_path(out_dir, 1, 1, args.out_path)
    print(f"\nDone. Wrote: {final_target}")


if __name__ == "__main__":
    main()
