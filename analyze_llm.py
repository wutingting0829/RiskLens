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
from decimal import Decimal, ROUND_CEILING
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


class LLMFactorResult(BaseModel):
    attack_vector: Literal["N", "A", "L", "P"] = Field(..., description="CVSS v3.1 Attack Vector: N/A/L/P.")
    attack_complexity: Literal["L", "H"] = Field(..., description="CVSS v3.1 Attack Complexity: L/H.")
    privileges_required: Literal["N", "L", "H"] = Field(..., description="CVSS v3.1 Privileges Required: N/L/H.")
    user_interaction: Literal["N", "R"] = Field(..., description="CVSS v3.1 User Interaction: N/R.")
    scope: Literal["U", "C"] = Field(..., description="CVSS v3.1 Scope: U/C.")
    confidentiality: Literal["H", "L", "N"] = Field(..., description="CVSS v3.1 Confidentiality impact: H/L/N.")
    integrity: Literal["H", "L", "N"] = Field(..., description="CVSS v3.1 Integrity impact: H/L/N.")
    availability: Literal["H", "L", "N"] = Field(..., description="CVSS v3.1 Availability impact: H/L/N.")
    root_cause_specificity: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="How specifically this function appears to be the vulnerability root-cause candidate (0.0 to 1.0).",
    )
    attacker_control: float = Field(..., ge=0.0, le=1.0, description="How directly attacker-controlled input appears to reach security-sensitive behavior.")
    boundary_crossing: float = Field(..., ge=0.0, le=1.0, description="How strongly the function sits at a trust, parser, privilege, policy, command, or file boundary.")
    input_validation_weakness: float = Field(..., ge=0.0, le=1.0, description="How strongly the function shows missing, weak, or bypassable validation.")
    memory_safety_relevance: float = Field(..., ge=0.0, le=1.0, description="How relevant the function is to memory safety risk.")
    command_or_path_influence: float = Field(..., ge=0.0, le=1.0, description="How strongly the function influences command, path, environment, or executable resolution.")
    parser_state_influence: float = Field(..., ge=0.0, le=1.0, description="How strongly the function influences parser state, tokenization, or state transitions.")
    privilege_or_policy_influence: float = Field(..., ge=0.0, le=1.0, description="How strongly the function influences privilege, authorization, policy, or security decisions.")
    error_handling_relevance: float = Field(..., ge=0.0, le=1.0, description="How relevant error handling in this function is to exploitability or bypass.")
    malformed_input_failure_mode: float = Field(..., ge=0.0, le=1.0, description="How directly malformed input can drive the function into the suspected parser failure mode or vulnerable state transition.")
    parser_state_transition_inconsistency: float = Field(..., ge=0.0, le=1.0, description="How directly the function can create or resolve inconsistent parser state transitions.")
    length_state_mismatch_risk: float = Field(..., ge=0.0, le=1.0, description="How directly the function relates to mismatches between declared length, consumed bytes, remaining bytes, and parser state.")
    parser_progress_manipulation: float = Field(..., ge=0.0, le=1.0, description="How directly the function manipulates parser progress such as cursor advancement, chunk length, remaining length, offsets, or state-machine progress.")
    malformed_chunk_handling_path: float = Field(..., ge=0.0, le=1.0, description="How central the function is to malformed chunk handling or malformed chunked-input edge cases.")
    security_impact_likelihood: float = Field(..., ge=0.0, le=1.0, description="How likely a bug here would have meaningful security impact.")
    evidence_strength: float = Field(..., ge=0.0, le=1.0, description="How strong the function-level evidence is, independent of final severity.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence level in this factor assessment (0.0 to 1.0).")
    vulnerability_types: List[str] = Field(..., description="List of potential vulnerability categories.")
    reasons: List[str] = Field(..., min_length=1, description="Concise reasons explaining the selected factors and root-cause specificity.")
    evidence: List[Evidence] = Field(default_factory=list, description="List of evidence snippets.")


class RiskResult(LLMFactorResult):
    severity_score: float = Field(..., ge=0.0, le=10.0, description="Official CVSS v3.1 Base Score computed from the selected factors.")
    prioritization_score: float = Field(..., ge=0.0, le=1.0, description="Function-level root-cause prioritization score used for ranking.")
    risk_level: Literal["Critical", "High", "Medium", "Low", "None"]
    risk_score: float = Field(..., ge=0.0, le=10.0, description="Alias of severity_score for backward compatibility.")
    cvss_vector: str = Field(..., description="CVSS v3.1 vector string, for example CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H.")
    cvss_iss: float = Field(..., ge=0.0, le=1.0, description="CVSS v3.1 Impact Sub-Score.")
    cvss_impact: float = Field(..., description="CVSS v3.1 Impact component.")
    cvss_exploitability: float = Field(..., description="CVSS v3.1 Exploitability component.")


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


# =========================
# CVSS v3.1 Base Score 公式
# =========================
AV_VALUES = {
    "N": 0.85,
    "A": 0.62,
    "L": 0.55,
    "P": 0.20,
}

AC_VALUES = {
    "L": 0.77,
    "H": 0.44,
}

PR_VALUES = {
    "U": {
        "N": 0.85,
        "L": 0.62,
        "H": 0.27,
    },
    "C": {
        "N": 0.85,
        "L": 0.68,
        "H": 0.50,
    },
}

UI_VALUES = {
    "N": 0.85,
    "R": 0.62,
}

IMPACT_VALUES = {
    "H": 0.56,
    "L": 0.22,
    "N": 0.0,
}


def cvss_roundup(value: float) -> float:
    """
    CVSS v3.1 roundup: round up to one decimal place.
    Decimal avoids floating-point artifacts around tenth boundaries.
    """
    return float(Decimal(str(value)).quantize(Decimal("0.1"), rounding=ROUND_CEILING))


def severity_band(score: float) -> Literal["Critical", "High", "Medium", "Low", "None"]:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def build_cvss_vector(factors: LLMFactorResult) -> str:
    return (
        "CVSS:3.1/"
        f"AV:{factors.attack_vector}/"
        f"AC:{factors.attack_complexity}/"
        f"PR:{factors.privileges_required}/"
        f"UI:{factors.user_interaction}/"
        f"S:{factors.scope}/"
        f"C:{factors.confidentiality}/"
        f"I:{factors.integrity}/"
        f"A:{factors.availability}"
    )


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def compute_prioritization_score(factors: LLMFactorResult, severity_score: float) -> float:
    """
    Function-level ranking score. CVSS severity is only a small supporting signal;
    root-cause locality and observable code proxies drive the ranking.
    """
    score = (
        0.28 * factors.root_cause_specificity
        + 0.16 * factors.parser_state_transition_inconsistency
        + 0.13 * factors.length_state_mismatch_risk
        + 0.12 * factors.parser_progress_manipulation
        + 0.10 * factors.malformed_chunk_handling_path
        + 0.08 * factors.malformed_input_failure_mode
        + 0.04 * factors.parser_state_influence
        + 0.03 * factors.security_impact_likelihood
        + 0.02 * factors.attacker_control
        + 0.01 * factors.input_validation_weakness
        + 0.02 * factors.evidence_strength
        + 0.01 * (severity_score / 10.0)
    )
    return round_metric(clamp01(score))


def compute_cvss_result(factors: LLMFactorResult) -> RiskResult:
    av = AV_VALUES[factors.attack_vector]
    ac = AC_VALUES[factors.attack_complexity]
    pr = PR_VALUES[factors.scope][factors.privileges_required]
    ui = UI_VALUES[factors.user_interaction]
    c = IMPACT_VALUES[factors.confidentiality]
    i = IMPACT_VALUES[factors.integrity]
    a = IMPACT_VALUES[factors.availability]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if factors.scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        severity_score = 0.0
    elif factors.scope == "U":
        severity_score = cvss_roundup(min(impact + exploitability, 10))
    else:
        severity_score = cvss_roundup(min(1.08 * (impact + exploitability), 10))

    prioritization_score = compute_prioritization_score(factors, severity_score)

    payload = factors.model_dump()
    payload.update(
        {
            "severity_score": severity_score,
            "prioritization_score": prioritization_score,
            "risk_score": severity_score,
            "risk_level": severity_band(severity_score),
            "cvss_vector": build_cvss_vector(factors),
            "cvss_iss": round_metric(iss),
            "cvss_impact": round_metric(impact),
            "cvss_exploitability": round_metric(exploitability),
        }
    )
    return RiskResult(**payload)


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
                "prioritization_score": analysis.get("prioritization_score"),
                "severity_score": analysis.get("severity_score"),
                "risk_score": analysis.get("risk_score"),
                "cvss_vector": analysis.get("cvss_vector"),
                "root_cause_specificity": analysis.get("root_cause_specificity"),
                "malformed_input_failure_mode": analysis.get("malformed_input_failure_mode"),
                "parser_state_transition_inconsistency": analysis.get("parser_state_transition_inconsistency"),
                "length_state_mismatch_risk": analysis.get("length_state_mismatch_risk"),
                "parser_progress_manipulation": analysis.get("parser_progress_manipulation"),
                "malformed_chunk_handling_path": analysis.get("malformed_chunk_handling_path"),
                "attacker_control": analysis.get("attacker_control"),
                "input_validation_weakness": analysis.get("input_validation_weakness"),
                "security_impact_likelihood": analysis.get("security_impact_likelihood"),
                "evidence_strength": analysis.get("evidence_strength"),
                "confidence": analysis.get("confidence"),
                "vulnerability_types": analysis.get("vulnerability_types", []),
            }
        )

    avg_priority = mean_or_zero(
        [
            item["prioritization_score"]
            for item in score_items
            if isinstance(item.get("prioritization_score"), (int, float))
        ]
    )
    avg_severity = mean_or_zero(
        [
            item["severity_score"]
            for item in score_items
            if isinstance(item.get("severity_score"), (int, float))
        ]
    )

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_report": report_path,
        "total_functions": len(score_items),
        "average_prioritization_score": round(avg_priority, 4),
        "average_severity_score": round(avg_severity, 2),
        "average_risk_score": round(avg_severity, 2),
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
                text_format=LLMFactorResult,
                temperature=DEFAULT_TEMPERATURE,
            )
            factors: LLMFactorResult = resp.output_parsed
            return compute_cvss_result(factors)
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
                print(f" V P={risk.prioritization_score} CVSS={risk.severity_score} {risk.risk_level}")
            except Exception as e:
                print(f" X Failed: {e}", file=sys.stderr)

    if resume:
        return read_jsonl(out_path)
    return run_results


# =========================
# 排名 / 多 run 彙整
# ========================
def assign_ranks(entries: List[dict]) -> Dict[str, int]:
    sortable: List[Tuple[str, float, float, float, float]] = []
    for item in entries:
        analysis = item.get("analysis") or {}
        score = analysis.get("prioritization_score")
        if isinstance(score, (int, float)) and not math.isnan(score):
            root_cause_specificity = analysis.get("root_cause_specificity")
            severity_score = analysis.get("severity_score")
            confidence = analysis.get("confidence")
            root_value = float(root_cause_specificity) if isinstance(root_cause_specificity, (int, float)) else 0.0
            severity_value = float(severity_score) if isinstance(severity_score, (int, float)) else 0.0
            confidence_value = float(confidence) if isinstance(confidence, (int, float)) else 0.0
            sortable.append((item["_key"], float(score), root_value, severity_value, confidence_value))

    sortable.sort(key=lambda pair: (-pair[1], -pair[2], -pair[3], -pair[4], pair[0]))
    return {key: index for index, (key, _score, _root, _severity, _confidence) in enumerate(sortable, 1)}


def write_runs_jsonl(runs_jsonl_path: str, all_run_results: List[dict]) -> None:
    with open(runs_jsonl_path, "w", encoding="utf-8") as fout:
        for item in all_run_results:
            fout.write(json.dumps(item, ensure_ascii=False) + "\n")


def summarize_runs(records: List[dict], all_run_results: List[dict], runs: int, out_dir: str) -> dict:
    """
    針對多次 runs 做統計彙整，輸出：
    - 每個 function 的平均 prioritization score
    - 平均 CVSS severity score
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
            "prioritization_scores": [],
            "severity_scores": [],
            "root_cause_specificities": [],
            "malformed_input_failure_modes": [],
            "parser_state_transition_inconsistencies": [],
            "length_state_mismatch_risks": [],
            "parser_progress_manipulations": [],
            "malformed_chunk_handling_paths": [],
            "attacker_controls": [],
            "input_validation_weaknesses": [],
            "security_impact_likelihoods": [],
            "evidence_strengths": [],
            "confidences": [],
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
            prioritization_score = analysis.get("prioritization_score")
            if isinstance(prioritization_score, (int, float)) and not math.isnan(prioritization_score):
                by_function[key]["prioritization_scores"].append(float(prioritization_score))
            severity_score = analysis.get("severity_score")
            if isinstance(severity_score, (int, float)) and not math.isnan(severity_score):
                by_function[key]["severity_scores"].append(float(severity_score))
            root_cause_specificity = analysis.get("root_cause_specificity")
            if isinstance(root_cause_specificity, (int, float)) and not math.isnan(root_cause_specificity):
                by_function[key]["root_cause_specificities"].append(float(root_cause_specificity))
            malformed_input_failure_mode = analysis.get("malformed_input_failure_mode")
            if isinstance(malformed_input_failure_mode, (int, float)) and not math.isnan(malformed_input_failure_mode):
                by_function[key]["malformed_input_failure_modes"].append(float(malformed_input_failure_mode))
            parser_state_transition_inconsistency = analysis.get("parser_state_transition_inconsistency")
            if isinstance(parser_state_transition_inconsistency, (int, float)) and not math.isnan(parser_state_transition_inconsistency):
                by_function[key]["parser_state_transition_inconsistencies"].append(float(parser_state_transition_inconsistency))
            length_state_mismatch_risk = analysis.get("length_state_mismatch_risk")
            if isinstance(length_state_mismatch_risk, (int, float)) and not math.isnan(length_state_mismatch_risk):
                by_function[key]["length_state_mismatch_risks"].append(float(length_state_mismatch_risk))
            parser_progress_manipulation = analysis.get("parser_progress_manipulation")
            if isinstance(parser_progress_manipulation, (int, float)) and not math.isnan(parser_progress_manipulation):
                by_function[key]["parser_progress_manipulations"].append(float(parser_progress_manipulation))
            malformed_chunk_handling_path = analysis.get("malformed_chunk_handling_path")
            if isinstance(malformed_chunk_handling_path, (int, float)) and not math.isnan(malformed_chunk_handling_path):
                by_function[key]["malformed_chunk_handling_paths"].append(float(malformed_chunk_handling_path))
            attacker_control = analysis.get("attacker_control")
            if isinstance(attacker_control, (int, float)) and not math.isnan(attacker_control):
                by_function[key]["attacker_controls"].append(float(attacker_control))
            input_validation_weakness = analysis.get("input_validation_weakness")
            if isinstance(input_validation_weakness, (int, float)) and not math.isnan(input_validation_weakness):
                by_function[key]["input_validation_weaknesses"].append(float(input_validation_weakness))
            security_impact_likelihood = analysis.get("security_impact_likelihood")
            if isinstance(security_impact_likelihood, (int, float)) and not math.isnan(security_impact_likelihood):
                by_function[key]["security_impact_likelihoods"].append(float(security_impact_likelihood))
            evidence_strength = analysis.get("evidence_strength")
            if isinstance(evidence_strength, (int, float)) and not math.isnan(evidence_strength):
                by_function[key]["evidence_strengths"].append(float(evidence_strength))
            confidence = analysis.get("confidence")
            if isinstance(confidence, (int, float)) and not math.isnan(confidence):
                by_function[key]["confidences"].append(float(confidence))
            if key in ranks:
                by_function[key]["ranks"].append(float(ranks[key]))
            by_function[key]["risk_levels"].append(analysis.get("risk_level"))
            by_function[key]["runs_present"].append(run_id)

    summary_rows = []
    for key, info in by_function.items():
        rec = info["record"]
        avg_priority = mean_or_zero(info["prioritization_scores"])
        priority_stdev = stdev_or_zero(info["prioritization_scores"])
        avg_severity = mean_or_zero(info["severity_scores"])
        severity_stdev = stdev_or_zero(info["severity_scores"])
        avg_root_cause_specificity = mean_or_zero(info["root_cause_specificities"])
        avg_malformed_input_failure_mode = mean_or_zero(info["malformed_input_failure_modes"])
        avg_parser_state_transition_inconsistency = mean_or_zero(info["parser_state_transition_inconsistencies"])
        avg_length_state_mismatch_risk = mean_or_zero(info["length_state_mismatch_risks"])
        avg_parser_progress_manipulation = mean_or_zero(info["parser_progress_manipulations"])
        avg_malformed_chunk_handling_path = mean_or_zero(info["malformed_chunk_handling_paths"])
        avg_attacker_control = mean_or_zero(info["attacker_controls"])
        avg_input_validation_weakness = mean_or_zero(info["input_validation_weaknesses"])
        avg_security_impact_likelihood = mean_or_zero(info["security_impact_likelihoods"])
        avg_evidence_strength = mean_or_zero(info["evidence_strengths"])
        avg_confidence = mean_or_zero(info["confidences"])
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
                "average_prioritization_score": round_metric(avg_priority),
                "prioritization_score_stddev": round_metric(priority_stdev),
                "average_severity_score": round_metric(avg_severity),
                "severity_score_stddev": round_metric(severity_stdev),
                "average_risk_score": round_metric(avg_severity),
                "risk_score_stddev": round_metric(severity_stdev),
                "average_root_cause_specificity": round_metric(avg_root_cause_specificity),
                "average_malformed_input_failure_mode": round_metric(avg_malformed_input_failure_mode),
                "average_parser_state_transition_inconsistency": round_metric(avg_parser_state_transition_inconsistency),
                "average_length_state_mismatch_risk": round_metric(avg_length_state_mismatch_risk),
                "average_parser_progress_manipulation": round_metric(avg_parser_progress_manipulation),
                "average_malformed_chunk_handling_path": round_metric(avg_malformed_chunk_handling_path),
                "average_attacker_control": round_metric(avg_attacker_control),
                "average_input_validation_weakness": round_metric(avg_input_validation_weakness),
                "average_security_impact_likelihood": round_metric(avg_security_impact_likelihood),
                "average_evidence_strength": round_metric(avg_evidence_strength),
                "average_confidence": round_metric(avg_confidence),
                "average_rank": round_metric(avg_rank),
                "rank_volatility": round_metric(rank_stdev),
                "run_prioritization_scores": [round_metric(v) for v in info["prioritization_scores"]],
                "run_severity_scores": [round_metric(v) for v in info["severity_scores"]],
                "run_scores": [round_metric(v) for v in info["severity_scores"]],
                "run_root_cause_specificities": [round_metric(v) for v in info["root_cause_specificities"]],
                "run_malformed_input_failure_modes": [round_metric(v) for v in info["malformed_input_failure_modes"]],
                "run_parser_state_transition_inconsistencies": [round_metric(v) for v in info["parser_state_transition_inconsistencies"]],
                "run_length_state_mismatch_risks": [round_metric(v) for v in info["length_state_mismatch_risks"]],
                "run_parser_progress_manipulations": [round_metric(v) for v in info["parser_progress_manipulations"]],
                "run_malformed_chunk_handling_paths": [round_metric(v) for v in info["malformed_chunk_handling_paths"]],
                "run_confidences": [round_metric(v) for v in info["confidences"]],
                "run_ranks": [round_metric(v) for v in info["ranks"]],
                "risk_levels": info["risk_levels"],
            }
        )

    # Ranking uses function-level prioritization first. CVSS severity is a supporting tie-breaker.
    summary_rows.sort(
        key=lambda row: (
            -row["average_prioritization_score"],
            -row["average_root_cause_specificity"],
            -row["average_severity_score"],
            -row["average_confidence"],
            row["average_rank"] if row["average_rank"] else float("inf"),
            row["func_name"] or "",
        )
    )

    overall_avg_priority = mean_or_zero([row["average_prioritization_score"] for row in summary_rows])
    overall_avg_severity = mean_or_zero([row["average_severity_score"] for row in summary_rows])
    overall_rank_volatility = mean_or_zero([row["rank_volatility"] for row in summary_rows])

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runs": runs,
        "total_functions": len(summary_rows),
        "overall_average_prioritization_score": round_metric(overall_avg_priority),
        "overall_average_severity_score": round_metric(overall_avg_severity),
        "overall_average_risk_score": round_metric(overall_avg_severity),
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
        f"- Overall average prioritization score: {payload['overall_average_prioritization_score']}",
        f"- Overall average severity score: {payload['overall_average_severity_score']}",
        f"- Overall average rank volatility: {payload['overall_average_rank_volatility']}",
        "",
        "| Rank | Function | Priority | Priority Stddev | Severity | Root Cause | State Inconsist | Len/State Mismatch | Progress | Chunk Path | Malformed Failure | Evidence | Confidence | Avg Rank | Rank Volatility | Completed Runs |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]

    for idx, row in enumerate(payload["functions"], 1):
        function_label = f"{row['func_name']} ({row['line_start']}-{row['line_end']})"
        lines.append(
            f"| {idx} | {function_label} | {row['average_prioritization_score']:.4f} | "
            f"{row['prioritization_score_stddev']:.4f} | {row['average_severity_score']:.4f} | "
            f"{row['average_root_cause_specificity']:.4f} | {row['average_parser_state_transition_inconsistency']:.4f} | "
            f"{row['average_length_state_mismatch_risk']:.4f} | {row['average_parser_progress_manipulation']:.4f} | "
            f"{row['average_malformed_chunk_handling_path']:.4f} | {row['average_malformed_input_failure_mode']:.4f} | "
            f"{row['average_evidence_strength']:.4f} | {row['average_confidence']:.4f} | {row['average_rank']:.4f} | "
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
