import argparse
import hashlib
import json
import math
import os
import statistics
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
IMPACT_REVIEW_PROMPT = (
    "Impact consistency review:\n"
    "Your previous answer selected C:N/I:N/A:N, which makes CVSS severity 0.0, "
    "but the function-level proxy factors indicate a plausible root-cause candidate. "
    "Re-evaluate the CVSS impact metrics only through code-grounded reasoning. "
    "If malformed input could plausibly cause crash/DoS, choose at least A:L. "
    "If it could corrupt parser/decompiler state, action dispatch, emitted output, or downstream interpretation, choose at least I:L. "
    "If it could cause out-of-bounds reads or unintended disclosure, choose at least C:L. "
    "Keep C:N/I:N/A:N only if the provided code supports no confidentiality, integrity, or availability impact. "
    "Return ONLY the corrected JSON object matching the schema."
)


def model_supports_temperature(model: str) -> bool:
    normalized = model.lower()
    no_temperature_prefixes = ("gpt-5", "o1", "o3", "o4")
    return not normalized.startswith(no_temperature_prefixes)

# =========================
# LLM 輸出格式定義
# =========================
WeaknessFamily = Literal[
    "memory_safety",
    "integer_size",
    "input_validation_parser",
    "path_file_resource",
    "privilege_access_control",
    "trust_boundary_security_decision",
    "protection_mechanism_failure",
    "race_ordering_toctou",
    "injection_command_execution",
    "crypto_auth_certificate",
    "resource_lifecycle",
    "other_uncertain",
]

OperationSignal = Literal[
    "memory_write",
    "memory_read",
    "pointer_lifetime",
    "size_index_arithmetic",
    "allocation_lifetime",
    "parser_decoder",
    "path_file_resolution",
    "command_execution",
    "privilege_identity_transition",
    "filesystem_namespace_transition",
    "trust_config_lookup",
    "dynamic_code_loading",
    "auth_policy_gate",
    "protection_mechanism_enforcement",
    "crypto_certificate_validation",
    "race_ordering",
    "environment_runtime_context",
    "resource_limit_lifecycle",
    "other_uncertain",
]


class Evidence(BaseModel):
    line: Optional[int] = Field(None, description="Line number if available")
    snippet: str = Field(..., description="Exact code snippet from the source that supports the claim.")


class VulnerabilityType(BaseModel):
    family_id: WeaknessFamily = Field(..., description="Fixed weakness family identifier from the whitelist.")
    name: str = Field(..., description="Short standard weakness name, preferably aligned with CWE naming.")
    cwe_id: Optional[str] = Field(None, description="Optional concrete CWE ID such as CWE-787 when justified by code evidence.")


class LLMFactorResult(BaseModel):
    # 定義function evidence 選 8 個 CVSS v3.1 Base Metrics
    attack_vector: Literal["N", "A", "L", "P"] = Field(..., description="CVSS v3.1 Attack Vector: N/A/L/P.")
    attack_complexity: Literal["L", "H"] = Field(..., description="CVSS v3.1 Attack Complexity: L/H.")
    privileges_required: Literal["N", "L", "H"] = Field(..., description="CVSS v3.1 Privileges Required: N/L/H.")
    user_interaction: Literal["N", "R"] = Field(..., description="CVSS v3.1 User Interaction: N/R.")
    scope: Literal["U", "C"] = Field(..., description="CVSS v3.1 Scope: U/C.")
    confidentiality: Literal["H", "L", "N"] = Field(..., description="CVSS v3.1 Confidentiality impact: H/L/N.")
    integrity: Literal["H", "L", "N"] = Field(..., description="CVSS v3.1 Integrity impact: H/L/N.")
    availability: Literal["H", "L", "N"] = Field(..., description="CVSS v3.1 Availability impact: H/L/N.")
    root_cause_likelihood: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="How likely this function contains or controls the vulnerability root cause (0.0 to 1.0).",
    )
    input_exposure: float = Field(..., ge=0.0, le=1.0, description="How plausibly attacker-controlled, external, file, command, environment, parser-derived, or policy-derived input reaches the function.")
    decision_or_validation_risk: float = Field(..., ge=0.0, le=1.0, description="How strongly the function performs weak validation, semantic acceptance, authorization, policy, trust, or continuation decisions.")
    state_ordering_consistency_risk: float = Field(..., ge=0.0, le=1.0, description="How strongly the function can affect security-sensitive state, ordering, parser progress, length consistency, authority state, namespace state, or check/use ordering.")
    failure_trigger_plausibility: float = Field(..., ge=0.0, le=1.0, description="How plausibly malformed or attacker-controlled input can trigger the suspected failure mode through this function.")
    security_boundary_relevance: float = Field(..., ge=0.0, le=1.0, description="How relevant memory, authority, path, command, trust-boundary, crypto/auth, resource, or protection-boundary behavior is to this function.")
    evidence_strength: float = Field(..., ge=0.0, le=1.0, description="How strong the function-level evidence is, independent of final severity.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence level in this factor assessment (0.0 to 1.0).")
    vulnerability_types: List[VulnerabilityType] = Field(..., description="Structured potential vulnerability categories.")
    weakness_families: List[WeaknessFamily] = Field(..., description="Fixed weakness-family whitelist entries supported by code evidence.")
    operation_signals: List[OperationSignal] = Field(..., description="Fixed security-operation signal categories supported by code evidence.")
    reasons: List[str] = Field(..., min_length=1, description="Concise reasons explaining the selected CVSS factors, proxy factors, root-cause likelihood, and confidence.")
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


def most_common_value(values: List[str]) -> str:
    if not values:
        return ""
    return max(values, key=lambda value: (values.count(value), value))


# 輸出數值四捨五入到小數點後四位
def round_metric(value: float) -> float:
    return round(value, 4)


# ======================================================================
# CVSS v3.1 Base Score 公式，越容易被利用、越不需要前置條件、影響越大，數值越高。
# https://www.first.org/cvss/v3-1/specification-document
# ======================================================================
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

# roundup 是 CVSS v3.1 規定的「無條件進位到小數第一位」
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


GATEKEEPER_BONUS = 0.03
GATEKEEPER_BONUS_GATE_THRESHOLD = 0.7
GATEKEEPER_BONUS_EVIDENCE_THRESHOLD = 0.6

# 對應basline_prompt中的prioritization_rubric，Python 再把這些 factor 加權成 prioritization_score
def compute_prioritization_score(factors: LLMFactorResult, severity_score: float) -> float:
    """
    Function-level ranking score. CVSS severity is only a small supporting signal;
    root-cause locality and observable code proxies drive the ranking.
    """
    score = (
        0.28 * factors.root_cause_likelihood   # 權重最高。因為排名目標是找 root cause，不是找最危險的 API 或最長的 parser function。
        + 0.16 * factors.input_exposure
        + 0.16 * factors.decision_or_validation_risk
        + 0.14 * factors.state_ordering_consistency_risk
        + 0.10 * factors.failure_trigger_plausibility
        + 0.08 * factors.security_boundary_relevance
        + 0.07 * factors.evidence_strength
        + 0.01 * (severity_score / 10.0)
    )
    if (
        factors.decision_or_validation_risk >= GATEKEEPER_BONUS_GATE_THRESHOLD
        and factors.evidence_strength >= GATEKEEPER_BONUS_EVIDENCE_THRESHOLD
    ):
        score += GATEKEEPER_BONUS

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


def has_zero_cvss_impact(factors: LLMFactorResult) -> bool:
    return (
        factors.confidentiality == "N"
        and factors.integrity == "N"
        and factors.availability == "N"
    )


def needs_impact_consistency_review(factors: LLMFactorResult) -> bool:
    if not has_zero_cvss_impact(factors):
        return False

    return (
        factors.root_cause_likelihood >= 0.45
        and factors.evidence_strength >= 0.45
        and (
            factors.security_boundary_relevance >= 0.35
            or factors.decision_or_validation_risk >= 0.45
            or factors.state_ordering_consistency_risk >= 0.45
            or factors.failure_trigger_plausibility >= 0.45
        )
    )


# 從單次 run 的報告檔中擷取重點欄位，輸出一份較精簡的 score summary JSON。
def build_score_payload(report_path: str) -> dict:
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
                "root_cause_likelihood": analysis.get("root_cause_likelihood"),
                "input_exposure": analysis.get("input_exposure"),
                "decision_or_validation_risk": analysis.get("decision_or_validation_risk"),
                "state_ordering_consistency_risk": analysis.get("state_ordering_consistency_risk"),
                "failure_trigger_plausibility": analysis.get("failure_trigger_plausibility"),
                "security_boundary_relevance": analysis.get("security_boundary_relevance"),
                "evidence_strength": analysis.get("evidence_strength"),
                "confidence": analysis.get("confidence"),
                "vulnerability_types": analysis.get("vulnerability_types", []),
                "weakness_families": analysis.get("weakness_families", []),
                "operation_signals": analysis.get("operation_signals", []),
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
    return payload


def write_score_json(report_path: str, score_json_path: str) -> None:
    payload = build_score_payload(report_path)
    write_json(score_json_path, payload)


def parse_llm_factors(client: OpenAI, model: str, messages: List[dict]) -> LLMFactorResult:
    payload = {
        "model": model,
        "input": messages,
        "text_format": LLMFactorResult,
    }
    if model_supports_temperature(model):
        payload["temperature"] = DEFAULT_TEMPERATURE

    try:
        resp = client.responses.parse(**payload)
    except Exception as e:
        if "temperature" not in payload:
            raise
        message = str(e)
        if "Unsupported parameter" not in message or "temperature" not in message:
            raise
        payload.pop("temperature")
        resp = client.responses.parse(**payload)

    return resp.output_parsed


# =========================
# LLM 呼叫
# =========================
def call_llm(client: OpenAI, model: str, user_prompt: str, max_retries: int = 5) -> RiskResult:
    backoff = 1.0
    last_err = None

    for _attempt in range(1, max_retries + 1):
        try:
            factors = parse_llm_factors(
                client,
                model,
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            )
            if needs_impact_consistency_review(factors):
                reviewed_factors = parse_llm_factors(
                    client,
                    model,
                    [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                        {"role": "assistant", "content": factors.model_dump_json()},
                        {"role": "user", "content": IMPACT_REVIEW_PROMPT},
                    ],
                )
                if not has_zero_cvss_impact(reviewed_factors):
                    factors = reviewed_factors
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
def build_output_record(rec: dict, risk: RiskResult, run_idx: int) -> dict:
    out = {
        **{k: v for k, v in rec.items() if not k.startswith("_")},
        "_key": rec["_key"],
        "run_id": run_idx,
        "analysis": risk.model_dump(),
        "baseline": rec["_baseline"],
        "prompt_name": PROMPT_NAME,
        "prompt_version": PROMPT_VERSION,
    }
    return out


# =========================
# 單次 run 分析流程
# =========================
def analyze_single_run(
    client: OpenAI,
    model: str,
    records: List[dict],
    out_path: str,
    resume: bool,
    run_idx: int,
    total_runs: int,
) -> List[dict]:
    done_keys = load_done_keys(out_path) if resume else set()
    mode = "a" if resume else "w"
    run_results: List[dict] = []

    with open(out_path, mode, encoding="utf-8") as fout:
        for idx, rec in enumerate(records, 1):
            if resume and rec["_key"] in done_keys:
                continue

            prompt = build_user_prompt(rec)
            print(
                f"[run {run_idx}/{total_runs}] [{idx}/{len(records)}] "
                f"Analyzing {rec.get('func_name')} (baseline={rec['_baseline']}) ...",
                end="",
                flush=True,
            )

            try:
                risk = call_llm(client, model, prompt)
                out = build_output_record(rec, risk, run_idx)
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
    sortable: List[Tuple[str, float, float, float, float, float]] = []
    for item in entries:
        analysis = item.get("analysis") or {}
        score = analysis.get("prioritization_score")
        if isinstance(score, (int, float)) and not math.isnan(score):
            root_cause_likelihood = analysis.get("root_cause_likelihood")
            decision_or_validation_risk = analysis.get("decision_or_validation_risk")
            severity_score = analysis.get("severity_score")
            confidence = analysis.get("confidence")
            root_value = float(root_cause_likelihood) if isinstance(root_cause_likelihood, (int, float)) else 0.0
            decision_value = float(decision_or_validation_risk) if isinstance(decision_or_validation_risk, (int, float)) else 0.0
            severity_value = float(severity_score) if isinstance(severity_score, (int, float)) else 0.0
            confidence_value = float(confidence) if isinstance(confidence, (int, float)) else 0.0
            sortable.append((item["_key"], float(score), root_value, decision_value, severity_value, confidence_value))

    sortable.sort(key=lambda pair: (-pair[1], -pair[2], -pair[3], -pair[4], -pair[5], pair[0]))
    return {key: index for index, (key, _score, _root, _gatekeeper, _severity, _confidence) in enumerate(sortable, 1)}


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
            "root_cause_likelihoods": [],
            "input_exposures": [],
            "decision_or_validation_risks": [],
            "state_ordering_consistency_risks": [],
            "failure_trigger_plausibilities": [],
            "security_boundary_relevances": [],
            "evidence_strengths": [],
            "confidences": [],
            "cvss_vectors": [],
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
            root_cause_likelihood = analysis.get("root_cause_likelihood")
            if isinstance(root_cause_likelihood, (int, float)) and not math.isnan(root_cause_likelihood):
                by_function[key]["root_cause_likelihoods"].append(float(root_cause_likelihood))
            for field_name, bucket_name in [
                ("input_exposure", "input_exposures"),
                ("decision_or_validation_risk", "decision_or_validation_risks"),
                ("state_ordering_consistency_risk", "state_ordering_consistency_risks"),
                ("failure_trigger_plausibility", "failure_trigger_plausibilities"),
                ("security_boundary_relevance", "security_boundary_relevances"),
            ]:
                value = analysis.get(field_name)
                if isinstance(value, (int, float)) and not math.isnan(value):
                    by_function[key][bucket_name].append(float(value))
            evidence_strength = analysis.get("evidence_strength")
            if isinstance(evidence_strength, (int, float)) and not math.isnan(evidence_strength):
                by_function[key]["evidence_strengths"].append(float(evidence_strength))
            confidence = analysis.get("confidence")
            if isinstance(confidence, (int, float)) and not math.isnan(confidence):
                by_function[key]["confidences"].append(float(confidence))
            cvss_vector = analysis.get("cvss_vector")
            if isinstance(cvss_vector, str) and cvss_vector:
                by_function[key]["cvss_vectors"].append(cvss_vector)
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
        avg_root_cause_likelihood = mean_or_zero(info["root_cause_likelihoods"])
        avg_input_exposure = mean_or_zero(info["input_exposures"])
        avg_decision_or_validation_risk = mean_or_zero(info["decision_or_validation_risks"])
        avg_state_ordering_consistency_risk = mean_or_zero(info["state_ordering_consistency_risks"])
        avg_failure_trigger_plausibility = mean_or_zero(info["failure_trigger_plausibilities"])
        avg_security_boundary_relevance = mean_or_zero(info["security_boundary_relevances"])
        avg_evidence_strength = mean_or_zero(info["evidence_strengths"])
        avg_confidence = mean_or_zero(info["confidences"])
        avg_rank = mean_or_zero(info["ranks"])
        rank_stdev = stdev_or_zero(info["ranks"])
        dominant_cvss_vector = most_common_value(info["cvss_vectors"])

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
                "average_root_cause_likelihood": round_metric(avg_root_cause_likelihood),
                "average_input_exposure": round_metric(avg_input_exposure),
                "average_decision_or_validation_risk": round_metric(avg_decision_or_validation_risk),
                "average_state_ordering_consistency_risk": round_metric(avg_state_ordering_consistency_risk),
                "average_failure_trigger_plausibility": round_metric(avg_failure_trigger_plausibility),
                "average_security_boundary_relevance": round_metric(avg_security_boundary_relevance),
                "average_evidence_strength": round_metric(avg_evidence_strength),
                "average_confidence": round_metric(avg_confidence),
                "average_rank": round_metric(avg_rank),
                "rank_volatility": round_metric(rank_stdev),
                "run_prioritization_scores": [round_metric(v) for v in info["prioritization_scores"]],
                "run_severity_scores": [round_metric(v) for v in info["severity_scores"]],
                "run_scores": [round_metric(v) for v in info["severity_scores"]],
                "run_root_cause_likelihoods": [round_metric(v) for v in info["root_cause_likelihoods"]],
                "run_input_exposures": [round_metric(v) for v in info["input_exposures"]],
                "run_decision_or_validation_risks": [round_metric(v) for v in info["decision_or_validation_risks"]],
                "run_state_ordering_consistency_risks": [round_metric(v) for v in info["state_ordering_consistency_risks"]],
                "run_failure_trigger_plausibilities": [round_metric(v) for v in info["failure_trigger_plausibilities"]],
                "run_security_boundary_relevances": [round_metric(v) for v in info["security_boundary_relevances"]],
                "run_confidences": [round_metric(v) for v in info["confidences"]],
                "run_ranks": [round_metric(v) for v in info["ranks"]],
                "run_cvss_vectors": info["cvss_vectors"],
                "dominant_cvss_vector": dominant_cvss_vector,
                "risk_levels": info["risk_levels"],
            }
        )

    # Ranking uses function-level prioritization first. CVSS severity is a supporting tie-breaker.
    summary_rows.sort(
        key=lambda row: (
            -row["average_prioritization_score"],
            -row["average_root_cause_likelihood"],
            -row["average_decision_or_validation_risk"],
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
        "| Rank | Function | Priority | Priority Stddev | Severity | Root Cause | Input | Decision | State/Ordering | Failure | Boundary | Evidence | Confidence | Avg Rank | Rank Volatility | Completed Runs |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]

    for idx, row in enumerate(payload["functions"], 1):
        function_label = f"{row['func_name']} ({row['line_start']}-{row['line_end']})"
        lines.append(
            f"| {idx} | {function_label} | {row['average_prioritization_score']:.4f} | "
            f"{row['prioritization_score_stddev']:.4f} | {row['average_severity_score']:.4f} | "
            f"{row['average_root_cause_likelihood']:.4f} | {row['average_input_exposure']:.4f} | "
            f"{row['average_decision_or_validation_risk']:.4f} | "
            f"{row['average_state_ordering_consistency_risk']:.4f} | {row['average_failure_trigger_plausibility']:.4f} | "
            f"{row['average_security_boundary_relevance']:.4f} | "
            f"{row['average_evidence_strength']:.4f} | {row['average_confidence']:.4f} | {row['average_rank']:.4f} | "
            f"{row['rank_volatility']:.4f} | {row['runs_completed']}/{row['runs_expected']} |"
        )

    with open(path, "w", encoding="utf-8") as fout:
        fout.write("\n".join(lines) + "\n")


def truncate_text(value: str, max_width: int) -> str:
    if len(value) <= max_width:
        return value
    if max_width <= 3:
        return value[:max_width]
    return value[: max_width - 3] + "..."


def metric(value: object) -> float:
    if isinstance(value, (int, float)) and not math.isnan(value):
        return float(value)
    return 0.0


def cvss_cia_label(vector: str) -> str:
    if not vector:
        return "---"
    parts = {}
    for item in vector.split("/"):
        if ":" in item:
            key, value = item.split(":", 1)
            parts[key] = value
    return f"{parts.get('C', '-')}/{parts.get('I', '-')}/{parts.get('A', '-')}"


def print_single_run_rank_summary(run_results: List[dict]) -> None:
    ranks = assign_ranks(run_results)
    rows = []
    for item in run_results:
        key = item.get("_key")
        analysis = item.get("analysis") or {}
        if key not in ranks:
            continue
        rows.append(
            {
                "rank": ranks[key],
                "func_name": item.get("func_name"),
                "line_start": item.get("line_start"),
                "line_end": item.get("line_end"),
                "priority": metric(analysis.get("prioritization_score")),
                "severity": metric(analysis.get("severity_score")),
                "root": metric(analysis.get("root_cause_likelihood")),
                "input": metric(analysis.get("input_exposure")),
                "decision": metric(analysis.get("decision_or_validation_risk")),
                "state_ordering": metric(analysis.get("state_ordering_consistency_risk")),
                "failure": metric(analysis.get("failure_trigger_plausibility")),
                "boundary": metric(analysis.get("security_boundary_relevance")),
                "evidence": metric(analysis.get("evidence_strength")),
                "confidence": metric(analysis.get("confidence")),
                "vector": analysis.get("cvss_vector") or "",
            }
        )

    rows.sort(key=lambda row: row["rank"])
    if not rows:
        print("\nFinal Ranking Summary: no functions to display.")
        return

    print("\nFinal Ranking Summary")
    print(
        f"{'Rank':>4}  {'Priority':>8}  {'Severity':>8}  {'Root':>6}  {'State':>6}  "
        f"{'Input':>6}  {'Dec':>6}  {'Fail':>6}  {'Bound':>6}  {'Evid':>6}  {'Conf':>6}  {'C/I/A':>5}  Function"
    )
    print(
        f"{'-' * 4}  {'-' * 8}  {'-' * 8}  {'-' * 6}  {'-' * 6}  "
        f"{'-' * 6}  {'-' * 6}  {'-' * 6}  {'-' * 6}  {'-' * 6}  {'-' * 6}  {'-' * 5}  {'-' * 48}"
    )

    for row in rows:
        function_label = f"{row['func_name']} ({row['line_start']}-{row['line_end']})"
        print(
            f"{row['rank']:>4}  {row['priority']:>8.4f}  {row['severity']:>8.4f}  "
            f"{row['root']:>6.4f}  {row['state_ordering']:>6.4f}  {row['input']:>6.4f}  {row['decision']:>6.4f}  "
            f"{row['failure']:>6.4f}  {row['boundary']:>6.4f}  "
            f"{row['evidence']:>6.4f}  {row['confidence']:>6.4f}  "
            f"{cvss_cia_label(row['vector']):>5}  "
            f"{truncate_text(function_label, 48)}"
        )

    print("\nCVSS vectors")
    for row in rows:
        function_label = f"{row['func_name']} ({row['line_start']}-{row['line_end']})"
        print(f"{row['rank']:>4}  {truncate_text(function_label, 48)}  {row['vector']}")


def print_average_rank_summary(payload: dict) -> None:
    rows = sorted(
        payload.get("functions", []),
        key=lambda row: (
            row["average_rank"] if row["average_rank"] else float("inf"),
            -row["average_prioritization_score"],
            -row["average_root_cause_likelihood"],
            -row["average_decision_or_validation_risk"],
            row["func_name"] or "",
        ),
    )

    if not rows:
        print("\nAverage Rank Summary: no functions to display.")
        return

    print("\nAverage Rank Summary (lower avg rank is better)")
    print(
        f"{'Rank':>4}  {'AvgRank':>7}  {'Priority':>8}  {'Severity':>8}  {'Root':>6}  "
        f"{'Input':>6}  {'Dec':>6}  {'State':>6}  {'Fail':>6}  {'Bound':>6}  "
        f"{'Evid':>6}  {'Conf':>6}  {'Vol':>6}  {'Runs':>7}  {'C/I/A':>5}  Function"
    )
    print(
        f"{'-' * 4}  {'-' * 7}  {'-' * 8}  {'-' * 8}  {'-' * 6}  "
        f"{'-' * 6}  {'-' * 6}  {'-' * 6}  {'-' * 6}  {'-' * 6}  "
        f"{'-' * 6}  {'-' * 6}  {'-' * 6}  {'-' * 7}  {'-' * 5}  {'-' * 48}"
    )

    for idx, row in enumerate(rows, 1):
        function_label = f"{row['func_name']} ({row['line_start']}-{row['line_end']})"
        completed_runs = f"{row['runs_completed']}/{row['runs_expected']}"
        print(
            f"{idx:>4}  {row['average_rank']:>7.4f}  "
            f"{row['average_prioritization_score']:>8.4f}  "
            f"{row['average_severity_score']:>8.4f}  "
            f"{row['average_root_cause_likelihood']:>6.4f}  "
            f"{row['average_input_exposure']:>6.4f}  "
            f"{row['average_decision_or_validation_risk']:>6.4f}  "
            f"{row['average_state_ordering_consistency_risk']:>6.4f}  "
            f"{row['average_failure_trigger_plausibility']:>6.4f}  "
            f"{row['average_security_boundary_relevance']:>6.4f}  "
            f"{row['average_evidence_strength']:>6.4f}  "
            f"{row['average_confidence']:>6.4f}  "
            f"{row['rank_volatility']:>6.4f}  {completed_runs:>7}  "
            f"{cvss_cia_label(row.get('dominant_cvss_vector') or ''):>5}  "
            f"{truncate_text(function_label, 48)}"
        )

    print("\nDominant CVSS vectors")
    for idx, row in enumerate(rows, 1):
        function_label = f"{row['func_name']} ({row['line_start']}-{row['line_end']})"
        print(f"{idx:>4}  {truncate_text(function_label, 48)}  {row.get('dominant_cvss_vector') or ''}")


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
    ap.add_argument("--model", default="gpt-4o-2024-08-06", help="OpenAI model id")
    ap.add_argument("--topk", type=int, default=0, help="Only analyze top-k by baseline score (0 = analyze all)")
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
            resume=args.resume,
            run_idx=run_idx,
            total_runs=args.runs,
        )
        all_run_results.extend(run_results)

        if args.runs == 1 and args.score_json:
            write_score_json(out_path, args.score_json)
            print(f"Wrote score JSON: {args.score_json}")

    if args.runs == 1:
        print_single_run_rank_summary(all_run_results)

    # 多次 run 模式下，整合原始結果並做 summary
    if args.runs > 1:
        runs_jsonl_path = os.path.join(out_dir, "runs.jsonl")
        write_runs_jsonl(runs_jsonl_path, all_run_results)
        summary = summarize_runs(records, all_run_results, args.runs, out_dir)
        print_average_rank_summary(summary)
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
