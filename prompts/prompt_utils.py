from typing import Optional


def normalize_code(code: Optional[str]) -> str:
    code = (code or "").strip()
    return code if code else "// No code content available"


def safe_code_block(code: Optional[str], language: str = "c") -> str:
    normalized = normalize_code(code)
    return f"```{language}\n{normalized}\n```"


def _join_or_default(values, default: str) -> str:
    return ", ".join([str(value) for value in values if str(value)]) or default


def _neutral_local_signals(callee: dict) -> str:
    signals = (
        callee.get("local_signals")
        or callee.get("downstream_signal_hint")
        or callee.get("danger_hint")
        or callee.get("danger_signals")
        or []
    )
    replacements = {
        "memory copy": "memory/buffer operation",
        "buffer write": "memory/buffer operation",
        "length update": "length-related logic",
        "length-dependent operation": "length-related logic",
        "length/remaining/consumed update": "length-related logic",
        "state transition": "parser state logic",
        "parser state update": "parser state logic",
        "parser progress update": "parser progress logic",
        "stack manipulation": "stack operation",
    }
    neutral = []
    for signal in signals:
        neutral_signal = replacements.get(str(signal), str(signal))
        if neutral_signal not in neutral:
            neutral.append(neutral_signal)
    return _join_or_default(neutral, "none observed")


def _caller_input_path_hint(caller: dict) -> str:
    return str(caller.get("input_path_hint") or caller.get("input_path_evidence") or "weak").lower()


def _caller_identity(caller: dict) -> tuple:
    return (
        caller.get("func_name", ""),
        tuple(caller.get("arg_texts") or caller.get("arguments") or []),
    )

# Select a subset of callers for inclusion in the prompt, prioritizing top-ranked callers and those with strong or medium input-path evidence.
def _select_callers_for_prompt(callers: list, base_count: int = 2, max_count: int = 5) -> list:
    """Keep top-ranked callers, then add strong/medium input-path evidence."""
    selected = []
    seen = set()

    def add(caller: dict) -> None:
        if len(selected) >= max_count:
            return
        key = _caller_identity(caller)
        if key in seen:
            return
        selected.append(caller)
        seen.add(key)

    for caller in callers[:base_count]:
        add(caller)

    for level in ("strong", "medium"):
        for caller in callers[base_count:]:
            if _caller_input_path_hint(caller) == level:
                add(caller)

    return selected


def format_function_metadata(rec: dict) -> str:
    return (
        "Function metadata:\n"
        f"- File: {rec.get('file', 'unknown')}\n"
        f"- Function name: {rec.get('func_name', 'unknown')}\n"
        f"- Line range: {rec.get('line_start', '?')}-{rec.get('line_end', '?')}\n"
    )

# 分析目標函數的呼叫上下文：
# 包含 caller、callee，以及相關函數之間的關聯性
# 把 extractor 產生的 caller/callee/cross-function evidence 整理成文字，放進 user prompt。
def format_call_context(rec: dict) -> str:
    caller_summary = rec.get("caller_summary") or {}
    callee_summary = rec.get("callee_summary") or {}
    direct_evidence = rec.get("cross_function_direct_evidence") or {}
    current_signals = rec.get("current_function_signals") or []
    callers = caller_summary.get("callers") or []
    callees = callee_summary.get("callees") or []
    direct_lines = direct_evidence.get("summary_lines") or []
    direct_patterns = direct_evidence.get("patterns") or []

    lines = ["\nCall Context Summary (LLVM/Clang MVP):", "Caller Context:"]

    if callers:
        for caller in _select_callers_for_prompt(callers):
            input_path_hint = _caller_input_path_hint(caller)
            arg_text = _join_or_default(caller.get("arg_texts") or caller.get("arguments") or [], "unknown")
            categories = _join_or_default(caller.get("argument_categories") or [], "unclear from syntax")
            lines.append(f"- Called by {caller.get('func_name', 'unknown')} with arguments: {arg_text}")
            lines.append(f"- Passed argument categories: {categories}")
            lines.append(f"- Input path evidence level: {input_path_hint}")
            lines.append("- Evidence scope: upstream_relation_only; current_function_body_evidence=false")
    else:
        lines.append("- none found in this translation unit")

    lines.append("Callee Context:")
    if callees:
        for callee in callees[:2]:
            arg_text = _join_or_default(callee.get("arg_texts") or callee.get("arguments") or [], "unknown")
            categories = _join_or_default(callee.get("argument_categories") or [], "unclear from syntax")
            evidence_scope = callee.get("evidence_scope", "downstream_only")
            is_current_evidence = callee.get("is_current_function_evidence", False)
            is_downstream_evidence = callee.get("is_downstream_evidence", True)
            operation_signals = _join_or_default(
                callee.get("operation_signals") or callee.get("operation_classes") or [],
                "none observed",
            )
            weakness_families = _join_or_default(
                callee.get("weakness_families") or callee.get("cwe_families") or [],
                "none observed",
            )
            lines.append(f"- Calls {callee.get('func_name', 'unknown')} with arguments: {arg_text}")
            lines.append(f"- Passed argument categories: {categories}")
            lines.append(f"- Callee has local signals: {_neutral_local_signals(callee)}")
            lines.append(f"- Callee operation signals: {operation_signals}")
            lines.append(f"- Callee weakness families: {weakness_families}")
            lines.append(
                "- Evidence scope: "
                f"{evidence_scope}; current_function_evidence={str(is_current_evidence).lower()}; "
                f"downstream_evidence={str(is_downstream_evidence).lower()}"
            )
    else:
        lines.append("- no direct callee with local signals selected")
    lines.append("- Note: callee signals are downstream evidence only unless the callee return value controls current-function progress.")

    lines.append("Cross-Function Direct Evidence:")
    if direct_patterns or direct_lines:
        for summary_line in direct_lines[:4]:
            lines.append(f"- {summary_line}")
        for pattern in direct_patterns[:3]:
            expression = pattern.get("expression", "unknown expression")
            callee = pattern.get("callee", "unknown")
            lhs = pattern.get("lhs", "unknown")
            strength = pattern.get("evidence_strength", "unknown")
            bound_check = pattern.get("bound_check_observed", "unknown")
            lines.append(
                "- Direct evidence pattern: "
                f"kind={pattern.get('kind', 'unknown')}; lhs={lhs}; callee={callee}; "
                f"expression={expression}; bound_check_observed={str(bound_check).lower()}; strength={strength}"
            )
        lines.append("- Evidence scope: cross_function_direct_evidence; current_function_body_evidence=true")
    else:
        lines.append("- none detected")

    lines.append("Current Function Signals:")
    if current_signals:
        for signal in current_signals[:3]:
            lines.append(f"- {signal}")
        lines.append("- Treat these as direct current-function evidence when the code shows parser cursor/progress updates or security-sensitive boundary-transition ordering around lookup/resolution.")
    else:
        lines.append("- none detected")

    return "\n".join(lines) + "\n"
