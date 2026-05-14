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


def format_function_metadata(rec: dict) -> str:
    return (
        "Function metadata:\n"
        f"- File: {rec.get('file', 'unknown')}\n"
        f"- Function name: {rec.get('func_name', 'unknown')}\n"
        f"- Line range: {rec.get('line_start', '?')}-{rec.get('line_end', '?')}\n"
    )

# 分析目標函數的呼叫上下文：
# 包含 caller、callee，以及相關函數之間的關聯性
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
        for caller in callers[:2]:
            input_path_hint = caller.get("input_path_hint") or caller.get("input_path_evidence") or "weak"
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
            lines.append(f"- Calls {callee.get('func_name', 'unknown')} with arguments: {arg_text}")
            lines.append(f"- Passed argument categories: {categories}")
            lines.append(f"- Callee has local signals: {_neutral_local_signals(callee)}")
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
        lines.append("- Treat these as direct current-function evidence when the code shows parser cursor, loop index, offset, consumed/remaining length, or progress state being updated.")
    else:
        lines.append("- none detected")

    return "\n".join(lines) + "\n"


def format_git_context(git_ctx: Optional[dict]) -> str:
    if git_ctx is None:
        return ""

    messages = git_ctx.get("recent_messages", [])
    msg_text = "\n".join([f"  - {m}" for m in messages])

    return (
        "\nGit context (optional):\n"
        f"- Commits analyzed: {git_ctx.get('commit_count', 0)}\n"
        f"- Recent commit messages (latest first):\n"
        f"{msg_text}\n"
    )
