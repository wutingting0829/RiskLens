from typing import Optional


def normalize_code(code: Optional[str]) -> str:
    code = (code or "").strip()
    return code if code else "// No code content available"


def safe_code_block(code: Optional[str], language: str = "c") -> str:
    normalized = normalize_code(code)
    return f"```{language}\n{normalized}\n```"


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
    callers = caller_summary.get("callers") or []
    callees = callee_summary.get("callees") or []

    lines = [
        "\nCall context summary (LLVM/Clang MVP):",
        "- Caller question: is this function on a user-controlled or parser-derived input path?",
    ]

    if callers:
        for caller in callers[:2]:
            lines.append(
                "  - "
                f"{caller.get('func_name', 'unknown')}: "
                f"role={caller.get('role_hint', caller.get('control_path_role', 'unknown'))}; "
                f"relevance={caller.get('relevance', caller.get('why_relevant', 'unknown'))}; "
                f"input={caller.get('input_hint', caller.get('input_origin', 'unknown'))}"
            )
    else:
        lines.append("  - none found in this translation unit")

    lines.append("- Callee question: is this function a dispatcher/gatekeeper, or is the dangerous primitive in a downstream helper?")
    if callees:
        for callee in callees[:2]:
            signals = callee.get("danger_hint") or callee.get("danger_signals") or []
            signal_text = ", ".join(signals) if signals else "none"
            lines.append(
                "  - "
                f"{callee.get('func_name', 'unknown')}: "
                f"role={callee.get('role_hint', 'unknown')}; "
                f"relevance={callee.get('relevance', callee.get('why_relevant', 'unknown'))}; "
                f"danger={signal_text}"
            )
    else:
        lines.append("  - no risk-relevant direct callee selected")

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
