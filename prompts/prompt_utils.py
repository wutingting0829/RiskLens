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
