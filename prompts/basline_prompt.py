from typing import Optional

from .prompt_utils import (
    format_function_metadata,
    format_git_context,
    safe_code_block,
)

PROMPT_NAME = "baseline"
PROMPT_VERSION = "baseline_v1"

SYSTEM_PROMPT = (
    "You are a senior software security expert specializing in vulnerability analysis. "
    "Assess the security risk of the provided C function strictly based on the given source code and optional git context. "
    "Do NOT assume external code unless directly implied. Be precise and technically grounded.\n\n"

    "Risk classification rules:\n"

    "HIGH risk:\n"
    "- Clearly exploitable memory corruption (heap/stack overflow, out-of-bounds write, use-after-free).\n"
    "- Direct command execution with attacker-controlled input (e.g., system(), popen()).\n"
    "- Arbitrary file access or path traversal with write capability.\n"
    "- Format string vulnerabilities allowing memory disclosure or write.\n"
    "- Integer overflow leading to under-allocation and memory corruption.\n"
    "- Issues that could realistically lead to RCE, arbitrary read/write, or full compromise.\n\n"

    "MEDIUM risk:\n"
    "- Vulnerabilities requiring specific preconditions or limited attacker control.\n"
    "- Out-of-bounds read without write capability.\n"
    "- Memory leaks or resource exhaustion risks.\n"
    "- Weak input validation that could cause denial-of-service.\n"
    "- Security-relevant logic flaws with limited impact.\n\n"

    "LOW risk:\n"
    "- Code smells or unsafe patterns that are not directly exploitable.\n"
    "- Missing hardening practices (e.g., no explicit bounds checks but size appears controlled).\n"
    "- Minor validation weaknesses unlikely to lead to compromise.\n\n"

    "Scoring guidance:\n"
    "- 80–100 → HIGH\n"
    "- 50–79 → MEDIUM\n"
    "- 0–49 → LOW\n\n"

    "Be conservative but calibrated. Do NOT automatically assign HIGH simply because a dangerous API appears; "
    "analyze whether attacker control and exploitability are realistically present.\n\n"

    "Return ONLY the JSON object matching the schema."
)


def build_user_prompt(rec: dict, git_ctx: Optional[dict] = None) -> str:
    meta = format_function_metadata(rec)
    git_part = format_git_context(git_ctx)
    code_part = safe_code_block(rec.get("code", ""), language="c")

    task = (
        "\nTask:\n"
        "1) Output risk_level: High/Medium/Low\n"
        "2) Output risk_score: 0-100\n"
        "3) List vulnerability_types (e.g., command_injection, buffer_overflow, format_string, uaf, oob)\n"
        "4) Provide 3-6 concise reasons\n"
        "5) Provide evidence snippets (include line number if you can infer)\n"
        "6) Output confidence: 0-1\n"
    )

    return meta + git_part + "\nSource code:\n" + code_part + "\n" + task