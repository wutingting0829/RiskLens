from typing import Optional

from .prompt_utils import (
    format_function_metadata,
    format_git_context,
    safe_code_block,
)

PROMPT_NAME = "baseline_cvss31"
PROMPT_VERSION = "baseline_cvss31_v1"

SYSTEM_PROMPT = (
    "You are a senior software security expert specializing in vulnerability analysis. "
    "Assess the provided C function using an estimated CVSS v3.1 Base Score, strictly based on the given source code and optional git context. "
    "Do NOT assume external code unless directly implied. If the function-level view is insufficient to support a strong CVSS claim, lower confidence and score conservatively.\n\n"

    "Use CVSS v3.1 severity bands:\n"
    "- 0.0 → None\n"
    "- 0.1–3.9 → Low\n"
    "- 4.0–6.9 → Medium\n"
    "- 7.0–8.9 → High\n"
    "- 9.0–10.0 → Critical\n\n"

    "When estimating the CVSS v3.1 Base Score, reason using the standard base metrics:\n"
    "- Attack Vector (AV)\n"
    "- Attack Complexity (AC)\n"
    "- Privileges Required (PR)\n"
    "- User Interaction (UI)\n"
    "- Scope (S)\n"
    "- Confidentiality (C)\n"
    "- Integrity (I)\n"
    "- Availability (A)\n\n"

    "Use conservative, technically grounded estimates. Do NOT automatically assign a high score merely because a dangerous API appears. "
    "Only score severe impact when attacker control and realistic exploitability are supported by the provided code.\n\n"

    "Prefer standard vulnerability labels and include CWE identifiers when you can justify them from the code, for example CWE-120, CWE-134, CWE-78.\n\n"

    "Return ONLY the JSON object matching the schema."
)


def build_user_prompt(rec: dict, git_ctx: Optional[dict] = None) -> str:
    meta = format_function_metadata(rec)
    git_part = format_git_context(git_ctx)
    code_part = safe_code_block(rec.get("code", ""), language="c")

    task = (
        "\nTask:\n"
        "1) Output risk_level using CVSS v3.1 severity bands: Critical/High/Medium/Low/None\n"
        "2) Output risk_score as an estimated CVSS v3.1 Base Score from 0.0 to 10.0\n"
        "3) Output cvss_vector as a valid CVSS:3.1 vector string\n"
        "4) List vulnerability_types, preferably with standard names and CWE identifiers when justified\n"
        "5) Provide 3-6 concise reasons tied to exploitability and impact\n"
        "6) Provide evidence snippets (include line number if you can infer)\n"
        "7) Output confidence: 0-1\n"
    )

    return meta + git_part + "\nSource code:\n" + code_part + "\n" + task
