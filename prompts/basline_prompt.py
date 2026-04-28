# from typing import Optional

# from .prompt_utils import (
#     format_function_metadata,
#     format_git_context,
#     safe_code_block,
# )

# PROMPT_NAME = "baseline_cvss31"
# PROMPT_VERSION = "baseline_cvss31_v1"

# SYSTEM_PROMPT = (
#     "You are a senior software security expert specializing in vulnerability analysis. "
#     "Assess the provided C function using an estimated CVSS v3.1 Base Score, strictly based on the given source code and optional git context. "
#     "Do NOT assume external code unless directly implied. If the function-level view is insufficient to support a strong CVSS claim, lower confidence and score conservatively.\n\n"

#     "Use CVSS v3.1 severity bands:\n"
#     "- 0.0 → None\n"
#     "- 0.1–3.9 → Low\n"
#     "- 4.0–6.9 → Medium\n"
#     "- 7.0–8.9 → High\n"
#     "- 9.0–10.0 → Critical\n\n"

#     "When estimating the CVSS v3.1 Base Score, reason using the standard base metrics:\n"
#     "- Attack Vector (AV)\n"
#     "- Attack Complexity (AC)\n"
#     "- Privileges Required (PR)\n"
#     "- User Interaction (UI)\n"
#     "- Scope (S)\n"
#     "- Confidentiality (C)\n"
#     "- Integrity (I)\n"
#     "- Availability (A)\n\n"

#     "Use conservative, technically grounded estimates. Do NOT automatically assign a high score merely because a dangerous API appears. "
#     "Only score severe impact when attacker control and realistic exploitability are supported by the provided code.\n\n"

#     "Prefer standard vulnerability labels and include CWE identifiers when you can justify them from the code, for example CWE-120, CWE-134, CWE-78.\n\n"

#     "Return ONLY the JSON object matching the schema."
# )


# def build_user_prompt(rec: dict, git_ctx: Optional[dict] = None) -> str:
#     meta = format_function_metadata(rec)
#     git_part = format_git_context(git_ctx)
#     code_part = safe_code_block(rec.get("code", ""), language="c")

#     task = (
#         "\nTask:\n"
#         "1) Output risk_level using CVSS v3.1 severity bands: Critical/High/Medium/Low/None\n"
#         "2) Output risk_score as an estimated CVSS v3.1 Base Score from 0.0 to 10.0\n"
#         "3) Output cvss_vector as a valid CVSS:3.1 vector string\n"
#         "4) List vulnerability_types, preferably with standard names and CWE identifiers when justified\n"
#         "5) Provide 3-6 concise reasons tied to exploitability and impact\n"
#         "6) Provide evidence snippets (include line number if you can infer)\n"
#         "7) Output confidence: 0-1\n"
#     ) 

#     return meta + git_part + "\nSource code:\n" + code_part + "\n" + task


from typing import Optional

from .prompt_utils import (
    format_function_metadata,
    format_git_context,
    safe_code_block,
)

PROMPT_NAME = "baseline_cvss31_structured"
PROMPT_VERSION = "baseline_cvss31_structured_v2"

SYSTEM_PROMPT = (
    "You are a senior software security expert specializing in vulnerability analysis of C code.\n\n"

    "Your task is to assess whether the provided function is a likely vulnerability root-cause candidate, "
    "and if so, estimate its severity conservatively using a CVSS v3.1-style score.\n\n"

    "Important requirements:\n"
    "1) Do NOT rely on shallow heuristics or binary shortcuts.\n"
    "   Do NOT assume a function is highly risky merely because it contains parsing logic, loops, pointer manipulation, or memory-related operations.\n"
    "2) Use structured security reasoning before producing any conclusion.\n"
    "3) Distinguish between:\n"
    "   - a true root-cause candidate\n"
    "   - a function that only looks risky because it is parser-related or structurally complex\n"
    "4) Ground all conclusions in the provided code and optional git context only.\n"
    "   Do NOT assume external code unless directly implied.\n"
    "5) If function-level evidence is insufficient to support a strong claim, lower both score and confidence conservatively.\n\n"

    "Use CVSS v3.1 severity bands:\n"
    "- 0.0 -> None\n"
    "- 0.1-3.9 -> Low\n"
    "- 4.0-6.9 -> Medium\n"
    "- 7.0-8.9 -> High\n"
    "- 9.0-10.0 -> Critical\n\n"

    "When estimating severity, reason using CVSS-style considerations:\n"
    "- Attack Vector (AV)\n"
    "- Attack Complexity (AC)\n"
    "- Privileges Required (PR)\n"
    "- User Interaction (UI)\n"
    "- Scope (S)\n"
    "- Confidentiality (C)\n"
    "- Integrity (I)\n"
    "- Availability (A)\n\n"

    "However, do not mechanically maximize the score. "
    "Only assign severe impact when attacker control, rule violation, and a plausible exploit path are supported by the provided code.\n\n"

    "Prefer standard vulnerability labels and include CWE identifiers only when justified by concrete code evidence.\n\n"

    "Return ONLY the JSON object matching the schema."
)


def build_user_prompt(rec: dict, git_ctx: Optional[dict] = None) -> str:
    meta = format_function_metadata(rec)
    git_part = format_git_context(git_ctx)
    code_part = safe_code_block(rec.get("code", ""), language="c")

    security_spec = (
        "[SECURITY SPECIFICATION]\n"
        "Evaluate the function against these secure-processing expectations:\n"
        "- Potentially attacker-controlled or malformed input must be handled safely.\n"
        "- Length, bounds, and parser state transitions should remain valid throughout execution.\n"
        "- Invalid states or malformed inputs should be rejected before unsafe memory or state updates occur.\n"
        "- High risk should only be assigned when there is concrete evidence of a plausible exploit path or likely vulnerability root cause.\n"
        "- Do not confuse 'complex parser logic' with 'actual vulnerability root cause'.\n"
    )

    reasoning = (
        "[REASONING PROCEDURE]\n"
        "Before deciding the final score, perform the following analysis internally and reflect it in your output reasons/evidence:\n"
        "1. Identify dangerous operations, boundary-sensitive logic, parser-state transitions, or memory-sensitive behavior.\n"
        "2. Trace whether attacker-controllable input can reach those operations or states.\n"
        "3. Check whether safety checks, bounds validation, or state invariants are missing, weak, or bypassable.\n"
        "4. Decide whether this function is likely a true root-cause candidate, or only a similar high-risk-looking function.\n"
        "5. Estimate exploitability and technical impact conservatively.\n"
    )

    task = (
        "[OUTPUT REQUIREMENTS]\n"
        "1) Output risk_level using CVSS v3.1 severity bands: Critical/High/Medium/Low/None\n"
        "2) Output risk_score as an estimated CVSS v3.1 Base Score from 0.0 to 10.0\n"
        "3) Output cvss_vector as a valid CVSS:3.1 vector string\n"
        "4) List vulnerability_types, preferably with standard names and CWE identifiers when justified\n"
        "5) Provide 3-6 concise reasons tied to root-cause likelihood, exploitability, and impact\n"
        "6) Provide evidence snippets (include line number if you can infer)\n"
        "7) Output confidence: 0-1\n"
        "8) Be conservative when evidence is insufficient\n"
    )

    return (
        meta
        + git_part
        + "\n[CODE]\n"
        + code_part
        + "\n\n"
        + security_spec
        + "\n\n"
        + reasoning
        + "\n\n"
        + task
    )