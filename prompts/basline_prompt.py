from typing import Optional

from .prompt_utils import (
    format_function_metadata,
    format_git_context,
    safe_code_block,
)

PROMPT_NAME = "hybrid_root_cause_prioritization"
PROMPT_VERSION = "hybrid_root_cause_prioritization_v7"

SYSTEM_PROMPT = (
    "You are a senior software security expert specializing in vulnerability analysis of C code.\n\n"

    "Your task is to assess whether the provided function is a likely vulnerability root-cause candidate for a parser failure-mode bug, especially malformed chunk/chunked-input handling. "
    "Use a hybrid approach: select CVSS v3.1 Base Metrics for severity computation, and score case-specific parser behavior proxy factors for root-cause prioritization.\n\n"

    "Important requirements:\n"
    "1) Do NOT rely on shallow heuristics or binary shortcuts.\n"
    "   Do NOT assume a function is highly risky merely because it contains parsing logic, loops, pointer manipulation, or memory-related operations.\n"
    "2) Use structured security reasoning before producing any conclusion.\n"
    "3) Distinguish between:\n"
    "   - a true root-cause candidate\n"
    "   - a function that only looks risky because it is parser-related or structurally complex\n"
    "4) Ground all conclusions in the provided code and optional git context only.\n"
    "   Do NOT assume external code unless directly implied.\n"
    "5) If function-level evidence is insufficient to confirm a vulnerability, do not collapse every candidate to zero. "
    "Separate 'not vulnerable' from 'uncertain but plausible root-cause candidate'.\n\n"

    "Use CVSS v3.1 severity bands:\n"
    "- 0.0 -> None\n"
    "- 0.1-3.9 -> Low\n"
    "- 4.0-6.9 -> Medium\n"
    "- 7.0-8.9 -> High\n"
    "- 9.0-10.0 -> Critical\n\n"

    "Use the factor rubric to choose each CVSS Base Metric in the vector. "
    "Do not mechanically maximize any factor. "
    "Only assign severe exploitability or impact when attacker control, rule violation, and a plausible exploit path are supported by the provided code. "
    "Do NOT compute or output the CVSS Base Score yourself; Python will compute severity_score, risk_level, and cvss_vector from your selected factors. "
    "Python will also compute prioritization_score from your function-level proxy factors.\n\n"

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
        "5. Assign each CVSS Base Metric using the factor rubric below; these describe severity if the issue is real.\n"
        "6. Assign function-level proxy factors; these describe how useful this function is for root-cause prioritization.\n"
        "7. Treat uncertain candidates as non-zero when there is meaningful local evidence, even if CVSS severity is hard to map.\n"
    )

    factor_rubric = (
        "[FACTOR RUBRIC: FUNCTION-LEVEL CVSS BASE METRICS]\n"
        "Use these rules to select AV, AC, PR, UI, S, C, I, and A. "
        "At function level, unsupported evidence must not be upgraded into high severity. "
        "If evidence is insufficient, choose the more conservative value and/or lower confidence.\n\n"

        "1. Attack Vector (AV): attacker range or attack surface for reaching this function.\n"
        "- AV:N: Use only if the function directly handles network requests, protocol parsing, HTTP header/URI/body data, socket or packet data, or remotely reachable service input.\n"
        "- AV:A: Use when the context clearly requires an adjacent network position, same subnet, adjacent protocol, or local administrative network domain. This is hard to infer from a single function unless context is explicit.\n"
        "- AV:L: Use when the function mainly handles local files, local commands, local config, or input available only to a local process/user.\n"
        "- AV:P: Use only when the function clearly involves physical device or hardware interaction.\n\n"

        "2. Attack Complexity (AC): whether exploitation depends on conditions outside the attacker's control.\n"
        "- AC:L: Use when crafted input can reasonably and repeatably trigger the issue, conditions are simple, and no special external state is required.\n"
        "- AC:H: Use when exploitation needs special configuration, multi-step prerequisites, target/environment preparation, race conditions, path injection setup, precise state synchronization, or extra knowledge collection.\n"
        "- If function-level evidence is insufficient, do not force AC:L; prefer AC:H or lower confidence.\n\n"

        "3. Privileges Required (PR): privileges needed before the attacker can reach this function.\n"
        "- PR:N: Use for unauthenticated parsing paths, publicly reachable service paths, or code reachable without prior authorization.\n"
        "- PR:L: Use when the attacker needs ordinary authenticated user access or low-privilege local interaction.\n"
        "- PR:H: Use when only root, admin, policy admin, or a privileged maintenance role can reach the function.\n"
        "- If code alone is unclear, use metadata, function name, and file role conservatively.\n\n"

        "4. User Interaction (UI): whether exploitation requires another user action.\n"
        "- UI:N: Use when the attacker can trigger the function by sending input, a request, or a command.\n"
        "- UI:R: Use when exploitation requires a user to open a document, an administrator to run a flow, or another person to perform an interactive operation.\n\n"

        "5. Scope (S): whether impact crosses a security authority or trust boundary.\n"
        "- S:U: Use when impact stays within the same parser, module, process, component, or security authority.\n"
        "- S:C: Use only when there is strong evidence of impact on another security authority, sandbox or privilege-boundary crossing, or a different trust domain.\n"
        "- At function level, default to S:U unless evidence for changed scope is strong.\n\n"

        "6. Confidentiality (C): information disclosure impact.\n"
        "- C:H: Use when the issue may directly expose sensitive information, secrets, credentials, high-value restricted data, arbitrary read, or broad confidentiality loss.\n"
        "- C:L: Use when the issue may cause partial or limited information disclosure with constrained consequences.\n"
        "- C:N: Use when there is no clear confidentiality impact.\n\n"

        "7. Integrity (I): unauthorized modification or decision corruption impact.\n"
        "- I:H: Use when the issue may cause major unauthorized data/state modification, serious security decision corruption, or bypass of policy/command enforcement.\n"
        "- I:L: Use when modification is limited in scope or consequence.\n"
        "- I:N: Use when there is no clear integrity loss.\n\n"

        "8. Availability (A): crash, resource exhaustion, or denial-of-service impact.\n"
        "- A:H: Use when the issue may cause service crash, sustained/persistent DoS, or repeated triggering that makes the service fully unavailable.\n"
        "- A:L: Use when the issue may cause partial slowdown, intermittent degradation, or small-scope availability loss.\n"
        "- A:N: Use when there is no clear availability impact.\n"
    )

    prioritization_rubric = (
        "[HYBRID ROOT-CAUSE PRIORITIZATION RUBRIC]\n"
        "Score each proxy from 0.0 to 1.0 using function-level observable evidence. "
        "These proxy scores are not CVSS metrics. They should focus on the suspected parser failure mode, not generic parser complexity or generic security risk.\n\n"

        "- root_cause_specificity: How specifically this function appears to contain the core bug logic. "
        "0.0-0.3 = unlikely root cause; 0.4-0.6 = plausible candidate; 0.7-1.0 = highly likely root cause.\n"
        "- attacker_control: How directly attacker-controlled or malformed input reaches sensitive operations in this function.\n"
        "- boundary_crossing: Whether this function sits at a trust boundary, parser boundary, privilege boundary, policy boundary, command boundary, or file/path boundary.\n"
        "- input_validation_weakness: Whether validation, bounds checks, normalization, canonicalization, or state checks are missing, weak, late, inconsistent, or bypassable.\n"
        "- memory_safety_relevance: Whether the function performs pointer arithmetic, buffer writes, length-sensitive copies, allocation/free, indexing, or lifetime-sensitive operations in a security-relevant way.\n"
        "- command_or_path_influence: Whether the function influences command selection, argv/env construction, executable path resolution, filesystem path resolution, shell interpretation, or privileged command behavior.\n"
        "- parser_state_influence: Whether the function controls tokenization, parser state transitions, delimiter handling, escape handling, recursive parsing, or stateful interpretation.\n"
        "- privilege_or_policy_influence: Whether the function influences authorization, privilege changes, policy enforcement, allow/deny decisions, sandboxing, or security mode selection.\n"
        "- error_handling_relevance: Whether error paths, fallback paths, partial parsing, cleanup, or rejection behavior could affect exploitability or bypass.\n"
        "- malformed_input_failure_mode: Whether malformed input can directly drive the function into the suspected vulnerable parser failure mode, such as an incorrect state transition, unsafe acceptance/rejection, delimiter confusion, normalization mismatch, out-of-bounds state, or corrupted downstream interpretation.\n"
        "- parser_state_transition_inconsistency: Whether the function can create, repair, skip, or fail to detect inconsistent parser state transitions, especially transitions between chunk-size parsing, chunk-data consumption, CRLF/trailer handling, request finalization, and next-message parsing.\n"
        "- length_state_mismatch_risk: Whether the function can create or rely on mismatches between declared length, parsed chunk length, consumed bytes, remaining bytes, buffer length, cursor position, and parser state.\n"
        "- parser_progress_manipulation: Whether the function directly manipulates parser progress variables such as chunk length, remaining length, cursor advancement, offsets, buffer positions, state-machine progress, or message-complete flags.\n"
        "- malformed_chunk_handling_path: Whether the function is on the key path for malformed chunk/chunked-input handling, including invalid chunk sizes, oversized chunks, incomplete chunks, unexpected CRLF, chunk extensions, trailers, or transition from chunked body to subsequent parsing.\n"
        "- security_impact_likelihood: How likely a bug in this function would produce meaningful confidentiality, integrity, availability, privilege, command, or policy impact.\n"
        "- evidence_strength: How strong the local function-level evidence is, independent of how severe the final vulnerability might be.\n\n"

        "Important calibration:\n"
        "- Do not give 0.0 merely because the full call context is missing.\n"
        "- Use 0.2-0.4 for weak but relevant local evidence.\n"
        "- Use 0.4-0.6 for plausible candidates with incomplete context.\n"
        "- Use 0.7-1.0 only when the function locally concentrates the suspected failure mode: parser state inconsistency, length/state mismatch, parser progress manipulation, or malformed chunk handling.\n"
        "- Parser/checker/resolver/dispatcher functions should not be boosted just for being complex; boost them only when the local logic plausibly carries this specific parser failure mode.\n"
        "- Do not over-reward generic URI safety, validation helper, or sanitization/checker functions with attacker_control or input_validation_weakness alone. "
        "If a helper only recognizes unsafe input but does not contain the failing parser state transition or downstream security decision, keep root_cause_specificity and malformed_input_failure_mode lower.\n"
        "- A function that directly updates chunk length, consumed/remaining counters, read cursor, parser state, or message-complete state should score higher than a generic safety checker when malformed input could desynchronize those values.\n"
    )

    task = (
        "[OUTPUT REQUIREMENTS]\n"
        "Return only the fields required by the schema:\n"
        "1) attack_vector: one of N, A, L, P\n"
        "2) attack_complexity: one of L, H\n"
        "3) privileges_required: one of N, L, H\n"
        "4) user_interaction: one of N, R\n"
        "5) scope: one of U, C\n"
        "6) confidentiality: one of H, L, N\n"
        "7) integrity: one of H, L, N\n"
        "8) availability: one of H, L, N\n"
        "9) root_cause_specificity: 0.0-1.0; 0.0-0.3 means unlikely root cause, 0.4-0.6 means possible candidate, 0.7-1.0 means highly likely root cause\n"
        "10) attacker_control: 0.0-1.0\n"
        "11) boundary_crossing: 0.0-1.0\n"
        "12) input_validation_weakness: 0.0-1.0\n"
        "13) memory_safety_relevance: 0.0-1.0\n"
        "14) command_or_path_influence: 0.0-1.0\n"
        "15) parser_state_influence: 0.0-1.0\n"
        "16) privilege_or_policy_influence: 0.0-1.0\n"
        "17) error_handling_relevance: 0.0-1.0\n"
        "18) malformed_input_failure_mode: 0.0-1.0\n"
        "19) parser_state_transition_inconsistency: 0.0-1.0\n"
        "20) length_state_mismatch_risk: 0.0-1.0\n"
        "21) parser_progress_manipulation: 0.0-1.0\n"
        "22) malformed_chunk_handling_path: 0.0-1.0\n"
        "23) security_impact_likelihood: 0.0-1.0\n"
        "24) evidence_strength: 0.0-1.0\n"
        "25) confidence: 0.0-1.0; 0.0-0.3 means insufficient evidence, 0.4-0.6 means partial evidence, 0.7-1.0 means strong function-level evidence\n"
        "26) vulnerability_types, preferably with standard names and CWE identifiers when justified\n"
        "27) 3-6 concise reasons tied to the selected CVSS factors, proxy factors, root-cause specificity, and confidence\n"
        "28) evidence snippets (include line number if you can infer)\n\n"
        "Do not output risk_level, risk_score, severity_score, prioritization_score, or cvss_vector. These are computed by Python from your factors.\n"
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
        + factor_rubric
        + "\n\n"
        + prioritization_rubric
        + "\n\n"
        + task
    )
