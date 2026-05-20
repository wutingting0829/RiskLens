from typing import Optional

from .prompt_utils import (
    format_call_context,
    format_function_metadata,
    format_git_context,
    safe_code_block,
)

PROMPT_NAME = "hybrid_root_cause_prioritization"
PROMPT_VERSION = "hybrid_root_cause_prioritization_v14_structured_taxonomy"

SYSTEM_PROMPT = (
    "You are a senior software security expert specializing in vulnerability analysis of code.\n\n"

    "Your task is to assess whether the provided function is a likely vulnerability root-cause candidate for a security-sensitive C bug. "
    "Use a hybrid approach: select CVSS v3.1 Base Metrics for severity computation, and score compact root-cause prioritization proxy factors.\n\n"

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

    "Use only the fixed weakness-family and operation-signal enums requested by the schema. "
    "Include a concrete CWE ID only when justified by concrete code evidence.\n\n"

    "Return ONLY the JSON object matching the schema."
)


def _lower_context(rec: dict) -> str:
    parts = [
        str(rec.get("file", "")),
        str(rec.get("func_name", "")),
        str(rec.get("code", "")),
        str(rec.get("caller_summary", "")),
        str(rec.get("callee_summary", "")),
    ]
    return "\n".join(parts).lower()


def build_case_type_addons(rec: dict) -> str:
    context = _lower_context(rec)
    addons = []

    if any(token in context for token in ["chunk", "chunked", "content_length", "http"]):
        addons.append(
            "[CASE-TYPE ADDON: CHUNKED INPUT]\n"
            "Apply this addon only for HTTP/chunked-input style cases.\n"
            "- Consider invalid chunk sizes, oversized chunks, incomplete chunks, chunk extensions, unexpected CRLF, trailers, and transitions from chunked body parsing to later request/message parsing.\n"
            "- For state_ordering_consistency_risk, focus on declared length, consumed bytes, remaining bytes, cursor advancement, and parser state staying synchronized.\n"
            "- For failure_trigger_plausibility, ask whether malformed chunked input can drive the function into the suspected failure path.\n"
        )

    if any(token in context for token in ["swf", "action", "decompile", "bytecode", "opcode", "cast", "push", "stack"]):
        addons.append(
            "[CASE-TYPE ADDON: SWF / ACTION / DECOMPILER]\n"
            "Apply this addon only for SWF, bytecode, action dispatch, or decompiler-style cases.\n"
            "- Check type-cast safety, signed/unsigned conversion, enum/integer mismatch, narrowing/widening conversion, opcode/action dispatch, stack effects, and Type Mismatch in Decompilation.\n"
            "- A cast or decoded action is risky when attacker-controlled bytes can influence sizes, offsets, indexes, allocation lengths, copy lengths, emitted output, or parser/decompiler state before adequate validation.\n"
            "- Pay special attention to loops where a helper return value updates the action index, bytecode cursor, read position, or parser progress. If malformed input can make that return value wrong, this may be root-cause evidence rather than generic dispatch complexity.\n"
            "- Do not reward generic decompiler complexity; reward only evidence tied to unsafe interpretation, dispatch, stack/data-structure state, or malformed bytecode/action handling.\n"
        )

    if any(token in context for token in ["tiff", "codec", "tag", "field", "admiss", "validforcodec", "fieldinfo"]):
        addons.append(
            "[CASE-TYPE ADDON: CODEC / TAG ADMISSIBILITY]\n"
            "Apply this addon only for codec, tag, field, or format-admissibility cases.\n"
            "- Treat semantic legality checks as potentially root-cause-relevant even when memory operations happen later.\n"
            "- For decision_or_validation_risk, ask whether the function decides whether a tag/field/property/codec combination is legal, supported, or allowed to proceed.\n"
            "- Do not lower root_cause_likelihood merely because the dangerous primitive is in a downstream helper if this function controls whether invalid format metadata reaches it.\n"
        )

    if not addons:
        return ""
    return "\n".join(addons) + "\n"


def build_user_prompt(rec: dict, git_ctx: Optional[dict] = None) -> str:
    meta = format_function_metadata(rec)
    call_context = format_call_context(rec)
    case_type_addons = build_case_type_addons(rec)
    git_part = format_git_context(git_ctx)
    code_part = safe_code_block(rec.get("code", ""), language="c")

    security_spec = (
        "[SECURITY SPECIFICATION]\n"
        "Evaluate the function against these secure-processing expectations:\n"
        "- Potentially attacker-controlled or malformed input must be handled safely.\n"
        "- Validation, bounds, semantic decisions, state transitions, length accounting, and data-structure invariants should remain valid throughout execution.\n"
        "- Invalid states or malformed inputs should be rejected before unsafe memory, state, command, policy, or data-structure updates occur.\n"
        "- Treat validation and gatekeeper functions as security-sensitive even when they do not directly write memory. "
        "A gatekeeper is a function that accepts/rejects syntax, validates semantic legality, selects legal states, or decides whether downstream processing may continue.\n"
        "- Do not assume that the most dangerous primitive must be the true root cause. "
        "Functions that make semantic validation or accept/reject decisions may be the actual root cause even if they contain fewer direct memory-manipulation operations.\n"
        "- For boolean or status-returning validation functions, explicitly consider the consequence if return 0, return 1, true, false, success, or failure is reversed, misinterpreted, or reached through an incomplete check. "
        "If an inverted or overly-permissive decision would allow malformed input into downstream processing, raise decision_or_validation_risk, state_ordering_consistency_risk, failure_trigger_plausibility, and evidence_strength as appropriate.\n"
        "- If the current function uses a callee return value to update a loop index, parser cursor, read position, consumed/remaining length, offset, or progress state, treat that as direct current-function evidence. "
        "When malformed input can make the callee return an incorrect progress amount, raise root_cause_likelihood, state_ordering_consistency_risk, and failure_trigger_plausibility as appropriate.\n"
        "- If the current function locally performs a security-sensitive boundary transition before or around name resolution, command resolution, path resolution, or authority-dependent lookup, treat that ordering as direct current-function evidence. "
        "This includes privilege, identity, group, filesystem-root, namespace, working-directory, environment, or protection-state changes that affect how later resolution is interpreted.\n"
        "- High risk should only be assigned when there is concrete evidence of a plausible exploit path or likely vulnerability root cause.\n"
        "- Do not confuse 'complex parser logic' with 'actual vulnerability root cause'.\n"
    )

    call_context_guidance = (
        "[CALL CONTEXT USAGE]\n"
        "Use caller/callee context only as supporting evidence, not as an automatic score boost.\n"
        "- Caller context helps decide whether external, parser-derived, or user-controlled input plausibly flows into the current function.\n"
        "- Callee context helps decide whether the truly dangerous operation may occur in a downstream helper called by the current function.\n"
        "- Do not increase severity, prioritization, input_exposure, security_boundary_relevance, state_ordering_consistency_risk, or root_cause_likelihood merely because callers or callees are present.\n"
        "- Do not lower the current function's root-cause relevance merely because a downstream helper contains a more obvious dangerous primitive; a gatekeeper/validation function can still be the root cause if its accept/reject decision controls whether malformed input reaches that helper.\n"
        "- Raise a factor only when the call context and the current function code together support a concrete data/control-flow link to unsafe parsing, state, length, memory, validation, command, or policy behavior.\n"
        "- If caller/callee context is vague, missing, or only shows generic helper calls, treat it as weak evidence and keep confidence appropriately conservative.\n"
        "\n[DIRECT CROSS-FUNCTION EVIDENCE RULE]\n"
        "Callee context is normally supporting evidence only.\n"
        "- However, if the current function uses a callee return value to update its own loop index, cursor, offset, consumed length, remaining length, or parser state, evaluate that evidence as current-function direct evidence because the traversal/progress decision occurs in the current function body.\n"
        "- Also evaluate boundary-transition ordering as current-function direct evidence when the current function locally performs a security-sensitive boundary transition before or around name resolution, command resolution, path resolution, or authority-dependent lookup, even if the final primitive is in a callee.\n"
        "- This does not automatically imply high risk.\n"
        "- Increase progress/state/root-cause factors only when: "
        "1) the updated variable affects subsequent traversal, loop continuation, parser state, index movement, or boundary-sensitive control flow; "
        "2) the current function lacks an explicit local check on the callee return value or on the updated progress variable; and "
        "3) the incorrect progress value could skip, repeat, desynchronize, or move parsing outside the expected range.\n"
        "- If explicit bounds checks or error handling are present, treat the pattern as normal parser control logic and do not increase the score substantially.\n"
        "- Keep ordinary callee-only facts as supporting evidence: helper-local memcpy, malloc, buffer write, allocation, privilege change, path lookup, or authorization check should not directly raise current-function root_cause_likelihood unless the current function controls whether or how that helper result affects traversal, state, authority, policy, or security ordering.\n"
    )

    reasoning = (
        "[REASONING PROCEDURE]\n"
        "Before deciding the final score, perform the following analysis internally and reflect it in your output reasons/evidence:\n"
        "1. Identify dangerous operations, boundary-sensitive logic, parser-state transitions, or memory-sensitive behavior.\n"
        "2. Trace whether attacker-controllable input can reach those operations or states.\n"
        "3. Check whether safety checks, bounds validation, or state invariants are missing, weak, or bypassable.\n"
        "4. Identify whether attacker-controlled values cross type, size, state, policy, or data-structure boundaries before adequate validation.\n"
        "5. Identify whether the function is a gatekeeper: a validation, legality check, state acceptance/rejection, dispatch filter, or semantic admissibility check.\n"
        "6. For gatekeeper functions, ask: if the return value or success/failure meaning is inverted, misread, or too permissive, what malformed input reaches later allocation, copy, dispatch, state-transition, command, policy, or data-structure code?\n"
        "6a. For semantic policy checks, ask whether this function makes the core legal/illegal or accept/reject decision even when the direct dangerous primitive happens later.\n"
        "6b. For progress-updating wrappers, ask whether callee return values are added to or assigned into loop indexes, offsets, cursors, or consumed/remaining counters; if so, malformed return values can desynchronize traversal and should increase root_cause_likelihood, state_ordering_consistency_risk, and failure_trigger_plausibility.\n"
        "6c. For boundary-ordering wrappers, ask whether the current function changes privilege, identity, group membership, filesystem root, namespace, cwd, environment, or protection state before or around name/path/command/user/group lookup. If so, treat the ordering as local root-cause evidence and raise root_cause_likelihood, decision_or_validation_risk, state_ordering_consistency_risk, failure_trigger_plausibility, and evidence_strength when a wrong order or failure handling could make resolution occur under the wrong authority or namespace.\n"
        "7. Decide whether this function is likely a true root-cause candidate, or only a similar high-risk-looking function.\n"
        "8. Assign each CVSS Base Metric using the factor rubric below; these describe severity if the issue is real.\n"
        "8a. Before selecting C/I/A, perform an impact consistency check: if your proxy factors indicate plausible root-cause evidence, explain why impact is truly absent before selecting C:N/I:N/A:N.\n"
        "9. Assign function-level proxy factors; these describe how useful this function is for root-cause prioritization.\n"
        "10. Treat uncertain candidates as non-zero when there is meaningful local evidence, even if CVSS severity is hard to map.\n"
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
        "- A:N: Use when there is no clear availability impact.\n\n"

        "Impact consistency calibration:\n"
        "- If a function has meaningful local evidence of unsafe type conversion, attacker-controlled size/index/offset interpretation, state desynchronization, malformed semantic acceptance, invalid memory access risk, or corrupted downstream interpretation, C:N/I:N/A:N should be rare and must be justified by evidence that the code cannot affect memory, state, output, policy, or availability.\n"
        "- When malformed input can plausibly crash the process, trigger assertion/abort behavior, create unbounded recursion/looping, or make processing fail in a repeated attacker-triggerable way, choose at least A:L.\n"
        "- When malformed input can plausibly corrupt state, dispatch, emitted output, policy decisions, or downstream interpretation without clear full compromise, choose at least I:L.\n"
        "- When malformed input can plausibly drive out-of-bounds reads, disclosure through emitted output, or reading unintended memory/data, choose at least C:L.\n"
        "- Keep impact low or none when evidence is truly generic, but do not collapse plausible root-cause candidates to zero severity solely because the complete call chain is missing.\n"
    )

    taxonomy_rubric = (
        "[STRUCTURED TAXONOMY]\n"
        "Use only these weakness_families values. Select one or more only when supported by code evidence; otherwise use other_uncertain.\n"
        "- memory_safety: Memory Safety / Buffer and Pointer Errors. Common CWE: CWE-787, CWE-125, CWE-119, CWE-120, CWE-122, CWE-416.\n"
        "- integer_size: Integer and Size Computation Errors. Common CWE: CWE-190, CWE-191, CWE-680, CWE-681.\n"
        "- input_validation_parser: Input Validation / Parser / Decoder Errors. Common CWE: CWE-20, CWE-1284, CWE-116, CWE-704.\n"
        "- path_file_resource: Path, File, and Resource Resolution Errors. Common CWE: CWE-22, CWE-73, CWE-59, CWE-61.\n"
        "- privilege_access_control: Privilege Management and Access Control Errors. Common CWE: CWE-269, CWE-284, CWE-285, CWE-266.\n"
        "- trust_boundary_security_decision: Trust Boundary and Security Decision Errors. Common CWE: CWE-807, CWE-345, CWE-346, CWE-348.\n"
        "- protection_mechanism_failure: Protection Mechanism Failure / Bypass. Common CWE: CWE-693, CWE-703, CWE-755.\n"
        "- race_ordering_toctou: Race Condition / Ordering / TOCTOU Errors. Common CWE: CWE-362, CWE-367, CWE-667.\n"
        "- injection_command_execution: Injection and Command Execution Errors. Common CWE: CWE-78, CWE-77, CWE-89, CWE-94, CWE-79.\n"
        "- crypto_auth_certificate: Cryptographic, Authentication, and Certificate Errors. Common CWE: CWE-287, CWE-295, CWE-326, CWE-327, CWE-347.\n"
        "- resource_lifecycle: Resource Management and Lifecycle Errors. Common CWE: CWE-400, CWE-401, CWE-404, CWE-772.\n"
        "- other_uncertain: Other / Uncertain; use when evidence is insufficient or no family fits reliably.\n\n"
        "Use only these operation_signals values:\n"
        "- memory_write, memory_read, pointer_lifetime, size_index_arithmetic, allocation_lifetime, parser_decoder,\n"
        "- path_file_resolution, command_execution, privilege_identity_transition, filesystem_namespace_transition,\n"
        "- trust_config_lookup, dynamic_code_loading, auth_policy_gate, protection_mechanism_enforcement,\n"
        "- crypto_certificate_validation, race_ordering, environment_runtime_context, resource_limit_lifecycle, other_uncertain.\n\n"
        "vulnerability_types must be structured objects with family_id, name, and optional cwe_id. "
        "The family_id must be in weakness_families. Use cwe_id only for concrete CWE evidence; otherwise set it to null.\n"
    )

    prioritization_rubric = (
        "[HYBRID ROOT-CAUSE PRIORITIZATION RUBRIC]\n"
        "Score each proxy from 0.0 to 1.0 using function-level observable evidence. "
        "These proxy scores are not CVSS metrics. They should focus on root-cause prioritization across vulnerability families, not generic parser complexity or generic security risk.\n\n"

        "- root_cause_likelihood: How likely this function contains or controls the core bug logic. "
        "0.0-0.3 = unlikely root cause; 0.4-0.6 = plausible candidate; 0.7-1.0 = highly likely root cause.\n"
        "- input_exposure: Whether attacker-controlled, external, file, command, environment, parser-derived, or policy-derived input plausibly reaches this function. Use caller context only as a supporting hint, not as automatic proof.\n"
        "- decision_or_validation_risk: Whether validation, bounds checks, semantic policy checks, admissibility checks, authorization checks, trust decisions, or accept/reject decisions are weak, incomplete, too permissive, inverted, or security-critical.\n"
        "  A decision/gatekeeper function should receive a high decision_or_validation_risk score only when: "
        "1) it makes a semantic valid/invalid, allow/deny, trust/untrust, or continue/stop decision; "
        "2) that decision controls whether downstream parsing, authority changes, command/path resolution, or structure updates continue; "
        "3) a wrong decision would admit malformed or untrusted input into later security-sensitive processing; and "
        "4) this decision is local to the current function.\n"
        "- state_ordering_consistency_risk: Whether the function can affect parser state, cursor/progress, declared length, authority state, filesystem namespace/root/cwd, credential/group state, check/use ordering, lock/order invariants, or security-sensitive sequence constraints.\n"
        "- failure_trigger_plausibility: Whether malformed, attacker-controlled, or untrusted input can plausibly trigger the suspected failure mode through this function, including unsafe acceptance/rejection or wrong security ordering.\n"
        "- security_boundary_relevance: Whether the function directly or structurally relates to memory, authority, path, command, trust-boundary, crypto/auth, protection mechanism, resource lifecycle, or dangerous downstream helper use.\n"
        "- evidence_strength: How strong the local function-level evidence is, independent of how severe the final vulnerability might be.\n\n"
        "Conceptual proxy: progress_control_risk should be folded into root_cause_likelihood, state_ordering_consistency_risk, and failure_trigger_plausibility. "
        "It is high when the current function controls parser traversal, loop progress, cursor/index movement, consumed/remaining length, or state transition using values derived from helper calls or untrusted input. "
        "For unchecked_callee_return_controls_loop_progress, evaluate progress_control_risk conditionally: raise it when the unchecked value can affect subsequent traversal and plausibly skip, repeat, desynchronize, or move parsing outside the expected range. "
        "It is low when a helper return value is only checked for error, does not affect traversal/progress/state, or the progress update is constant and locally bounded.\n\n"

        "Conceptual proxy: security_ordering_risk should be folded into root_cause_likelihood, decision_or_validation_risk, state_ordering_consistency_risk, failure_trigger_plausibility, and evidence_strength. "
        "It is high when a function locally performs a security-sensitive boundary transition before or around name resolution, command resolution, path resolution, or authority-dependent lookup. "
        "Treat that ordering as direct current-function evidence even if the final lookup, open, command resolution, NSS lookup, or policy primitive is implemented in a callee. "
        "It is lower when the function merely calls a helper that performs the entire transition and lookup internally, or when explicit restoration and failure handling make the ordering irrelevant to the suspected failure mode.\n\n"

        "Important calibration:\n"
        "- Do not give 0.0 merely because the full call context is missing.\n"
        "- Do not raise any proxy factor merely because caller/callee context exists; use it only when it strengthens concrete local evidence.\n"
        "- Use 0.2-0.4 for weak but relevant local evidence.\n"
        "- Use 0.4-0.6 for plausible candidates with incomplete context.\n"
        "- Use 0.7-1.0 only when the function locally concentrates the suspected failure mode: state inconsistency, length/state mismatch, progress manipulation, semantic validation failure, unsafe malformed-input acceptance, privilege/namespace transition error, trust-boundary mistake, protection bypass, command/path resolution error, or security-ordering flaw.\n"
        "- Checker/resolver/dispatcher functions should not be boosted just for being complex; boost them only when the local logic plausibly carries the specific failure mode.\n"
        "- Validation, authorization, resolver, namespace, privilege, and protection gatekeeper functions should be boosted when the local logic decides legality, admissibility, continuation, authority, or accept/reject behavior, and a wrong return value would globally change downstream behavior.\n"
        "- For functions dominated by return 0/return 1, true/false, or success/failure branches, explicitly reason about the downstream consequence of an inverted, ambiguous, or overly-permissive decision before lowering root_cause_likelihood.\n"
        "- Do not penalize a semantic validation gatekeeper solely because memory copy, allocation, or buffer write occurs in a callee or later function. "
        "If the current function controls whether invalid input reaches dangerous downstream behavior, raise decision_or_validation_risk and consider root_cause_likelihood accordingly.\n"
        "- Do not over-reward generic URI safety, validation helper, sanitization/checker, logging, or diagnostic functions with input_exposure or decision_or_validation_risk alone. "
        "If a helper only recognizes unsafe input but does not contain the failing state transition or downstream security decision, keep root_cause_likelihood and failure_trigger_plausibility lower.\n"
        "- A function that directly updates consumed/remaining counters, read cursor, state, or completion flags should score higher than a generic safety checker when malformed input could desynchronize those values.\n"
        "- A function that updates a loop index, parser cursor, read position, offset, consumed/remaining length, or progress state from a callee return value should score higher than a generic dispatcher when malformed input could make that return value skip, repeat, overrun, or desynchronize traversal. "
        "In that case, raise root_cause_likelihood, state_ordering_consistency_risk, and failure_trigger_plausibility even if the memory write or detailed parsing occurs in the callee.\n"
        "- A function that locally changes boundary state before or around lookup/resolution should score higher than a generic caller when wrong ordering, restoration, or error handling could make the lookup occur under the wrong authority, namespace, cwd, root, environment, or protection state. "
        "In that case, raise root_cause_likelihood, decision_or_validation_risk, state_ordering_consistency_risk, failure_trigger_plausibility, and evidence_strength even if the final resolution primitive occurs in a callee.\n"
        "Do not assume that the true root cause must be the function with the strongest local memory or data-manipulation primitive. Dispatcher or validation functions may be the root cause when their decision or dispatch logic controls which downstream behavior is reached.\n"
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
        "9) root_cause_likelihood: 0.0-1.0; 0.0-0.3 means unlikely root cause, 0.4-0.6 means possible candidate, 0.7-1.0 means highly likely root cause\n"
        "10) input_exposure: 0.0-1.0\n"
        "11) decision_or_validation_risk: 0.0-1.0\n"
        "12) state_ordering_consistency_risk: 0.0-1.0\n"
        "13) failure_trigger_plausibility: 0.0-1.0\n"
        "14) security_boundary_relevance: 0.0-1.0\n"
        "15) evidence_strength: 0.0-1.0\n"
        "16) confidence: 0.0-1.0; 0.0-0.3 means insufficient evidence, 0.4-0.6 means partial evidence, 0.7-1.0 means strong function-level evidence\n"
        "17) vulnerability_types: list of structured objects {family_id, name, cwe_id}; cwe_id may be null\n"
        "18) weakness_families: list using only the fixed whitelist values\n"
        "19) operation_signals: list using only the fixed operation signal enum values\n"
        "20) 3-6 concise reasons tied to the selected CVSS factors, proxy factors, root-cause likelihood, taxonomy choices, and confidence\n"
        "21) evidence snippets (include line number if you can infer)\n\n"
        "Do not output risk_level, risk_score, severity_score, prioritization_score, or cvss_vector. These are computed by Python from your factors.\n"
    )

    return (
        meta
        + call_context
        + git_part
        + "\n[CODE]\n"
        + code_part
        + "\n\n"
        + security_spec
        + "\n\n"
        + case_type_addons
        + ("\n" if case_type_addons else "")
        + call_context_guidance
        + "\n\n"
        + reasoning
        + "\n\n"
        + factor_rubric
        + "\n\n"
        + taxonomy_rubric
        + "\n\n"
        + prioritization_rubric
        + "\n\n"
        + task
    )
