---
name: remedy-unit-test-independent
description: "Build isolated unit tests for SecRemedy remediate plugins using mock AST and scan_result payloads. Use for CIS remediation test generation, context-safety assertions, and plugin validation tests without docker/ssh. Viet trigger: test doc lap remedyEng, unit test remediate, mock scan_result, test AST mutation."
argument-hint: "Provide target rule IDs or plugin files and desired coverage depth"
user-invocable: true
---

# Remedy Unit Test Independent Workflow

## Purpose
This skill standardizes how to create and run isolated unit tests for remediation plugins in SecRemedy.

It is designed for plugin tests that verify AST mutation behavior from scan_result-driven payloads, without depending on docker services, SSH access, or live nginx validation.

## When To Use
- You add or update a plugin in core/remedyEng/recommendations.
- You need fast feedback for mutation correctness.
- You want to verify input validation and context safety guards.
- You need regression tests for root-context and path-normalization edge cases.

## Do Not Use For
- End-to-end scanner + parser + remediation pipelines.
- Docker integration scenarios.
- Performance benchmarking.

## Guardrails
- Do not modify contracts/, core/scannerEng/, database/.
- Do not consume code from core/remedyEng/archive/.
- Prefer adding tests and fixtures over modifying production logic.

## Inputs
- Rule scope: all 12 remediate plugins or selected IDs.
- Expected behavior from docs/recommendations and docs/tests.
- Existing sample payload patterns from contracts/scan_result*.json.

## Canonical Test Contract
For each plugin test, set up:
- remedy.user_inputs
- remedy.child_scan_result as {file_path: [remediation entries]}
- remedy.child_ast_config as {file_path: {parsed: [...]}}

Then run:
- remedy.remediate()

Assert on:
- remedy.child_ast_modified[file_path]["parsed"]

## Coverage Matrix Per Rule
Create at least 3 groups per rule:
1. Metadata and validation:
   - id/title sanity
   - _validate_user_inputs success/failure
2. Mutation correctness:
   - expected directive mutation by action type
   - expected block placement (http/server/location)
3. Safety and edge handling:
   - root parsed context fallback
   - logical_context mismatch defense

## AST Payload Design Rules
- Keep AST fixtures minimal and explicit.
- Use only required directives to prove behavior.
- Include at least one nested block case when rule supports location-level mutation.
- Do not rely on external parser execution for unit tests.

## scan_result Mapping Checks
Add targeted tests for ASTEditor.to_context_scan where relevant:
- exact_path propagated to context
- logical_context normalization
- value to args conversion behavior
- file-path normalization assumptions

## Suggested Execution
1. Run focused tests first:
   - pytest tests/others_remedyEng_test -q
2. Run file-targeted tests after edits:
   - pytest <target_test_file> -q
3. If shared fixtures are updated, re-run remedyEng unit scope.

## Reporting Template
After each run, report:
1. Rule IDs covered
2. New tests added
3. Pass/fail summary
4. Known gaps and next tests

## Quality Checklist
- Test names identify rule ID and expected behavior.
- Every failing-path assertion includes clear reason.
- Root-context insertion mistakes are explicitly prevented.
- No dependency on docker/ssh/nginx binary.
- Changes stay within allowed folders.
