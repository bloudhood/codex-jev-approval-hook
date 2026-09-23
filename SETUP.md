# Setup

## Requirements

- Windows and PowerShell 7, since session context and file-based credentials use Windows DPAPI.
- A Codex CLI version with hooks enabled and a Jev-compatible Decisions API endpoint. The endpoint must accept the OpenRouter Decisions request shape used by this hook (`model`, `state`, `questions`) and return `answers.decision.choice`, `answers.decision.probabilities`, `answers.reason.choice`, and `usage.input_tokens`. This is not a generic chat-completions endpoint.

## Configure the API

Copy `settings.example.json` to `settings.json` beside `hook.ps1` and set:

- `api_url`: HTTPS Decisions API endpoint.
- `model`: model identifier accepted by that endpoint.
- `api_key_env`: environment variable name, preferred for managed setups.
- `api_key_file`: optional filename holding a same-user DPAPI encrypted key; set to an empty string when using only the environment variable.
- `timeout_seconds`: per-request timeout, at most 5 seconds is recommended to fit the Codex hook timeout.

To use a DPAPI file, run `pwsh -NoProfile -File .\protect-key.ps1 -OutputPath .\api-key.dpapi`; enter the key at the secure prompt. The encrypted file is bound to the current Windows user and machine and must not be copied to another account. Keep `settings.json` and `*.dpapi` private. The hook checks the environment variable first, then the encrypted file.

## Install as a Codex hook

Place the project in a stable user-owned directory and point Codex hook commands to its absolute `hook.ps1` path. Configure these events:

- `UserPromptSubmit`: pass the event JSON to `hook.ps1`.
- `PostToolUse` filtered to `Bash`: pass the event JSON to `hook.ps1`.
- `PermissionRequest` filtered to `Bash`: pass the event JSON to `hook.ps1` and use a 12-second timeout.
- `SessionEnd`: pass the event JSON to `hook.ps1`.

Use `approval_policy = "on-request"`, `approvals_reviewer = "user"`, and a sandbox mode that preserves Codex's intended command boundary. The hook handles only Bash permission requests; commands already permitted by the sandbox do not reach this reviewer. Keep the native user approval path enabled by using `on-request`.

## What Jev receives

The first request contains up to six original user messages (maximum 12,000 combined characters), the proposed Bash command, its working directory, and policy instructions. It does not include assistant prose or reasoning, tool output, or the agent-written approval description. Previously executed Bash commands are omitted initially. If Jev returns `need_context`, one follow-up request may include up to four previous commands from the current turn. If available user history is incomplete, oversized, blank, or secret-like, the hook leaves the decision to Codex.

Only a high-confidence low-risk allow result automatically approves. High-risk command patterns, uncertain responses, API errors, and missing context fall back to native approval. Clear denials return a reason to Codex. This hook reviews requests; it is not a sandbox or a complete enforcement boundary.

Session context is encrypted with DPAPI and removed on `SessionEnd`; an interrupted session may leave encrypted state behind. `audit.jsonl` records timestamps, short session hashes, decision categories, token totals, and call counts, but not prompt or command text. Review and remove local audit data according to your retention needs.

## Test

Run `pwsh -NoProfile -File .\tests.ps1`. The tests use mock Decisions API responses and do not execute proposed shell commands or make live API calls.
