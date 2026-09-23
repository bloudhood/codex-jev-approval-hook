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

Place the project in a stable user-owned directory whose path contains no spaces, then copy `hooks.example.json` to `~/.codex/hooks.json` and replace `C:/path/to/codex-jev-approval/hook.ps1` with the absolute path of `hook.ps1`. It configures:

- `UserPromptSubmit`: pass the event JSON to `hook.ps1`.
- `PostToolUse` filtered to `Bash`: pass the event JSON to `hook.ps1`.
- `PermissionRequest` filtered to `Bash`: pass the event JSON to `hook.ps1` and use a 12-second timeout.
- `SessionEnd`: pass the event JSON to `hook.ps1`.

Keep the command in the unquoted `pwsh ... -File <path>` form. Codex runs hook commands through the session shell (`pwsh -Command` when that is PowerShell, `cmd.exe /c` otherwise); a command starting with a quoted executable path such as `"C:\Program Files\PowerShell\7\pwsh.exe" ...` is a PowerShell parse error and every hook fails with exit code 1. `tests.ps1` runs the example command through both shells.

Codex asks you to review hooks again whenever a hook command changes; open `/hooks` in a new session and trust the updated entries.

Use `approval_policy = "on-request"`, `approvals_reviewer = "user"`, and a sandbox mode that preserves Codex's intended command boundary. The hook handles only Bash permission requests; commands already permitted by the sandbox do not reach this reviewer. Keep the native user approval path enabled by using `on-request`.

## What Jev receives

The first request contains up to six user messages: the session's first message, which usually sets the task and its limits, followed by the most recent ones. Longer histories are truncated rather than sent to manual approval: messages in between are left out, messages over 4,000 characters keep their start and end, and if the total still exceeds 12,000 characters the oldest messages after the first are dropped. The request reports how many messages were left out, and Jev is told to ask the user when the command could conflict with unseen content. It also contains the proposed Bash command, its working directory, and policy instructions. It does not include assistant prose or reasoning, tool output, or the agent-written approval description. Previously executed Bash commands are omitted initially. If Jev returns `need_context`, one follow-up request may include up to four previous commands from the current turn. Secret values (bearer tokens, common API key prefixes, `password=`/`api_key=`/`token=` style assignments, private key blocks) are replaced with `[REDACTED]` before anything is stored or sent, and the request reports how many were removed. If a secret-like pattern remains after redaction, or no non-blank user message is available, the hook leaves the decision to Codex.

Only a high-confidence low-risk allow result automatically approves. High-risk command patterns, uncertain responses, API errors, and missing context fall back to native approval. Clear denials return a reason to Codex. This hook reviews requests; it is not a sandbox or a complete enforcement boundary.

A prior command over 4,000 characters is not stored; for that turn the hook never sends a follow-up request. Parallel tool calls update session state under a per-session lock. The whole decision, including a follow-up request, is kept within the hook timeout; if time runs out, Codex's native approval takes over.

Session context is encrypted with DPAPI and removed on `SessionEnd`; state left by interrupted sessions expires after seven days. `audit.jsonl` records timestamps, short session hashes, decision categories, token totals, call counts, elapsed time, and for hook errors the exception type, but not prompt or command text or error messages. Review and remove local audit data according to your retention needs.

## Test

Run `pwsh -NoProfile -File .\tests.ps1`. The tests use mock Decisions API responses and do not execute proposed shell commands or make live API calls.
