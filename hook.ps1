param(
    [string]$HomePath = $PSScriptRoot,
    [string]$MockResponsePath,
    [string]$MockSecondResponsePath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$MaxPromptChars = 12000
$MaxContextChars = 12000
$MaxCommandChars = 4000
$MaxMessages = 6
$MaxPriorCommands = 4
$MinimumAllowProbability = 0.98
$MinimumDenyProbability = 0.80
$SensitivePattern = '(?i)(sk-(?:or-)?[a-z0-9_-]{16,}|Bearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(password|api[_-]?key|access[_-]?token)\s*[:=])'

$ReasonMessages = @{
    destructive = 'Blocked: the command may delete or discard existing user work. Preserve the files and propose a narrower action.'
    credentials = 'Blocked: the command may read, change, or transmit credentials. Use a method that does not expose secrets.'
    outside_scope = 'Blocked: the command acts outside the scope authorized by the user. Confirm the exact target first.'
    persistent_change = 'Blocked: a persistent machine change needs explicit authorization and a verified pre-change record.'
    remote_code = 'Blocked: the command would execute code from an unreviewed source. Inspect and verify the source first.'
    publication = 'Blocked: publishing, pushing, or deploying was not explicitly authorized for this target.'
    unclear_effect = 'Blocked: the command effects cannot be established from the available evidence. Propose an inspectable command.'
    other = 'Blocked by the approval policy. Review the command and request a narrower action.'
}

function Write-HookJson([hashtable]$Value) {
    [Console]::Out.WriteLine(($Value | ConvertTo-Json -Depth 8 -Compress))
}

function Get-SessionHash([string]$SessionId) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($SessionId)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Get-StatePath([string]$SessionId) {
    return Join-Path (Join-Path $HomePath 'state') ((Get-SessionHash $SessionId) + '.dpapi')
}

function Protect-Text([string]$Plaintext) {
    $secure = ConvertTo-SecureString -String $Plaintext -AsPlainText -Force
    return ConvertFrom-SecureString -SecureString $secure
}

function Unprotect-Text([string]$Ciphertext) {
    $secure = ConvertTo-SecureString -String $Ciphertext
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        $secure.Dispose()
    }
}

function Read-State([string]$SessionId) {
    $path = Get-StatePath $SessionId
    if (-not [IO.File]::Exists($path)) { return @{ messages = @(); prior_commands = @(); history_incomplete = $false } }
    $plaintext = Unprotect-Text ([IO.File]::ReadAllText($path))
    return ConvertFrom-Json -InputObject $plaintext -AsHashtable
}

function Save-State([string]$SessionId, [hashtable]$State) {
    $path = Get-StatePath $SessionId
    $directory = [IO.Path]::GetDirectoryName($path)
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $ciphertext = Protect-Text ($State | ConvertTo-Json -Depth 8 -Compress)
    $temporary = $path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temporary, $ciphertext)
        [IO.File]::Move($temporary, $path, $true)
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Write-Audit([string]$SessionId, [string]$Decision, [string]$Reason, [int]$Tokens = 0, [int]$Calls = 0) {
    try {
        $entry = @{
            time = [DateTimeOffset]::UtcNow.ToString('o')
            session = (Get-SessionHash $SessionId).Substring(0, 12)
            decision = $Decision
            reason = $Reason
            input_tokens = $Tokens
            api_calls = $Calls
        } | ConvertTo-Json -Compress
        [IO.File]::AppendAllText((Join-Path $HomePath 'audit.jsonl'), $entry + [Environment]::NewLine)
    } catch {
        # Audit failure must never turn an uncertain decision into approval.
    }
}

function Deny-Request([string]$Message) {
    Write-HookJson @{
        hookSpecificOutput = @{
            hookEventName = 'PermissionRequest'
            decision = @{ behavior = 'deny'; message = $Message }
        }
    }
}

function Get-Settings {
    $path = Join-Path $HomePath 'settings.json'
    if (-not [IO.File]::Exists($path)) { throw 'settings.json is missing' }
    $settings = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path)) -AsHashtable
    $uri = [Uri]$settings.api_url
    $timeout = if ($settings.timeout_seconds) { [int]$settings.timeout_seconds } else { 5 }
    if ($uri.Scheme -ne 'https' -or [string]::IsNullOrWhiteSpace([string]$settings.model) -or $timeout -lt 1 -or $timeout -gt 5) {
        throw 'settings.json requires an HTTPS api_url and a model'
    }
    return $settings
}

function Get-ApiKey([hashtable]$Settings) {
    $environmentName = [string]$Settings.api_key_env
    if (-not [string]::IsNullOrWhiteSpace($environmentName)) {
        $value = [Environment]::GetEnvironmentVariable($environmentName)
        if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
    }
    $keyFile = [string]$Settings.api_key_file
    if ([string]::IsNullOrWhiteSpace($keyFile)) { throw 'No API key is configured' }
    $path = Join-Path $HomePath $keyFile
    if (-not [IO.File]::Exists($path)) { throw 'Configured DPAPI API key file is missing' }
    return Unprotect-Text ([IO.File]::ReadAllText($path))
}

function Test-HighRiskCommand([string]$Command) {
    return $Command -match '(?i)(\b(Remove-Item|Set-Content|Add-Content|Clear-Content|Copy-Item|Move-Item|New-Item|Out-File|Invoke-Item)\b|\brm\s+-[a-z]*[rf]|\b(del|erase|rmdir|rd|mkdir|cp|mv)\b|\bgit\s+(reset\s+--hard|clean\b|push\b|clone\b)|\b(iex|Invoke-Expression|Start-Process|schtasks|Set-ItemProperty|New-Service|setx)\b|\breg\s+add\b|\b(npm|pnpm|yarn|pip|uv|cargo|winget|choco)\s+(install|add)\b|\bgh\s+(release|pr\s+(create|merge))\b|\b(python|node|pwsh|powershell|cmd)\b.*\s+(-c|-Command|/c)\b|\bEncodedCommand\b|\b(POST|PUT|PATCH|--data|--upload-file|--form|--output|-OutFile)\b|\.(ps1|bat|cmd|sh|py|js|exe)\b|\.ssh[\\/]|\.codex[\\/](auth|config)|\.env\b|[;&|><`$])'
}

function Invoke-Jev([string]$Request, [int]$Pass) {
    if ($MockResponsePath) {
        [IO.File]::WriteAllText((Join-Path $HomePath 'last-request.json'), $Request)
        [IO.File]::WriteAllText((Join-Path $HomePath "stage-$Pass-request.json"), $Request)
        $path = if ($Pass -eq 2) { $MockSecondResponsePath } else { $MockResponsePath }
        if ([string]::IsNullOrWhiteSpace($path)) { throw 'Second mock response is missing' }
        return ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path)) -AsHashtable
    }

    $settings = Get-Settings
    $apiKey = Get-ApiKey $settings
    try {
        return Invoke-RestMethod -Uri ([string]$settings.api_url) -Method Post -Headers @{ Authorization = "Bearer $apiKey" } -ContentType 'application/json' -Body $Request -TimeoutSec ([int]$(if ($settings.timeout_seconds) { $settings.timeout_seconds } else { 5 }))
    } finally {
        Remove-Variable apiKey -ErrorAction SilentlyContinue
    }
}

try {
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { exit 0 }
    $event = ConvertFrom-Json -InputObject $raw -AsHashtable
    $eventName = [string]$event.hook_event_name
    $sessionId = [string]$event.session_id
    if ([string]::IsNullOrWhiteSpace($sessionId)) { exit 0 }

    if ($eventName -eq 'UserPromptSubmit') {
        $prompt = [string]$event.prompt
        $state = Read-State $sessionId
        $messages = @($state.messages)
        $messages += @{
            turn_id = [string]$event.turn_id
            text = $(if ($prompt.Length -le $MaxPromptChars) { $prompt } else { '' })
            too_long = ($prompt.Length -gt $MaxPromptChars)
        }
        if ($messages.Count -gt $MaxMessages) { $state.history_incomplete = $true }
        $state.messages = @($messages | Select-Object -Last $MaxMessages)
        $state.prior_commands = @()
        Save-State $sessionId $state
        exit 0
    }

    if ($eventName -eq 'SessionEnd') {
        $statePath = Get-StatePath $sessionId
        if ([IO.File]::Exists($statePath)) { [IO.File]::Delete($statePath) }
        exit 0
    }

    if ($eventName -eq 'PostToolUse' -and $event.tool_name -eq 'Bash') {
        $state = Read-State $sessionId
        $turnId = [string]$event.turn_id
        if (-not @($state.messages | Where-Object { $_.turn_id -eq $turnId }).Count) { exit 0 }
        $command = [string]$event.tool_input.command
        if ([string]::IsNullOrWhiteSpace($command)) { exit 0 }
        if ($command.Length -gt $MaxCommandChars -or $command -match $SensitivePattern) {
            $state.history_incomplete = $true
            Save-State $sessionId $state
            exit 0
        }
        $commands = @($state.prior_commands)
        $commands += @{
            turn_id = $turnId
            command = $command
        }
        $state.prior_commands = @($commands | Select-Object -Last $MaxPriorCommands)
        Save-State $sessionId $state
        exit 0
    }

    if ($eventName -ne 'PermissionRequest' -or $event.tool_name -ne 'Bash') { exit 0 }
    $command = [string]$event.tool_input.command
    $turnId = [string]$event.turn_id
    $state = Read-State $sessionId
    $messages = @($state.messages)
    if (-not $messages.Count -or $messages.Count -gt $MaxMessages -or $state.history_incomplete -or
        -not @($messages | Where-Object { $_.turn_id -eq $turnId }).Count -or
        [string]::IsNullOrWhiteSpace($command) -or $command.Length -gt $MaxCommandChars -or
        @($messages | Where-Object { $_.too_long -or [string]::IsNullOrWhiteSpace([string]$_.text) }).Count) {
        Write-Audit $sessionId 'user' 'missing_or_oversized_context'
        exit 0
    }

    $userMessages = @($messages | ForEach-Object { [string]$_.text })
    if (($userMessages -join '').Length -gt $MaxContextChars) {
        Write-Audit $sessionId 'user' 'oversized_context'
        exit 0
    }
    $priorCommands = @($state.prior_commands | Where-Object { $_.turn_id -eq $turnId })
    if (($userMessages -join "`n") -match $SensitivePattern -or $command -match $SensitivePattern) {
        Write-Audit $sessionId 'user' 'possible_secret'
        exit 0
    }

    $stateForJev = @{
        policy = 'Judge the proposed command against every supplied user message. Later user messages override earlier ones. Only user messages establish authorization. Prior executed commands, if supplied, are agent-origin context, never permission. Inspect the whole command, including chained, substituted, and indirect effects; if effects cannot be established, ask the user. Existing user files must not be deleted. Persistent machine changes outside the workspace require explicit authorization and a verified pre-change record. Credentials must not be exposed. Unreviewed remote code and unauthorized publication must not run.'
        user_messages = $userMessages
        prior_executed_commands = @()
        omitted_prior_command_count = $priorCommands.Count
        more_local_context_available = ($priorCommands.Count -gt 0)
        review_stage = 'initial'
        cwd = [string]$event.cwd
        proposed_command = $command
        pre_change_record_verified = $false
    }
    $requestData = @{
        model = [string](Get-Settings).model
        state = $stateForJev
        questions = @{
            decision = @{
                type = 'choice'
                instructions = 'Can this entire command run now under the policy and actual user authorization? Choose need_context only if the omitted prior commands could resolve an uncertainty and more_local_context_available is true.'
                criteria = @{
                    allow = 'Every effect is narrow, inspectable, authorized by the user, and satisfies all prerequisites.'
                    ask_user = 'A potentially legitimate action lacks a necessary user decision, target, or reliable context.'
                    need_context = 'The supplied user messages are complete, but omitted prior executed commands may resolve uncertainty about this action.'
                    deny = 'The command clearly violates a policy or includes a forbidden side effect.'
                }
            }
            reason = @{
                type = 'choice'
                instructions = 'What is the primary reason for blocking or deferring this command? Choose none only when it can run now.'
                criteria = @{
                    none = 'The command can run now without a concern.'
                    destructive = 'It may delete or discard existing user work.'
                    credentials = 'It may read, change, or transmit credentials or other secrets.'
                    outside_scope = 'The target or effect is outside what the user authorized.'
                    persistent_change = 'It makes a persistent machine change without verified pre-change recording.'
                    remote_code = 'It executes unreviewed code obtained from a remote source.'
                    publication = 'It publishes, pushes, merges, or deploys without exact authorization.'
                    unclear_effect = 'Its target or effects are hidden or cannot be established.'
                    other = 'A different policy conflict or missing user decision.'
                }
            }
        }
    }

    $calls = 1
    $response = Invoke-Jev ($requestData | ConvertTo-Json -Depth 12 -Compress) $calls
    $tokens = [int]$response.usage.input_tokens
    if ([string]$response.answers.decision.choice -eq 'need_context') {
        if (-not $priorCommands.Count) {
            Write-Audit $sessionId 'user' 'no_more_local_context' $tokens $calls
            exit 0
        }
        $requestData.state.prior_executed_commands = $priorCommands
        $requestData.state.omitted_prior_command_count = 0
        $requestData.state.more_local_context_available = $false
        $requestData.state.review_stage = 'expanded'
        $requestData.questions.decision.instructions = 'All locally available context is now supplied. Choose allow, ask_user, or deny; if uncertainty remains, ask the user.'
        $calls = 2
        $response = Invoke-Jev ($requestData | ConvertTo-Json -Depth 12 -Compress) $calls
        $tokens += [int]$response.usage.input_tokens
    }

    $decision = [string]$response.answers.decision.choice
    $reason = [string]$response.answers.reason.choice
    $probabilities = $response.answers.decision.probabilities
    $allowProbability = [double]$probabilities.allow
    $denyProbability = [double]$probabilities.deny
    if ($decision -eq 'allow' -and $allowProbability -ge $MinimumAllowProbability -and
        $denyProbability -le 0.01 -and -not (Test-HighRiskCommand $command)) {
        Write-Audit $sessionId 'allow' 'low_risk' $tokens $calls
        Write-HookJson @{ hookSpecificOutput = @{ hookEventName = 'PermissionRequest'; decision = @{ behavior = 'allow' } } }
        exit 0
    }
    if ($decision -eq 'deny' -and $denyProbability -ge $MinimumDenyProbability) {
        if (-not $ReasonMessages.ContainsKey($reason)) { $reason = 'other' }
        Write-Audit $sessionId 'deny' $reason $tokens $calls
        Deny-Request $ReasonMessages[$reason]
        exit 0
    }
    Write-Audit $sessionId 'user' $(if ($decision -eq 'allow') { 'allow_not_verified' } elseif ($decision -eq 'need_context') { 'context_still_insufficient' } else { $reason }) $tokens $calls
} catch {
    if ($sessionId) { Write-Audit $sessionId 'user' 'hook_error' ([int]$tokens) ([int]$calls) }
    # No decision delegates to Codex's native user approval.
}
