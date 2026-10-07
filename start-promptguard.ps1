param(
  [string]$Prompt = '',
  [Parameter(ValueFromRemainingArguments=$true)][string[]]$ClaudeArgs
)

$ErrorActionPreference = 'Stop'

function Stop-ProcessTree([System.Diagnostics.Process]$RootProcess) {
  $queue = [System.Collections.Generic.Queue[int]]::new()
  $queue.Enqueue($RootProcess.Id)
  $descendants = [System.Collections.Generic.List[int]]::new()
  while ($queue.Count -gt 0) {
    $parentId = $queue.Dequeue()
    foreach ($child in @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$parentId" -ErrorAction SilentlyContinue)) {
      $descendants.Add([int]$child.ProcessId)
      $queue.Enqueue([int]$child.ProcessId)
    }
  }
  for ($i=$descendants.Count-1; $i -ge 0; $i--) { Stop-Process -Id $descendants[$i] -Force -ErrorAction SilentlyContinue }
  Stop-Process -Id $RootProcess.Id -Force -ErrorAction SilentlyContinue
  $RootProcess.WaitForExit()
}

$root = $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
  throw '설치되지 않았습니다. 먼저 repository root에서 install.cmd를 실행하세요.'
}
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Node.js를 찾지 못했습니다.' }
$claudeCommand = Get-Command claude -ErrorAction SilentlyContinue
if (-not $claudeCommand) { throw 'Claude Code CLI를 찾지 못했습니다. install.cmd의 안내에 따라 설치하세요.' }

$runtime = Join-Path $root '.runtime'
$auditDir = Join-Path $runtime 'audit'
New-Item -ItemType Directory -Force -Path $auditDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$port = Get-Random -Minimum 30001 -Maximum 38000
$bridge = Join-Path $root 'src\credsweeper-adapter\mcp-bridge.cjs'
$mcpConfig = Join-Path $runtime "mcp-$stamp.json"
$mcpConfigJson = [ordered]@{
  mcpServers = [ordered]@{
    pgdetector = [ordered]@{ command = 'node'; args = @($bridge) }
  }
} | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText($mcpConfig, $mcpConfigJson, [System.Text.UTF8Encoding]::new($false))

$env:PYTHONPATH = Join-Path $root '.venv\Lib\site-packages'
$env:PG_DETECTOR_PORT = [string]$port
$env:PG_DETECTOR_MODE = 'normal'
$env:PG_DETECTOR_URL = "http://127.0.0.1:$port"
$env:PG_MOD_AUDIT = Join-Path $auditDir "mod-audit-$stamp.json"
$seed = [guid]::NewGuid().ToString()
$env:PG_SESSION_HASH = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($seed))) -Algorithm SHA256).Hash.ToLowerInvariant()
$env:CLAUDE_CODE_ENABLE_FUNCTION_HOOKS = '1'

$worker = Join-Path $root 'src\credsweeper-adapter\worker.py'
$workerProcess = Start-Process $python -ArgumentList @($worker) -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput (Join-Path $runtime "detector-$stamp.stdout.log") -RedirectStandardError (Join-Path $runtime "detector-$stamp.stderr.log") -PassThru
try {
  $ready = $false
  for ($i=0; $i -lt 200; $i++) {
    try { Invoke-RestMethod "http://127.0.0.1:$port/health" -TimeoutSec 1 | Out-Null; $ready = $true; break }
    catch { Start-Sleep -Milliseconds 100 }
  }
  if (-not $ready -or $workerProcess.HasExited) { throw 'CredSweeper worker가 시작되지 않았습니다.' }

  Write-Host 'PromptGuard Native Mod — 체험 모드' -ForegroundColor Cyan
  Write-Host "Workspace: $(Get-Location)"
  Write-Host "Raw-free audit: $env:PG_MOD_AUDIT"
  Write-Warning '이 launcher는 Mod-only입니다. 실제 provider용 Final Guard는 포함하지 않습니다.'

  $args = @('--plugin-dir', (Join-Path $root 'src\native-mod'), '--mcp-config', $mcpConfig)
  if ($Prompt) { $args += @('-p', $Prompt) }
  if ($ClaudeArgs) { $args += $ClaudeArgs }
  & $claudeCommand.Source @args
  exit $LASTEXITCODE
} finally {
  Stop-ProcessTree $workerProcess
}
