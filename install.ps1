$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

$pythonExe = $null
$pythonPrefix = @()
if ($env:PROMPTGUARD_PYTHON -and (Test-Path -LiteralPath $env:PROMPTGUARD_PYTHON)) {
  $pythonExe = (Resolve-Path -LiteralPath $env:PROMPTGUARD_PYTHON).Path
} else {
  $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
  if ($pyLauncher) {
    & $pyLauncher.Source -3.12 -c "import sys" 2>$null
    if ($LASTEXITCODE -eq 0) { $pythonExe = $pyLauncher.Source; $pythonPrefix = @('-3.12') }
  }
  if (-not $pythonExe) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) { $pythonExe = $pythonCommand.Source }
  }
}
if (-not $pythonExe) { throw 'Python 3.12를 찾지 못했습니다. Python 3.12를 설치하고 PATH에 추가한 뒤 다시 실행하세요.' }

$version = & $pythonExe @pythonPrefix -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
if ($LASTEXITCODE -ne 0 -or -not $version.StartsWith('3.12.')) {
  throw "Python 3.12가 필요합니다. 현재 버전: $version"
}

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw 'Node.js를 찾지 못했습니다. Node.js LTS를 설치한 뒤 다시 실행하세요.'
}

$venv = Join-Path $root '.venv'
$venvPython = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) {
  & $pythonExe @pythonPrefix -m venv $venv
  if ($LASTEXITCODE -ne 0) { throw 'Python virtual environment 생성에 실패했습니다.' }
}

& $venvPython -m pip install --disable-pip-version-check -r (Join-Path $root 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'CredSweeper 설치에 실패했습니다.' }

$claudeCommand = Get-Command claude -ErrorAction SilentlyContinue
if (-not $claudeCommand) {
  Write-Warning 'Claude Code CLI가 없습니다. 다음 명령으로 2.1.291을 설치하세요:'
  Write-Host 'npm install -g @anthropic-ai/claude-code@2.1.291' -ForegroundColor Yellow
} else {
  $claudeVersion = & $claudeCommand.Source --version
  if (-not ($claudeVersion -match '2\.1\.291')) {
    Write-Warning "검증 버전은 Claude Code 2.1.291입니다. 현재: $claudeVersion"
  }
}

Write-Host ''
Write-Host 'PromptGuard Demo V0 설치 완료' -ForegroundColor Green
Write-Host "Python: $version"
Write-Host 'CredSweeper: 1.19.0 (ML OFF)'
Write-Host '다음 단계: sample-protected-project로 이동한 뒤 ..\start-promptguard.cmd 실행'
