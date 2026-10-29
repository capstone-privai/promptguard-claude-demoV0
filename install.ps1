$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

$pythonExe = $null
$pythonPrefix = @()
if ($env:PROMPTGUARD_PYTHON -and (Test-Path -LiteralPath $env:PROMPTGUARD_PYTHON)) {
  $pythonExe = (Resolve-Path -LiteralPath $env:PROMPTGUARD_PYTHON).Path
} else {
  $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
  if ($pyLauncher) {
    foreach ($candidate in @('-3.12', '-3.14')) {
      if ($pythonExe) { break }
      # Under 'Stop', Windows PowerShell 5 turns py's "no runtime" stderr line into
      # a terminating error, so the probe runs with 'Continue'.
      $previous = $ErrorActionPreference
      $ErrorActionPreference = 'Continue'
      & $pyLauncher.Source $candidate -c "import sys" 2>$null
      $probe = $LASTEXITCODE
      $ErrorActionPreference = $previous
      if ($probe -eq 0) { $pythonExe = $pyLauncher.Source; $pythonPrefix = @($candidate) }
    }
  }
  if (-not $pythonExe) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) { $pythonExe = $pythonCommand.Source }
  }
}
if (-not $pythonExe) { throw 'Python 3.12 또는 3.14를 찾지 못했습니다. 설치하고 PATH에 추가한 뒤 다시 실행하세요.' }

$version = & $pythonExe @pythonPrefix -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
if ($LASTEXITCODE -ne 0 -or -not ($version.StartsWith('3.12.') -or $version.StartsWith('3.14.'))) {
  throw "Python 3.12 또는 3.14가 필요합니다. 현재 버전: $version"
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

$gitleaksCommand = Get-Command gitleaks -ErrorAction SilentlyContinue
$gitleaksStatus = '없음 (선택 detector 모듈이므로 건너뜀; scoop install gitleaks 또는 GitHub release 설치)'
if ($gitleaksCommand) { $gitleaksStatus = (& $gitleaksCommand.Source version) }

Write-Host ''
Write-Host 'PromptGuard Demo V0 설치 완료' -ForegroundColor Green
Write-Host "Python: $version"
Write-Host 'CredSweeper: 1.19.0 (ML OFF)'
Write-Host "Gitleaks: $gitleaksStatus"
Write-Host '권장 실행: sample-protected-project로 이동한 뒤 ..\promptguard.cmd run'
Write-Host '기존 Mod-only 데모: ..\start-promptguard.cmd'
