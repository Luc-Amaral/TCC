[CmdletBinding()]
param(
    [switch]$SkipNpcap,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Find-Python {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $python) {
        throw "Python nao encontrado. Instale Python 3.10+ e marque 'Add Python to PATH'."
    }
    return $python.Source
}

function Test-NpcapInstalled {
    $services = @('npcap', 'npf')
    foreach ($serviceName in $services) {
        if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
            return $true
        }
    }
    return $false
}

function Invoke-NativeChecked([string]$FilePath, [string[]]$Arguments) {
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath falhou com codigo de saida $LASTEXITCODE"
    }
}

function Install-Npcap {
    if (Test-NpcapInstalled) {
        Write-Host 'Npcap ja esta instalado.' -ForegroundColor Green
        return
    }

    $version = if ($env:NPCAP_VERSION) { $env:NPCAP_VERSION } else { '1.86' }
    $installerName = "npcap-$version.exe"
    $installerPath = Join-Path $projectRoot $installerName
    $url = if ($env:NPCAP_URL) { $env:NPCAP_URL } else { "https://npcap.com/dist/$installerName" }

    Write-Step "Baixando Npcap $version"
    Invoke-WebRequest -Uri $url -OutFile $installerPath -UseBasicParsing

    Write-Step 'Iniciando instalador Npcap com privilegio administrativo'
    Write-Host 'Confirme o UAC e mantenha WinPcap compatibility mode habilitado.' -ForegroundColor Yellow
    Start-Process -FilePath $installerPath -ArgumentList '/winpcap_mode=yes' -Verb RunAs -Wait

    if (-not (Test-NpcapInstalled)) {
        throw 'Npcap nao foi detectado apos o instalador. Verifique a instalacao e o servico npcap.'
    }
    Write-Host 'Npcap instalado e detectado.' -ForegroundColor Green
}

Write-Step 'Verificando Python'
$pythonPath = Find-Python
Write-Host "Python: $pythonPath"

$venvPath = Join-Path $projectRoot 'vpn_tester_env'
$venvPython = Join-Path $venvPath 'Scripts\python.exe'
if (-not (Test-Path $venvPython)) {
    Write-Step 'Criando ambiente virtual vpn_tester_env'
    & $pythonPath -m venv $venvPath
}

if (-not (Test-Path $venvPython)) {
    throw 'Nao foi possivel criar vpn_tester_env.'
}

Write-Step 'Instalando dependencias Python'
Invoke-NativeChecked $venvPython @('-m', 'pip', 'install', '--upgrade', 'pip')
Invoke-NativeChecked $venvPython @('-m', 'pip', 'install', '-r', (Join-Path $projectRoot 'requirements.txt'))

Write-Step 'Verificando imports Python'
Invoke-NativeChecked $venvPython @('-c', "import scapy, requests, psutil, dns; print('imports_python_ok')")

Write-Step 'Verificando ferramentas Windows'
foreach ($commandName in @('route', 'netstat', 'ipconfig')) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Ferramenta do Windows nao encontrada: $commandName"
    }
    Write-Host "$commandName encontrado" -ForegroundColor Green
}

if (-not $SkipNpcap) {
    Install-Npcap
}
else {
    Write-Host 'Npcap ignorado por -SkipNpcap.' -ForegroundColor Yellow
}

if (-not $SkipTests) {
    Write-Step 'Executando verificacoes locais'
    Invoke-NativeChecked $venvPython @('-m', 'unittest', 'tests.test_auditoria_unitaria', '-v')
    Invoke-NativeChecked $venvPython @('-m', 'compileall', '-q', 'main.py', 'core', 'tests', 'utils')
}

Write-Host "`nAmbiente pronto. Execute:" -ForegroundColor Green
Write-Host ".\vpn_tester_env\Scripts\Activate.ps1"
Write-Host "python main.py --salvar-relatorio"
