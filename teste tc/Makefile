PROJECT_DIR := $(CURDIR)
VENV_DIR ?= vpn_tester_env
PYTHON ?= python
NPCAP_VERSION ?= 1.86
NPCAP_FILE ?= npcap-$(NPCAP_VERSION).exe
NPCAP_URL ?= https://npcap.com/dist/$(NPCAP_FILE)

PYTHON_BIN := $(VENV_DIR)/Scripts/python.exe
PIP_BIN := $(VENV_DIR)/Scripts/pip.exe

.PHONY: help install setup venv python-deps system-deps download-npcap install-npcap check-tools test compile run clean-npcap

help:
	@echo "Alvos disponiveis:"
	@echo "  make install       Verifica tudo, cria o ambiente e instala dependencias"
	@echo "  make setup         Executa setup.ps1 diretamente"
	@echo "  make download-npcap Baixa o instalador do Npcap"
	@echo "  make install-npcap Inicia o Npcap como Administrador com WinPcap mode"
	@echo "  make check-tools   Verifica Python, route e netstat"
	@echo "  make test          Executa os testes unitarios"
	@echo "  make compile       Compila os modulos Python"
	@echo "  make run           Executa main.py"

venv:
	@powershell -NoProfile -Command "if (-not (Test-Path '$(PYTHON_BIN)')) { $(PYTHON) -m venv '$(VENV_DIR)' }"

python-deps: venv
	"$(PIP_BIN)" install --upgrade pip
	"$(PIP_BIN)" install -r requirements.txt

system-deps:
	@powershell -NoProfile -ExecutionPolicy Bypass -Command "if (-not (Get-Command route -ErrorAction SilentlyContinue)) { throw 'route nao encontrado' }; if (-not (Get-Command netstat -ErrorAction SilentlyContinue)) { throw 'netstat nao encontrado' }; Write-Host 'Ferramentas Windows route/netstat encontradas.'"

install:
	powershell -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1

setup:
	powershell -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1

check-tools:
	@"$(PYTHON_BIN)" --version
	@powershell -NoProfile -Command "Get-Command route,netstat | Select-Object Name,Source"

# O instalador e baixado, mas a instalacao exige UAC e pode exigir confirmacao do usuario.
download-npcap:
	@powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri '$(NPCAP_URL)' -OutFile '$(NPCAP_FILE)'"
	@echo "Npcap baixado em $(NPCAP_FILE)."

install-npcap: download-npcap
	@powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '$(PROJECT_DIR)\\$(NPCAP_FILE)' -ArgumentList '/winpcap_mode=yes' -Verb RunAs -Wait"
	@echo "Instalacao do Npcap concluida ou encerrada pelo instalador."

test: python-deps
	"$(PYTHON_BIN)" -m unittest tests.test_auditoria_unitaria -v

compile: python-deps
	"$(PYTHON_BIN)" -m compileall -q main.py core tests utils

run: python-deps
	"$(PYTHON_BIN)" main.py --salvar-relatorio

clean-npcap:
	@powershell -NoProfile -Command "Remove-Item -Force '$(NPCAP_FILE)' -ErrorAction SilentlyContinue"
