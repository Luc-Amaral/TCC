# VPN Security Tester

Projeto em Python para testar a segurança e a robustez de conexões VPN em ambiente local, com foco em quatro aspectos principais:

- Criptografia
- Integridade
- Privacidade
- Robustez / vazamento de rota


## Estrutura do projeto

- `main.py` — ponto de entrada do programa
- `core/nucleo_exec.py` — orquestração dos testes
- `tests/` — módulos dos testes individuais
- `utils/network.py` — detecção de interfaces, gateways e ambiente de rede
- `vpn_tester_env/` — ambiente virtual Python do projeto

## Como executar
1. Instale o Nmap:

Execute o instalador dando um duplo clique em `nmap-7.99-setup.exe`.

Atenção à tela do Npcap: No meio do processo, o Nmap vai abrir uma janela secundária que é justamente a instalação do driver Npcap.

Marque a caixa obrigatória: Quando essa tela aparecer, você deve marcar a opção "Install Npcap in WinPcap API-compatible Mode". Se não marcar isso, o Python continuará sem conseguir ler a sua placa de rede.

Reinicie o Terminal: Finalize a instalação, feche a janela do PowerShell atual e abra uma nova como Administrador.

2. Entre na pasta do projeto:

cd "c:\Users\lucas\Documents\academic\TCC TESTES\teste tc\copia"


3. Crie o ambiente virtual:


python -m venv vpn_tester_env


4. Ative o ambiente virtual:


.\vpn_tester_env\Scripts\Activate.ps1


5. Instale as dependências:


pip install -r requirements.txt


6. Execute o programa sem a VPN estar ligada: 

python main.py


7. irá verificar a interface(wifi, ethernet, etc), após confirmar se está correto, ira aparecer uma mensagem para ligar sua VPN, após iniciar a mesma, siga a instrução do CMD



## Fluxo de uso

Ao iniciar, o programa:

- identifica o IP público real da máquina;
- identifica os DNS originais do sistema;
- solicita que a VPN seja conectada;
- detecta a interface física e a interface da VPN;
- executa a bateria de testes;
- exibe um resumo consolidado dos resultados.

## Testes implementados

### 1. Criptografia
Verifica se o tráfego gerado pelo sistema está sendo encapsulado e protegido pela VPN, sem vazamento em texto claro pela rede local.

### 2. Integridade
Monitora tráfego HTTP em porta 80 para verificar se há acesso sem criptografia fora do túnel.

### 3. Privacidade
Analisa:

- vazamento de IP real;
- vazamento de IPv6;
- vazamento de consultas DNS na interface física.

### 4. Robustez / Fallback de rota
Verifica se há tráfego sendo enviado fora do túnel em caso de quebra de rota ou comportamento inesperado da VPN.


## Requisitos

O projeto usa bibliotecas Python como:

- `scapy`
- `requests`
- `psutil`
- `dnspython`
- `python-nmap` 


