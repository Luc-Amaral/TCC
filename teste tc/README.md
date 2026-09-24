# VPN Security Tester

Auditoria restrita de isolamento de rede L3/L4 em Windows, usando Scapy/Npcap.

## Execucao

```powershell
cd "c:\Users\lucas\Documents\academic\TCC TESTES\teste tc"
.\vpn_tester_env\Scripts\Activate.ps1
python main.py
```

Execute com a VPN desligada para coletar o baseline e conecte-a quando o programa solicitar. A captura do Scapy pode exigir PowerShell como Administrador e Npcap instalado.

## Testes ativos

1. `test_1_isolamento_payload.py`: verifica se um payload UDP conhecido aparece na interface fisica ou somente no tunel. Nao mede algoritmo ou forca criptografica.
2. `test_2_isolamento_http.py`: verifica isolamento de uma requisicao TCP/80 para o destino resolvido de `neverssl.com`.
3. `test_3_privacidade.py`: verifica baseline IPv4/IPv6, DNS TCP/UDP/53, DoH/HTTPS e DoT/TCP/853 nas interfaces fisica e VPN.
4. `test_4_isolamento_rota.py`: verifica IPv4 TCP/80 e TCP/443, IPv6 TCP/443, UDP/53 e UDP/443 com a VPN ativa.
5. `test_5_killswitch.py`: encerra o processo VPN e procura SYNs na interface fisica depois da queda. Exige privilegio administrativo e altera o estado da VPN.

## Estados

- `SUCESSO`, `ISOLADO` e `BLOQUEADO`: aprovados dentro do escopo.
- `INCONCLUSIVO` e `ERRO`: nao comprovam seguranca.
- `FALHA`: vazamento observado.

O veredicto `APROVADO NO ESCOPO` nao significa que a VPN foi comprovada segura em todos os cenarios. Ele significa que todos os testes ativos passaram dentro dos protocolos e condicoes documentados.

## Validacao local

```powershell
python -m unittest tests.test_auditoria_unitaria -v
python -m compileall -q main.py core tests utils
```

Os testes de integracao de rede sao opt-in e nao encerram a VPN:

```powershell
$env:VPN_INTEGRATION = "1"
python -m unittest tests.test_integracao_rede -v
```

O teste de kill switch da bateria principal encerra o processo VPN detectado. Execute-o somente quando puder reconectar a VPN depois.

As pastas `backup` e arquivos `.pyc` antigos nao fazem parte do caminho ativo e devem ser mantidos fora da execucao principal.
