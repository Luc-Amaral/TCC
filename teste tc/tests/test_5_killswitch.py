import time
import psutil
import requests
import urllib3
from scapy.all import AsyncSniffer, TCP

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def executar(nome_processo_vpn, interface_fisica):
    print("\n[*] 5. Testando Kill-Switch (Isolamento Cronológico Estrito)...")
    
    resultado = {
        "status": "INCONCLUSIVO",
        "detalhes": "",
        "pacote_vazado": None
    }

    # 1. Localização estrita do processo
    alvo_proc = None
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            nome_limpo = proc.info['name'].lower().replace('.exe', '')
            if nome_processo_vpn.lower() in [nome_limpo, proc.info['name'].lower()]:
                alvo_proc = proc
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if not alvo_proc:
        resultado["detalhes"] = f"Processo '{nome_processo_vpn}' não encontrado de forma exata."
        print(f"    [-] AVISO: {resultado['detalhes']}")
        return resultado

    ip_alvo = "8.8.4.4"
    filtro_bpf = f"tcp port 443 and host {ip_alvo}"
    sniffer_fisica = AsyncSniffer(iface=interface_fisica, filter=filtro_bpf)
    
    try:
        # Iniciamos a escuta no silêncio, ANTES de qualquer queda
        print(f"    [*] Iniciando sensores na placa física ({interface_fisica})...")
        sniffer_fisica.start()
        time.sleep(1)

        print(f"    [!] Encerrando {alvo_proc.info['name']} (PID: {alvo_proc.info['pid']})...")
        alvo_proc.kill()
        
        # Bloqueia a execução até o SO confirmar a morte do processo (Timeout de 3s)
        alvo_proc.wait(timeout=3)
        hora_da_morte = time.time()
        print(f"    [*] Processo confirmadamente morto. (Timestamp: {hora_da_morte})")
        print("    [>] Forçando injeção de tráfego de emergência pós-queda...")

        # Gera tráfego de forma cadenciada e monitorizada
        tentativas_reais = 0
        for _ in range(5):
            try:
                requests.get(f"https://{ip_alvo}", timeout=1, verify=False, proxies={"http": None, "https": None})
            except Exception:
                pass # Exceção de rede (Timeout/Reset) é o esperado se o bloqueio funcionar
            
            tentativas_reais += 1
            time.sleep(0.4)

    except psutil.TimeoutExpired:
        resultado["detalhes"] = "O processo demorou muito para morrer. Teste abortado para evitar falso positivo cronológico."
        print(f"    [-] ERRO: {resultado['detalhes']}")
        return resultado
    except psutil.AccessDenied:
        resultado["status"] = "ERRO"
        resultado["detalhes"] = "Permissão negada pelo Windows para matar o processo da VPN."
        print(f"    [-] ERRO DE PRIVILÉGIOS: {resultado['detalhes']}")
        print("        -> DICA OBRIGATÓRIA: Feche este terminal e abra um novo PowerShell com 'Executar como Administrador'.")
        return resultado
    except psutil.NoSuchProcess:
        hora_da_morte = time.time() # Processo morreu tão rápido que não houve tempo de wait()
    finally:
        sniffer_fisica.stop()

    # 4. Filtra pacotes rigorosamente pela linha do tempo (apenas após a morte)
    pacotes_pos_queda = [p for p in sniffer_fisica.results if p.haslayer(TCP) and p[TCP].flags == 'S' and p.time > hora_da_morte]

    # 5. Avaliação do Terminal e Relatório
    if tentativas_reais == 0:
        resultado["status"] = "INCONCLUSIVO"
        resultado["detalhes"] = "Falha interna: Não foi possível injetar tráfego pós-queda."
        print("    [-] RESULTADO INCONCLUSIVO: Tráfego de teste de emergência falhou na injeção.")
        
    elif pacotes_pos_queda:
        resultado["status"] = "FALHA"
        resultado["pacote_vazado"] = pacotes_pos_queda[0].summary()
        resultado["detalhes"] = f"Fail-Open: {len(pacotes_pos_queda)} SYNs escaparam após a queda do túnel."
        print(f"    [!] FALHA CRÍTICA NO KILL-SWITCH: {len(pacotes_pos_queda)} conexões expostas na rede local!")
        print(f"        -> Amostra: {resultado['pacote_vazado']}")
        
    else:
        resultado["status"] = "BLOQUEADO"
        resultado["detalhes"] = f"Fail-Closed: {tentativas_reais} tentativas geradas e retidas com sucesso."
        print(f"    [+] BLOQUEIO CONFIRMADO: Kill-Switch atuou retendo fisicamente {tentativas_reais} requisições de rede.")

    return resultado