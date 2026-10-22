import time
import socket
import psutil
import urllib3
from scapy.all import AsyncSniffer, TCP
from utils.network import obter_tabela_rotas, interface_esta_ativa

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def executar(nome_processo_vpn, interface_fisica, interface_vpn):
    print("\n[*] 5. Testando Kill-Switch (Isolamento Cronológico Estrito)...")
    
    resultado = {
        "status": "INCONCLUSIVO",
        "detalhes": "",
        "pacote_vazado": None
    }
    
    tentativas_reais = 0
    hora_da_morte = None
    captura_iniciada = False
    processo_terminou = False
    rotas_antes = obter_tabela_rotas()
    rotas_depois = None
    interface_vpn_antes = interface_esta_ativa(interface_vpn)

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
        resultado["detalhes"] = (
            f"Processo VPN '{nome_processo_vpn}' não foi identificado automaticamente; "
            "kill switch não executado."
        )
        print(f"    [-] AVISO: {resultado['detalhes']}")
        return resultado

    if any(marcador in alvo_proc.info['name'].lower() for marcador in ('dnsblock', 'dns-block', 'helper')):
        resultado["detalhes"] = (
            f"Processo '{alvo_proc.info['name']}' parece ser auxiliar; "
            "informe o processo principal da VPN para testar o kill switch."
        )
        print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
        return resultado

    ip_alvo = "8.8.4.4"
    filtro_bpf = f"tcp port 443 and host {ip_alvo}"
    sniffer_fisica = AsyncSniffer(iface=interface_fisica, filter=filtro_bpf)
    
    try:
        # Inicia a captura ANTES da morte
        print(f"    [*] Iniciando sensores na placa física ({interface_fisica}) de forma antecipada...")
        sniffer_fisica.start()
        captura_iniciada = True
        time.sleep(1)

        print(f"    [!] Encerrando violentamente {alvo_proc.info['name']} (PID: {alvo_proc.info['pid']})...")
        try:
            alvo_proc.kill()
            alvo_proc.wait(timeout=5)
            # Verifica estritamente se o processo parou de rodar
            if not alvo_proc.is_running():
                processo_terminou = True
                hora_da_morte = time.time()
        except psutil.NoSuchProcess:
            # Se sumiu instantaneamente, registramos o momento do sumiço
            processo_terminou = True
            hora_da_morte = time.time()
        except psutil.TimeoutExpired:
            resultado["detalhes"] = "O processo demorou mais de 5s para morrer. Teste abortado."
            print(f"    [-] ERRO: {resultado['detalhes']}")
            return resultado
        except psutil.AccessDenied:
            resultado["status"] = "ERRO"
            resultado["detalhes"] = "Permissão negada pelo Windows para matar o processo da VPN."
            print(f"    [-] ERRO DE PRIVILÉGIOS: {resultado['detalhes']}")
            return resultado

        if not hora_da_morte:
            resultado["detalhes"] = "O `is_running()` confirmou que a VPN continua viva. Teste abortado."
            print(f"    [-] ERRO CRÍTICO: {resultado['detalhes']}")
            return resultado

        rotas_depois = obter_tabela_rotas()
        interface_vpn_depois = interface_esta_ativa(interface_vpn)
        print(f"    [*] Processo confirmadamente morto. (Timestamp: {hora_da_morte})")
        print("    [>] Forçando injeção estrita de tráfego pós-queda...")

        # Conexões exclusivamente pós-queda confirmada
        for _ in range(5):
            tentativas_reais += 1
            try:
                conexao = socket.create_connection((ip_alvo, 443), timeout=1)
                conexao.close()
            except Exception:
                pass
            time.sleep(0.4)

    finally:
        if captura_iniciada:
            sniffer_fisica.stop()

    if not captura_iniciada or not processo_terminou or hora_da_morte is None:
        resultado["status"] = "INCONCLUSIVO"
        resultado["detalhes"] = "A captura ou a confirmação da queda da VPN não foi concluída."
        return resultado

    # Filtra EXCLUSIVAMENTE pacotes que aconteceram DEPOIS do timestamp da morte (Isolamento Cronológico)
    pacotes_pos_queda = [p for p in sniffer_fisica.results if p.haslayer(TCP) and p[TCP].flags == 'S' and p.time > hora_da_morte]
    resultado["tentativas_pos_queda"] = tentativas_reais
    resultado["syns_pos_queda"] = len(pacotes_pos_queda)
    resultado["captura_confirmada"] = captura_iniciada
    resultado["processo_terminou"] = processo_terminou
    resultado["rotas_antes"] = rotas_antes
    resultado["rotas_depois"] = rotas_depois
    resultado["interface_vpn_antes"] = interface_vpn_antes
    resultado["interface_vpn_depois"] = interface_vpn_depois

    # Avaliação do Relatório
    if tentativas_reais == 0:
        resultado["status"] = "INCONCLUSIVO"
        resultado["detalhes"] = "Falha do gerador local: Nenhuma tentativa pós-queda foi injetada."
        print("    [-] RESULTADO INCONCLUSIVO: O tráfego de teste de emergência falhou na injeção.")
        
    elif pacotes_pos_queda:
        resultado["status"] = "FALHA"
        resultado["pacote_vazado"] = pacotes_pos_queda[0].summary()
        resultado["detalhes"] = f"Fail-Open: {len(pacotes_pos_queda)} SYNs escaparam para a rede física após o término do processo."
        print(f"    [!] FALHA CRÍTICA NO KILL-SWITCH: {len(pacotes_pos_queda)} conexões expostas na rede local!")
        print(f"        -> Amostra pós-queda: {resultado['pacote_vazado']}")
        
    else:
        resultado["status"] = "BLOQUEADO"
        resultado["detalhes"] = f"Fail-Closed: Processo encerrou, e {tentativas_reais} tentativas injetadas foram bloqueadas na origem."
        print(f"    [+] BLOQUEIO CONFIRMADO: Kill-Switch atuou retendo fisicamente as {tentativas_reais} requisições.")

    return resultado