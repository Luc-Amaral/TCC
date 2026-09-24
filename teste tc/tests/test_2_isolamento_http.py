import socket
import time
import requests
from scapy.all import AsyncSniffer, TCP

def executar(interface_fisica, interface_vpn):
    print("\n[*] 2. Testando Isolamento HTTP (Filtro Alvo Restrito)...")
    resultado = {"status": "INCONCLUSIVO", "detalhes": "", "amostra_vazamento": None}

    try:
        print("    [*] Resolvendo alvo HTTP para restringir captura...")
        alvo_ip = socket.gethostbyname('neverssl.com')
        filtro = f"tcp port 80 and host {alvo_ip}"
        
        print(f"    [*] Iniciando sniffer na física ({interface_fisica}) e na VPN ({interface_vpn})...")
        sniffer_fisica = AsyncSniffer(iface=interface_fisica, filter=filtro)
        sniffer_vpn = AsyncSniffer(iface=interface_vpn, filter=filtro)
        
        try:
            sniffer_fisica.start()
            sniffer_vpn.start()
            time.sleep(1)

            print("        [>] Disparando requisição alvo HTTP (Texto Claro) em background...")
            requisicao_confirmada = False
            try:
                requests.get(f'http://{alvo_ip}', timeout=4, proxies={"http": None, "https": None}, headers={'Host': 'neverssl.com'})
                requisicao_confirmada = True
            except Exception:
                pass 
            time.sleep(1)
        finally:
            sniffer_fisica.stop()
            sniffer_vpn.stop()

        pacotes_fisica = [p for p in sniffer_fisica.results if p.haslayer(TCP)]
        pacotes_vpn = [p for p in sniffer_vpn.results if p.haslayer(TCP)]

        if not requisicao_confirmada and not pacotes_fisica and not pacotes_vpn:
             resultado["detalhes"] = "A requisição falhou antes de ir para a placa de rede."
             print("    [-] RESULTADO INCONCLUSIVO: A requisição HTTP falhou silenciosamente antes de atingir a rede.")
             return resultado

        if pacotes_fisica:
            resultado["status"] = "FALHA"
            resultado["amostra_vazamento"] = pacotes_fisica[0].summary()
            resultado["detalhes"] = f"Pacote alvo TCP/80 vazou na física."
            print("    [!] FALHA DE ISOLAMENTO: Tráfego HTTP do alvo exposto na rede física.")
            print(f"        -> Amostra interceptada: {resultado['amostra_vazamento']}")
            
        elif pacotes_vpn and not pacotes_fisica:
            resultado["status"] = "SUCESSO"
            resultado["detalhes"] = "Tráfego HTTP isolado na VPN."
            print("    [+] ISOLAMENTO CONFIRMADO: Requisição HTTP encapsulada com sucesso no túnel.")
            
        else:
            resultado["status"] = "INCONCLUSIVO"
            resultado["detalhes"] = "Padrão de tráfego TCP incompleto ou não identificado."
            print("    [-] RESULTADO INCONCLUSIVO: O tráfego TCP correspondente não foi detectado pelos sensores.")

        return resultado

    except Exception as e:
        resultado["status"] = "ERRO"
        resultado["detalhes"] = str(e)
        print(f"    [-] ERRO CRÍTICO: {resultado['detalhes']}")
        return resultado