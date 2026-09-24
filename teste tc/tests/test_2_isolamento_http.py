import socket
import time
import requests
from scapy.all import AsyncSniffer, TCP, IP

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

            print(f"        [>] Disparando requisição alvo HTTP para {alvo_ip}...")
            requisicao_iniciada = False
            try:
                # Bypass de proxy forçado
                requests.get(f'http://{alvo_ip}', timeout=4, proxies={"http": None, "https": None}, headers={'Host': 'neverssl.com'})
                requisicao_iniciada = True
            except Exception as e:
                resultado["detalhes"] += f"Requisição levantou exceção: {e}. "
            time.sleep(1)
        finally:
            sniffer_fisica.stop()
            sniffer_vpn.stop()

        # Garante que só analisa pacotes que tenham o IP do alvo
        pacotes_fisica = [p for p in sniffer_fisica.results if p.haslayer(TCP) and p.haslayer(IP) and (p[IP].dst == alvo_ip or p[IP].src == alvo_ip)]
        pacotes_vpn = [p for p in sniffer_vpn.results if p.haslayer(TCP) and p.haslayer(IP) and (p[IP].dst == alvo_ip or p[IP].src == alvo_ip)]

        if not requisicao_iniciada and not pacotes_fisica and not pacotes_vpn:
             resultado["detalhes"] += "A requisição HTTP falhou silenciosamente antes de atingir a rede."
             print(f"    [-] RESULTADO INCONCLUSIVO: {resultado['detalhes']}")
             return resultado

        if pacotes_fisica:
            resultado["status"] = "FALHA"
            resultado["amostra_vazamento"] = pacotes_fisica[0].summary()
            resultado["detalhes"] += "Pacote alvo TCP/80 vazou na física."
            print("    [!] FALHA DE ISOLAMENTO: Tráfego HTTP do alvo exposto na rede física.")
            print(f"        -> Amostra interceptada: {resultado['amostra_vazamento']}")
            
        elif pacotes_vpn and not pacotes_fisica:
            resultado["status"] = "ISOLADO"
            resultado["detalhes"] += "Tráfego HTTP isolado na VPN."
            print("    [+] ISOLAMENTO CONFIRMADO: Requisição HTTP encapsulada com sucesso no túnel.")
            
        else:
            resultado["status"] = "INCONCLUSIVO"
            resultado["detalhes"] += "Padrão de tráfego TCP alvo não identificado."
            print("    [-] RESULTADO INCONCLUSIVO: O tráfego TCP correspondente não foi detectado pelos sensores.")

        return resultado

    except Exception as e:
        resultado["status"] = "ERRO"
        resultado["detalhes"] = str(e)
        print(f"    [-] ERRO CRÍTICO: {resultado['detalhes']}")
        return resultado