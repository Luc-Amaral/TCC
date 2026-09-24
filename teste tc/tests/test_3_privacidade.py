import socket
import time
import requests
from scapy.all import AsyncSniffer, DNS

def executar(ips_reais, dns_real, interface_fisica, interface_vpn):
    print("\n[*] 3. Testando Privacidade (IPv4/IPv6 e Roteamento DNS via Dual-Sniffing)...")
    
    resultado = {
        "status": "INCONCLUSIVO",
        "detalhes": "",
        "ip_detectado": None,
        "vazamento_dns": False
    }

    # --- 3.1 Verificação de IP Público ---
    print("        [>] Checando mascaramento e vazamentos de IP...")
    sem_proxy = {"http": None, "https": None}
    try:
        ip_v4 = None
        try:
            ip_v4 = requests.get('https://api.ipify.org?format=json', timeout=5, proxies=sem_proxy).json().get('ip')
        except requests.exceptions.ConnectionError:
            trace = requests.get('https://1.1.1.1/cdn-cgi/trace', timeout=5, proxies=sem_proxy).text
            ip_v4 = next((linha.split('=')[1] for linha in trace.splitlines() if linha.startswith('ip=')), None)

        ip_v6 = None
        estado_v6 = "Não testado"
        try:
            trace_v6 = requests.get('https://[2606:4700:4700::1111]/cdn-cgi/trace', timeout=5, proxies=sem_proxy).text
            ip_v6 = next((linha.split('=')[1] for linha in trace_v6.splitlines() if linha.startswith('ip=')), None)
            estado_v6 = f"Ativo ({ip_v6})"
        except requests.exceptions.Timeout:
            estado_v6 = "Bloqueado (Timeout/Blackhole de segurança)"
        except Exception:
            estado_v6 = "Erro de rota local (Sem placa IPv6)"

        resultado["ip_detectado"] = f"v4:{ip_v4} | v6:{estado_v6}"

        se_vazou = False
        
        # Avaliação de Terminal: IPv4
        if ip_v4 and ip_v4 == ips_reais.get('v4'):
            print(f"    [!] FALHA NO IP: IPv4 nativo exposto! ({ip_v4})")
            resultado["detalhes"] += "IPv4 real vazado. "
            se_vazou = True
        elif ip_v4:
            print(f"    [+] SUCESSO NO IP: IPv4 mascarado ({ip_v4}).")
            resultado["detalhes"] += "IPv4 mascarado. "

        # Avaliação de Terminal: IPv6
        if ip_v6 and ips_reais.get('v6') and ip_v6 == ips_reais.get('v6'):
            print(f"    [!] FALHA CRÍTICA IPv6: O túnel não intercetou o protocolo IPv6! ({ip_v6})")
            resultado["detalhes"] += "IPv6 nativo exposto. "
            se_vazou = True
        elif ip_v6:
            print(f"    [!] AVISO IPv6: Rota externa ativa, mas mascarada ({ip_v6}).")
            resultado["detalhes"] += "IPv6 ativo e mascarado pela VPN. "
        else:
            print(f"    [+] ISOLAMENTO IPv6: O tráfego IPv6 não tem rota de saída externa ({estado_v6}).")
            resultado["detalhes"] += "IPv6 isolado/desativado. "

        resultado["status"] = "FALHA" if se_vazou else "SUCESSO"

    except Exception as e:
        print("    [-] AVISO: Falha ao verificar IP externo.")
        resultado["detalhes"] += "Checagem de IP falhou. "

    # --- 3.2 Verificação Cruzada de Vazamento DNS ---
    try:
        dominios = ["dnsleaktest.com", "ufmt.br"]
        print(f"    [*] Iniciando escuta DNS (UDP/TCP Porta 53) na física e na VPN...")
        
        filtro_dns = "port 53" # Agora escuta tanto UDP quanto TCP
        
        sniffer_fisica = AsyncSniffer(iface=interface_fisica, filter=filtro_dns)
        sniffer_vpn = AsyncSniffer(iface=interface_vpn, filter=filtro_dns)
        
        try:
            sniffer_fisica.start()
            sniffer_vpn.start()
            time.sleep(1)

            print(f"        [>] Disparando resolução nativa para: {', '.join(dominios)}...")
            for d in dominios:
                try: socket.getaddrinfo(d, 80)
                except: pass
            
            time.sleep(1)
        finally:
            sniffer_fisica.stop()
            sniffer_vpn.stop()

        pacotes_vazados = [p for p in sniffer_fisica.results if p.haslayer(DNS) and p[DNS].qd]
        pacotes_vpn = [p for p in sniffer_vpn.results if p.haslayer(DNS) and p[DNS].qd]

        # Análise de Terminal: DNS
        if pacotes_vazados:
            resultado["status"] = "FALHA"
            resultado["vazamento_dns"] = True
            destinos_vazados = set([p.dst for p in pacotes_vazados if hasattr(p, 'dst')])
            usou_dns_real = any(str(d) in destinos_vazados for d in dns_real)
            
            detalhe_dns = "DNS Vazou na placa física."
            if usou_dns_real: detalhe_dns += " (E utilizou o servidor original!)"
            resultado["detalhes"] += detalhe_dns
            print(f"    [!] FALHA NO DNS: {len(pacotes_vazados)} requisições vazaram para {destinos_vazados}")
        
        elif pacotes_vpn and not pacotes_vazados:
            if resultado["status"] != "FALHA":
                resultado["status"] = "SUCESSO"
            resultado["detalhes"] += "DNS isolado no túnel."
            print("    [+] SUCESSO NO DNS: Consultas interceptadas apenas na VPN.")
        
        else:
            resultado["status"] = "INCONCLUSIVO"
            resultado["detalhes"] += "Nenhuma consulta DNS detectada (Cache local atuou)."
            print("    [-] RESULTADO INCONCLUSIVO: O sistema operativo resolveu o DNS sem gerar tráfego de rede capturável.")
        
        return resultado

    except Exception as e:
        resultado["status"] = "ERRO"
        resultado["detalhes"] += f" Erro no DNS: {str(e)}"
        return resultado