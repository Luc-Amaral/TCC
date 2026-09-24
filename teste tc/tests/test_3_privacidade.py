import socket
import ssl
import time
import requests
from scapy.all import AsyncSniffer, DNS, TCP, UDP

def executar(ips_reais, dns_real, interface_fisica, interface_vpn):
    print("\n[*] 3. Testando Privacidade Estrita (IPv4, IPv6 e DNS TCP/UDP)...")
    
    resultado = {
        "status": "INCONCLUSIVO",
        "detalhes": "",
        "ip_detectado": None,
        "dominio_dns": None,
        "dns_pacotes_fisica": 0,
        "dns_pacotes_vpn": 0,
        "dns_protocolos": [],
        "ipv4_status": "INCONCLUSIVO",
        "ipv6_status": "INCONCLUSIVO",
        "dns_status": "INCONCLUSIVO",
        "doh_dot_status": "INCONCLUSIVO",
        "doh_dot_pacotes_fisica": 0,
        "doh_dot_pacotes_vpn": 0,
    }
    sem_proxy = {"http": None, "https": None}
    
    # --- 3.1 Verificação de IPv4 ---
    print("        [>] Checando mascaramento e roteamento de IP...")
    ip_v4, estado_v4 = None, "IPv4_INCONCLUSIVO"
    try:
        try:
            ip_v4 = requests.get('https://api.ipify.org?format=json', timeout=5, proxies=sem_proxy).json().get('ip')
        except Exception:
            trace = requests.get('https://1.1.1.1/cdn-cgi/trace', timeout=5, proxies=sem_proxy).text
            ip_v4 = next((l.split('=')[1] for l in trace.splitlines() if l.startswith('ip=')), None)
            
        if ip_v4:
            estado_v4 = "IPv4_MASCARADO" if ip_v4 != ips_reais.get('v4') else "IPv4_VAZADO"
    except Exception as e:
        estado_v4 = f"IPv4_ERRO"

    # --- 3.2 Verificação de IPv6 (Distinção de Estados) ---
    ip_v6, estado_v6 = None, "IPv6_INCONCLUSIVO"
    try:
        trace_v6 = requests.get('https://[2606:4700:4700::1111]/cdn-cgi/trace', timeout=5, proxies=sem_proxy).text
        ip_v6 = next((l.split('=')[1] for l in trace_v6.splitlines() if l.startswith('ip=')), None)
        if ip_v6:
            estado_v6 = "IPv6_ATIVO_MASCARADO" if ip_v6 != ips_reais.get('v6') else "IPv6_VAZADO"
    except requests.exceptions.Timeout:
        estado_v6 = "IPv6_INCONCLUSIVO"
    except Exception as e:
        estado_v6 = f"IPv6_ERRO"

    resultado["ip_detectado"] = f"v4:{estado_v4} | v6:{estado_v6}"
    resultado["ipv4_status"] = estado_v4
    resultado["ipv6_status"] = estado_v6
    
    # Analisa e imprime IPs
    status_ip = "SUCESSO"
    if estado_v4 == "IPv4_VAZADO":
        print(f"    [!] FALHA NO IP: IPv4 real exposto! ({ip_v4})")
        resultado["detalhes"] += "IPv4 original vazou. "
        status_ip = "FALHA"
    elif estado_v4 == "IPv4_MASCARADO":
        print(f"    [+] SUCESSO NO IP: IPv4 perfeitamente mascarado ({ip_v4}).")
        resultado["detalhes"] += "IPv4 mascarado. "
    else:
        print(f"    [-] INCONCLUSIVO: O sistema falhou ao obter IPv4 externo.")
        status_ip = "INCONCLUSIVO"
        
    if estado_v6 == "IPv6_VAZADO":
        print(f"    [!] FALHA CRÍTICA IPv6: O túnel não isolou a conectividade IPv6. Rota original exposta! ({ip_v6})")
        resultado["detalhes"] += "IPv6 nativo vazou. "
        status_ip = "FALHA"
    elif estado_v6 in ["IPv6_BLOQUEADO", "IPv6_ATIVO_MASCARADO"]:
        print(f"    [+] ISOLAMENTO IPv6: O tráfego IPv6 atuou com segurança ({estado_v6}).")
        resultado["detalhes"] += f"IPv6 isolado ({estado_v6}). "
    else:
        print(f"    [-] AVISO IPv6: Indisponível ou erro na placa local ({estado_v6}).")
        if status_ip != "FALHA": status_ip = "INCONCLUSIVO"

    # --- 3.3 Verificação de DNS ---
    status_dns = "INCONCLUSIVO"
    try:
        dominio_unico = f"test-{int(time.time() * 1000)}.dnsleaktest.com"
        resultado["dominio_dns"] = dominio_unico
        print(f"    [*] Iniciando escuta DNS (UDP/TCP Porta 53) para domínio único: {dominio_unico}...")
        
        filtro_dns = "port 53" 
        sniffer_fisica = AsyncSniffer(iface=interface_fisica, filter=filtro_dns)
        sniffer_vpn = AsyncSniffer(iface=interface_vpn, filter=filtro_dns)
        
        try:
            sniffer_fisica.start()
            sniffer_vpn.start()
            time.sleep(1)

            print(f"        [>] Disparando resolução nativa...")
            try: socket.getaddrinfo(dominio_unico, 80)
            except Exception: pass
            time.sleep(1)
        finally:
            sniffer_fisica.stop()
            sniffer_vpn.stop()

        pacotes_vazados = [p for p in sniffer_fisica.results if p.haslayer(DNS) and p[DNS].qd]
        pacotes_vpn = [p for p in sniffer_vpn.results if p.haslayer(DNS) and p[DNS].qd]
        resultado["dns_pacotes_fisica"] = len(pacotes_vazados)
        resultado["dns_pacotes_vpn"] = len(pacotes_vpn)
        resultado["dns_protocolos"] = sorted({
            "TCP" if p.haslayer(TCP) else "UDP" if p.haslayer(UDP) else "OUTRO"
            for p in pacotes_vazados + pacotes_vpn
        })

        if pacotes_vazados:
            status_dns = "FALHA"
            destinos = set([str(p.dst) for p in pacotes_vazados if hasattr(p, 'dst')])
            resultado["detalhes"] += f"DNS Vazou para {destinos}. "
            print(f"    [!] FALHA NO DNS: {len(pacotes_vazados)} requisições vazaram na placa física.")
        
        elif pacotes_vpn and not pacotes_vazados:
            status_dns = "ISOLADO"
            resultado["detalhes"] += f"DNS isolado na VPN. (Testes DoH/DoT ausentes). "
            print("    [+] ISOLAMENTO CONFIRMADO: Consultas DNS (TCP/UDP) retidas no túnel.")
        
        else:
            resultado["detalhes"] += "Nenhuma consulta DNS detectada (Cache local). "
            print("    [-] RESULTADO INCONCLUSIVO: O SO resolveu sem gerar tráfego capturável.")

        resultado["dns_status"] = status_dns

        # DoH e DoT sao transportes criptografados: a evidencia aqui e a rota,
        # nao a leitura de uma consulta DNS dentro do pacote.
        filtro_privado = "(tcp port 443 and host 1.1.1.1) or (tcp port 853 and host 1.1.1.1)"
        sniffer_privado_fisica = AsyncSniffer(iface=interface_fisica, filter=filtro_privado)
        sniffer_privado_vpn = AsyncSniffer(iface=interface_vpn, filter=filtro_privado)
        tentativas_privadas = 0
        try:
            sniffer_privado_fisica.start()
            sniffer_privado_vpn.start()
            time.sleep(1)

            try:
                requests.post(
                    "https://1.1.1.1/dns-query",
                    headers={"Host": "cloudflare-dns.com", "Accept": "application/dns-message"},
                    data=b"",
                    timeout=3,
                    verify=False,
                    proxies=sem_proxy,
                )
                tentativas_privadas += 1
            except Exception:
                tentativas_privadas += 1

            try:
                contexto = ssl.create_default_context()
                with socket.create_connection(("1.1.1.1", 853), timeout=3) as conexao:
                    with contexto.wrap_socket(conexao, server_hostname="cloudflare-dns.com"):
                        pass
                tentativas_privadas += 1
            except Exception:
                tentativas_privadas += 1
            time.sleep(1)
        finally:
            sniffer_privado_fisica.stop()
            sniffer_privado_vpn.stop()

        pacotes_privados_fisica = [p for p in sniffer_privado_fisica.results if p.haslayer(TCP)]
        pacotes_privados_vpn = [p for p in sniffer_privado_vpn.results if p.haslayer(TCP)]
        resultado["doh_dot_pacotes_fisica"] = len(pacotes_privados_fisica)
        resultado["doh_dot_pacotes_vpn"] = len(pacotes_privados_vpn)
        if pacotes_privados_fisica:
            resultado["doh_dot_status"] = "FALHA"
            resultado["detalhes"] += "DoH/DoT vazaram na interface fisica. "
        elif pacotes_privados_vpn:
            resultado["doh_dot_status"] = "ISOLADO"
            resultado["detalhes"] += "DoH/DoT isolados na VPN. "
        elif tentativas_privadas:
            resultado["doh_dot_status"] = "INCONCLUSIVO"
            resultado["detalhes"] += "DoH/DoT foram tentados, mas nenhum pacote foi observado. "

    except Exception as e:
        status_dns = "ERRO"
        resultado["detalhes"] += f" Erro no DNS: {str(e)}"
        print(f"    [-] ERRO CRÍTICO DNS: {str(e)}")

    # Lógica de Prioridade de Status (O Pior Status Prevalece)
    status_privado = resultado["doh_dot_status"]
    if "FALHA" in [status_ip, status_dns, status_privado]:
        resultado["status"] = "FALHA"
    elif "ERRO" in [status_ip, status_dns, status_privado]:
        resultado["status"] = "ERRO"
    elif "INCONCLUSIVO" in [status_ip, status_dns, status_privado]:
        resultado["status"] = "INCONCLUSIVO"
    else:
        resultado["status"] = "ISOLADO" # Aprovado plenamente

    return resultado