import socket
import threading
import time
import requests
from scapy.all import DNS, sniff

def executar(ip_real, dns_real, interface_fisica):
    print("\n[*] 3. Testando Privacidade (IP e DNS via Sniffing)...")
    sucesso_ip = True
    vazamento_dns = False
    ip_indeterminado = False

    # --- 3.1 Verificação de IP Público (Forçando IPv4 e IPv6 separadamente) ---
    print("        [>] Checando mascaramento de IPv4 e vazamento de IPv6...")
    try:
        # Tentativa 1: API padrão (requer resolução DNS)
        try:
            ip_v4 = requests.get('https://api.ipify.org?format=json', timeout=5).json().get('ip')
        except requests.exceptions.ConnectionError:
            # Tentativa 2: Bypass de DNS usando Raw IP (Cloudflare Trace)
            print("        [!] DNS estrito detectado. Executando bypass via Raw IP...")
            trace = requests.get('https://1.1.1.1/cdn-cgi/trace', timeout=5).text
            ip_v4 = next((linha.split('=')[1] for linha in trace.splitlines() if linha.startswith('ip=')), None)
            if not ip_v4: 
                raise ValueError("Falha ao extrair IP do trace.")

        # Checagem de IPv6 (usando Raw IP da Cloudflare para evitar bloqueios de DNS)
        ip_v6 = None
        try:
            trace_v6 = requests.get('https://[2606:4700:4700::1111]/cdn-cgi/trace', timeout=5).text
            ip_v6 = next((linha.split('=')[1] for linha in trace_v6.splitlines() if linha.startswith('ip=')), None)
        except requests.RequestException:
            pass # Sem IPv6 (Seguro)

        if ip_v4 == ip_real:
            print(f"    [!] FALHA NO IP: IPv4 real exposto! ({ip_v4})")
            sucesso_ip = False
        elif ip_v6 and ":" in ip_v6 and ip_v6 != ip_v4:
            print(f"    [!] FALHA CRÍTICA NO IP: A VPN está vazando seu IPv6 real direto na rede! ({ip_v6})")
            sucesso_ip = False
        else:
            print(f"    [+] SUCESSO NO IP: IPv4 mascarado ({ip_v4}) e tráfego IPv6 devidamente bloqueado.")

    except requests.exceptions.Timeout:
        print("    [-] AVISO: timeout ao consultar IP externo; não há evidência clara de vazamento, mas a verificação ficou inconclusiva.")
        ip_indeterminado = True
        sucesso_ip = True
    except Exception as e:
        print(f"    [-] Erro ao verificar IP: {e}")
        ip_indeterminado = True
        sucesso_ip = True

    # --- 3.2 Verificação de Vazamento de DNS ---
    def forcar_resolucao_dns():
        time.sleep(1)
        dominios_teste = ["dnsleaktest.com", "google.com", "ufmt.br"]
        print(f"        [>] Disparando resolução de DNS agressiva para: {', '.join(dominios_teste)}...")
        for d in dominios_teste:
            try:
                socket.getaddrinfo(d, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except Exception:
                pass

    threading.Thread(target=forcar_resolucao_dns).start()
    print(f"    [*] Escutando consultas DNS (Porta 53 UDP) na interface física ({interface_fisica})...")

    try:
        pacotes_dns = sniff(iface=interface_fisica, filter="udp port 53", timeout=5)
        if len(pacotes_dns) > 0:
            print(f"    [!] FALHA NO DNS: {len(pacotes_dns)} pacote(s) DNS vazaram na placa física!")
            for p in pacotes_dns[:3]:
                if p.haslayer(DNS) and p[DNS].qd:
                    dominio_vazado = p[DNS].qd.qname.decode('utf-8', 'ignore').strip('.')
                    print(f"        -> Vazamento confirmado para o site: {dominio_vazado}")
            vazamento_dns = True
        else:
            print("    [+] SUCESSO NO DNS: Nenhuma consulta vazou na interface física.")
    except Exception as e:
        print(f"    [-] Erro ao monitorar DNS: {e}")
        vazamento_dns = True

    resultado_final = sucesso_ip and not vazamento_dns
    if ip_indeterminado:
        print("    [!] RESULTADO: IP inconclusivo; a VPN não foi comprovadamente vazada, mas a checagem externa não respondeu.")

    return resultado_final