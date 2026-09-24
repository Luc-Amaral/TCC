import socket
import time
import requests
import threading
from scapy.all import sniff, DNS

def executar(ip_real, dns_real, interface_fisica):
    print("\n[*] 3. Testando Privacidade (IP e DNS via Sniffing)...")
    sucesso_ip = True
    vazamento_dns = False

    # --- 3.1 Verificação de IP Público (Forçando IPv4 e IPv6 separadamente) ---
    print("        [>] Checando mascaramento de IPv4 e vazamento de IPv6...")
    try:
        ip_v4 = requests.get('https://api.ipify.org?format=json', timeout=5).json().get('ip')
        
        # O bloco abaixo usa uma API exclusiva IPv6. Se a VPN bloquear IPv6 (correto), dará timeout/erro.
        # Se a VPN vazar (como a Touch VPN), a API retornará o IP brasileiro em hexadecimal.
        ip_v6 = None
        try:
            ip_v6 = requests.get('https://ipv6.icanhazip.com', timeout=5).text.strip()
        except requests.RequestException:
            pass # Sem IPv6 (Seguro)

        if ip_v4 == ip_real:
            print(f"    [!] FALHA NO IP: IPv4 real exposto! ({ip_v4})")
            sucesso_ip = False
        elif ip_v6 and ":" in ip_v6: # Verifica se obteve uma string hexadecimal válida de IPv6
            print(f"    [!] FALHA CRÍTICA NO IP: A VPN está vazando seu IPv6 real direto na rede! ({ip_v6})")
            sucesso_ip = False
        else:
            print(f"    [+] SUCESSO NO IP: IPv4 mascarado ({ip_v4}) e tráfego IPv6 devidamente bloqueado.")
            
    except requests.RequestException as e:
        print(f"    [-] Erro ao verificar IP: {e}")
        sucesso_ip = False

    # --- 3.2 Verificação de Vazamento de DNS ---
    def forcar_resolucao_dns():
        time.sleep(1)
        dominios_teste = ["dnsleaktest.com", "google.com", "ufmt.br"]
        print(f"        [>] Disparando resolução de DNS agressiva para: {', '.join(dominios_teste)}...")
        for d in dominios_teste:
            try: socket.getaddrinfo(d, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except Exception: pass

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

    return sucesso_ip and not vazamento_dns