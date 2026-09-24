import requests
import psutil
import dns.resolver

def obter_ip_real():
    print("[*] Detectando IP público real da máquina...")
    try:
        resposta = requests.get('https://api.ipify.org?format=json', timeout=5)
        ip = resposta.json().get('ip')
        print(f"[+] IP real detectado com sucesso: {ip}")
        return ip
    except requests.RequestException as e:
        print(f"[-] Erro ao obter IP real: {e}")
        return None

def obter_dns_real():
    print("[*] Detectando servidores DNS originais...")
    try:
        resolver = dns.resolver.Resolver()
        servidores_dns = resolver.nameservers
        print(f"[+] DNS originais detectados: {', '.join(servidores_dns)}")
        return servidores_dns
    except Exception as e:
        print(f"[-] Erro ao obter DNS real: {e}")
        return []

def detectar_ambiente_vpn():
    print("[*] Mapeando ambiente de rede pós-conexão (Heurística Avançada)...")
    interface_detectada = None
    processo_detectado = None
    tipo_vpn = "Desconhecido"

    # 1. DETECÇÃO DE INTERFACE
    keywords_interface = [
        'tun', 'tap', 'wg', 'ppp', 'polar', 'nord', 'tailscale', 'zerotier', 
        'cisco', 'virtual', 'vpn', 'warp', 'windscribe', 'surfshark'
    ]
    
    interfaces_ativas = psutil.net_if_stats()
    for iface, stats in interfaces_ativas.items():
        if stats.isup: 
            if_lower = iface.lower()
            
            # Ignora interfaces de sistema e placas físicas
            if "loopback" in if_lower or if_lower == "lo":
                continue
            if "wi-fi" in if_lower or "wlan" in if_lower:
                continue
                
            if any(kw in if_lower for kw in keywords_interface):
                interface_detectada = iface
                tipo_vpn = "Túnel Virtual (Auto-detectado)"
                break

    # 2. DETECÇÃO DE PROCESSOS
    processos_conhecidos = [
        'openvpn', 'wireguard', 'wg', 'nordvpn', 'nordvpn-service', 
        'protonvpn', 'tunnelbear', 'expressvpn', 'ciscocvpnd', 
        'anyconnect', 'tailscaled', 'windscribe', 'surfshark', 
        'mullvad', 'cyberghost', 'hide.me', 'pia'
    ]
    
    for proc in psutil.process_iter(['name']):
        try:
            nome_proc = proc.info['name'].lower()
            nome_proc_sem_ext = nome_proc.replace('.exe', '')
            
            if any(alvo in nome_proc_sem_ext for alvo in processos_conhecidos):
                processo_detectado = proc.info['name']
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return interface_detectada, processo_detectado, tipo_vpn