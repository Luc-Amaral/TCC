import nmap
import psutil
import socket

def obter_ip_interface(interface):
    """Descobre o IP local atribuído à interface da VPN."""
    try:
        addrs = psutil.net_if_addrs()
        for snic in addrs.get(interface, []):
            if snic.family == socket.AF_INET:
                return snic.address
    except Exception:
        return None
    return None

def executar(interface_vpn):
    print(f"\n[*] 4. Testando Robustez (Nmap) na interface {interface_vpn}...")
    
    ip_alvo = obter_ip_interface(interface_vpn)
    if not ip_alvo:
        print(f"    [-] Erro: Não foi possível determinar o IP da interface {interface_vpn}.")
        return False

    print(f"    [*] Iniciando Fast Scan (Top 100 portas) no IP do túnel ({ip_alvo})...")
    try:
        nm = nmap.PortScanner()
        # Executa um scan rápido (-F) e agressivo no tempo (-T4) para não travar o TCC
        nm.scan(hosts=ip_alvo, arguments='-F -T4')
        
        # Se o host nem responder ao Nmap, está perfeitamente oculto/filtrado
        if ip_alvo not in nm.all_hosts():
            print("    [+] SUCESSO: O IP da VPN está protegido (filtrou o scan completamente).")
            return True
        
        portas_abertas = []
        for proto in nm[ip_alvo].all_protocols():
            lport = nm[ip_alvo][proto].keys()
            for port in lport:
                if nm[ip_alvo][proto][port]['state'] == 'open':
                    portas_abertas.append(port)
        
        if portas_abertas:
            print(f"    [!] FALHA NA ROBUSTEZ: A VPN está expondo portas da sua máquina: {portas_abertas}")
            return False
        else:
            print("    [+] SUCESSO: Nenhuma porta indevida aberta no túnel da VPN.")
            return True

    except nmap.PortScannerError:
        print("    [-] Erro: O software Nmap não foi encontrado no sistema.")
        return False
    except Exception as e:
        print(f"    [-] Erro durante a varredura: {e}")
        return False