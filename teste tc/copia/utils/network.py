import platform
import re
import socket
import subprocess

import dns.resolver
import psutil
import requests

VPN_INTERFACE_KEYWORDS = [
    'tun', 'tap', 'wg', 'ppp', 'utun', 'wireguard', 'virtual', 'vpn', 'warp',
    'nord', 'tailscale', 'zerotier', 'cisco', 'windscribe', 'surfshark',
    'mullvad', 'proton', 'openvpn'
]

PHYSICAL_INTERFACE_KEYWORDS = [
    'wi-fi', 'wifi', 'wlan', 'ethernet', 'eth', 'lan', 'enp', 'eno', 'ens', 'em1', 'en0', 'en1'
]


def _interface_e_vpn(interface_name):
    nome = interface_name.lower()
    return any(kw in nome for kw in VPN_INTERFACE_KEYWORDS)


def _obter_gateway_padrao():
    sistema = platform.system().lower()
    try:
        if sistema == 'windows':
            saida = subprocess.run(
                ['cmd', '/c', 'route print 0.0.0.0 mask 0.0.0.0'],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            linhas = saida.stdout.splitlines()
            for linha in linhas:
                if '0.0.0.0' in linha and 'Gateway' not in linha:
                    partes = linha.split()
                    if len(partes) >= 3 and partes[0] == '0.0.0.0':
                        return partes[2]
            return None

        comandos = [
            ['ip', 'route', 'show', 'default'],
            ['netstat', '-rn'],
            ['route', '-n'],
        ]
        for comando in comandos:
            try:
                saida = subprocess.run(comando, capture_output=True, text=True, timeout=10, check=False)
                texto = saida.stdout.strip()
                if not texto:
                    continue
                for linha in texto.splitlines():
                    if 'default' in linha.lower() or '0.0.0.0' in linha:
                        match = re.search(r'(?:via\s+)(\d+\.\d+\.\d+\.\d+)', linha)
                        if match:
                            return match.group(1)
                        partes = linha.split()
                        if len(partes) >= 3:
                            return partes[2]
            except Exception:
                continue
        return None
    except Exception:
        return None


def obter_informacoes_redes():
    dados = {
        'gateway_padrao': _obter_gateway_padrao(),
        'interfaces': {}
    }

    try:
        for iface, addrs in psutil.net_if_addrs().items():
            ips = []
            for addr in addrs:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    ips.append(addr.address)
            dados['interfaces'][iface] = {
                'ips': ips,
                'status': psutil.net_if_stats().get(iface),
            }
    except Exception:
        pass

    return dados


def detectar_interface_fisica(interface_vpn=None):
    """Escolhe a interface de rede física mais provável, ignorando a VPN e interfaces virtuais."""
    try:
        interfaces_ativas = psutil.net_if_stats()
    except Exception:
        return None

    info_rede = obter_informacoes_redes()
    gateway_padrao = info_rede.get('gateway_padrao')
    candidatos = []

    for iface, stats in interfaces_ativas.items():
        if not getattr(stats, 'isup', False):
            continue

        nome = iface.lower()
        if 'loopback' in nome or nome in {'lo', 'lo0'}:
            continue
        if interface_vpn and iface == interface_vpn:
            continue
        if _interface_e_vpn(iface):
            continue
        if any(token in nome for token in ['docker', 'vbox', 'vmware', 'bridge', 'virtual']):
            continue

        score = 0
        if any(kw in nome for kw in PHYSICAL_INTERFACE_KEYWORDS):
            score += 10
        if gateway_padrao:
            ips_interface = info_rede.get('interfaces', {}).get(iface, {}).get('ips', [])
            if ips_interface:
                score += 5
        if not any(token in nome for token in ['docker', 'vbox', 'vmware', 'bridge', 'virtual']):
            score += 5
        candidatos.append((score, iface))

    if not candidatos:
        return None

    candidatos.sort(key=lambda item: item[0], reverse=True)
    return candidatos[0][1]


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
        print(f"[+] DNS originais detectados: {', '.join(map(str, servidores_dns))}")
        return servidores_dns
    except Exception as e:
        print(f"[-] Erro ao obter DNS real: {e}")
        return []


def listar_interfaces_ativas():
    """Retorna as interfaces ativas para exibição ao usuário."""
    try:
        stats = psutil.net_if_stats()
        interfaces = []
        for iface, info in stats.items():
            if getattr(info, 'isup', False):
                nome = iface.lower()
                if 'loopback' in nome or nome in {'lo', 'lo0'}:
                    continue
                interfaces.append(iface)
        return sorted(interfaces)
    except Exception:
        return []


def obter_detalhes_interface(iface):
    """Retorna IPs e gateway de uma interface para ajudar na confirmação do usuário."""
    try:
        addrs = psutil.net_if_addrs().get(iface, [])
        ips = []
        for addr in addrs:
            if addr.family in (socket.AF_INET, socket.AF_INET6):
                ips.append(addr.address)

        gateway = _obter_gateway_padrao()
        return {
            'interface': iface,
            'ips': ips,
            'gateway_padrao': gateway,
        }
    except Exception:
        return {'interface': iface, 'ips': [], 'gateway_padrao': None}


def detectar_ambiente_vpn():
    print("[*] Mapeando ambiente de rede pós-conexão (Heurística Avançada)...")
    interface_detectada = None
    processo_detectado = None
    tipo_vpn = "Desconhecido"
    detalhe_rede = obter_informacoes_redes()

    interfaces_ativas = psutil.net_if_stats()
    for iface, stats in interfaces_ativas.items():
        if not getattr(stats, 'isup', False):
            continue

        nome = iface.lower()
        if 'loopback' in nome or nome in {'lo', 'lo0'}:
            continue
        if _interface_e_vpn(iface):
            interface_detectada = iface
            tipo_vpn = "Túnel Virtual (Auto-detectado)"
            break

    processos_conhecidos = [
        'openvpn', 'wireguard', 'wg', 'nordvpn', 'nordvpn-service',
        'protonvpn', 'tunnelbear', 'expressvpn', 'ciscocvpnd',
        'anyconnect', 'tailscaled', 'windscribe', 'surfshark',
        'mullvad', 'cyberghost', 'hide.me', 'pia', 'vpn'
    ]

    for proc in psutil.process_iter(['name']):
        try:
            nome_proc = proc.info['name']
            if not nome_proc:
                continue
            nome_proc_sem_ext = nome_proc.lower().replace('.exe', '')
            if any(alvo in nome_proc_sem_ext for alvo in processos_conhecidos):
                processo_detectado = proc.info['name']
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    interface_fisica = detectar_interface_fisica(interface_detectada)
    if not interface_fisica:
        print("[!] Não foi possível detectar automaticamente a interface física. O usuário precisará informar manualmente.")

    return interface_detectada, processo_detectado, tipo_vpn, interface_fisica, detalhe_rede