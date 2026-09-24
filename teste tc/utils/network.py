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
    'mullvad', 'proton', 'openvpn', 'hoxxvpn'
]

PHYSICAL_INTERFACE_KEYWORDS = [
    'wi-fi', 'wifi', 'wlan', 'ethernet', 'eth', 'lan', 'enp', 'eno', 'ens', 'em1', 'en0', 'en1'
]


def _interface_e_vpn(interface_name):
    """Verifica se o nome da interface corresponde a um padrão de VPN conhecido."""
    nome = interface_name.lower()
    return any(kw in nome for kw in VPN_INTERFACE_KEYWORDS)


def obter_tabela_rotas():
    """Captura a tabela de rotas do SO antes do teste para análise de vazamento estrutural."""
    try:
        sistema = platform.system().lower()
        if sistema == 'windows':
            saida = subprocess.run(['route', 'print', '-4'], capture_output=True, text=True, timeout=5)
            return saida.stdout
        else:
            saida = subprocess.run(['netstat', '-rn'], capture_output=True, text=True, timeout=5)
            return saida.stdout
    except Exception:
        return "Indisponível"


def interface_esta_ativa(nome_interface):
    if not nome_interface:
        return False
    try:
        status = psutil.net_if_stats().get(nome_interface)
        return bool(status and status.isup)
    except Exception:
        return False


def _obter_gateway_padrao():
    """Obtém o IP do gateway padrão do sistema."""
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
    """Coleta IPs, interfaces, rotas e converte os objetos psutil em dicionários nativos p/ JSON."""
    dados = {
        'gateway_padrao': _obter_gateway_padrao(),
        'tabela_rotas': obter_tabela_rotas(),
        'interfaces': {}
    }

    try:
        stats_gerais = psutil.net_if_stats()
        for iface, addrs in psutil.net_if_addrs().items():
            ips = []
            for addr in addrs:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    ips.append(addr.address)
            
            st = stats_gerais.get(iface)
            status_dict = {}
            
            # Conversão estrita do objeto psutil para dicionário nativo (Requisito do JSON)
            if st:
                status_dict = {
                    'isup': getattr(st, 'isup', False),
                    'duplex': getattr(st, 'duplex', 0),
                    'speed': getattr(st, 'speed', 0),
                    'mtu': getattr(st, 'mtu', 0),
                    'flags': getattr(st, 'flags', '')
                }
                
            dados['interfaces'][iface] = {
                'ips': ips,
                'status': status_dict,
            }
    except Exception:
        pass

    return dados


def detectar_interface_fisica(interface_vpn=None):
    """
    Escolhe a interface de rede física de forma inteligente.
    Penaliza interfaces virtuais e prioriza a interface que possui o Gateway Padrão.
    Evita selecionar APENAS por palavras no nome.
    """
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
        
        # O principal fator passa a ser se a placa tem acesso ao Gateway, e não só o nome.
        if gateway_padrao:
            ips_interface = info_rede.get('interfaces', {}).get(iface, {}).get('ips', [])
            if ips_interface:
                score += 15  # Peso maior para a presença de IP de Gateway
                
        if any(kw in nome for kw in PHYSICAL_INTERFACE_KEYWORDS):
            score += 10
            
        candidatos.append((score, iface))

    if not candidatos:
        return None

    candidatos.sort(key=lambda item: item[0], reverse=True)
    return candidatos[0][1]


def obter_ips_reais():
    """Detecta os IPs da máquina ignorando forçadamente os proxies do SO."""
    print("[*] Detectando IPs públicos reais da máquina (Bypass de Proxies Ativo)...")
    ips = {'v4': None, 'v6': None}
    sem_proxy = {"http": None, "https": None}
    
    try:
        ips['v4'] = requests.get('https://api.ipify.org?format=json', timeout=5, proxies=sem_proxy).json().get('ip')
        print(f"[+] IPv4 real base: {ips['v4']}")
    except Exception as e:
        print(f"[-] Sem conectividade IPv4 base: {e}")

    try:
        trace_v6 = requests.get('https://[2606:4700:4700::1111]/cdn-cgi/trace', timeout=5, proxies=sem_proxy).text
        ips['v6'] = next((linha.split('=')[1] for linha in trace_v6.splitlines() if linha.startswith('ip=')), None)
        if ips['v6']:
            print(f"[+] IPv6 real base: {ips['v6']}")
    except Exception:
        print("[-] Sem conectividade IPv6 nativa ativa.")
        
    return ips
    

def obter_dns_real():
    """Coleta a lista original de resolvedores de DNS."""
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


def detectar_ambiente_vpn(nome_processo_exato=None):
    """Procura automaticamente pela interface e processo da VPN em execução."""
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
        'mullvad', 'cyberghost', 'hide.me', 'pia', 'hoxxvpn'
    ]

    candidatos_processo = []
    for proc in psutil.process_iter(['name']):
        try:
            nome_proc = proc.info['name']
            if not nome_proc:
                continue
            
            nome_proc_sem_ext = nome_proc.lower().replace('.exe', '')
            
            if nome_processo_exato and nome_processo_exato.lower() in [nome_proc.lower(), nome_proc_sem_ext]:
                processo_detectado = proc.info['name']
                break
            elif not nome_processo_exato and any(alvo in nome_proc_sem_ext for alvo in processos_conhecidos):
                candidatos_processo.append(proc.info['name'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    if not nome_processo_exato and candidatos_processo:
        nome_interface = (interface_detectada or '').lower()
        candidatos_principais = [
            nome for nome in candidatos_processo
            if not any(marcador in nome.lower() for marcador in ('dnsblock', 'dns-block', 'helper'))
        ]
        processo_detectado = next(
            (
                nome for nome in candidatos_principais
                if nome.lower().replace('.exe', '') == nome_interface
            ),
            candidatos_principais[0] if candidatos_principais else None,
        )

    interface_fisica = detectar_interface_fisica(interface_detectada)
    if not interface_fisica:
        print("[!] Não foi possível detectar automaticamente a interface física. O usuário precisará informar manualmente.")

    return interface_detectada, processo_detectado, tipo_vpn, interface_fisica, detalhe_rede