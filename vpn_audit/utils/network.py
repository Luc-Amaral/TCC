"""Utilitários de rede.

Mudanças principais em relação à versão anterior:
  * o estado de referência (interface física, gateway, adaptadores) é capturado ANTES
    de ligar a VPN, e a interface da VPN é detectada por diferença (rota padrão /
    novos adaptadores), não por palavras no nome;
  * a interface física é identificada pela rota padrão (IP -> adaptador), e não por um
    score que dava +15 a qualquer adaptador com IP;
  * a saída de `route print` é decodificada com o codepage OEM (acentos corretos) e
    interpretada em estrutura (destino, máscara, gateway, interface, métrica);
  * consulta de IP externo com fallback e classificação do tipo de erro;
  * comparação de IPv6 por prefixo /64 (endereços temporários mudam);
  * detecção de processo sem falsos positivos de tokens curtos ('wg', 'pia').
"""
import ipaddress
import os
import platform
import re
import socket
import subprocess
import sys

import psutil
import requests

try:  # opcional: só usado como fallback para listar DNS
    import dns.resolver as _dnsresolver
except Exception:  # noqa: BLE001
    _dnsresolver = None

SEM_PROXY = {"http": None, "https": None}

VPN_INTERFACE_KEYWORDS = [
    "tun", "tap", "wg", "ppp", "utun", "wireguard", "vpn", "warp",
    "nord", "tailscale", "zerotier", "cisco", "windscribe", "surfshark",
    "mullvad", "proton", "openvpn", "hoxxvpn", "tuxler", "urban", "bear",
]

PHYSICAL_INTERFACE_KEYWORDS = [
    "wi-fi", "wifi", "wlan", "ethernet", "eth", "lan", "enp", "eno", "ens", "em1", "en0", "en1",
]

_IGNORAR_NOMES = (
    "loopback", "pseudo", "docker", "vbox", "vmware", "virtualbox", "vethernet",
    "hyper-v", "bluetooth", "isatap", "teredo", "wsl",
)

PROCESSOS_CONHECIDOS = [
    "openvpn", "wireguard", "wg", "nordvpn", "nordvpn-service",
    "protonvpn", "tunnelbear", "expressvpn", "ciscocvpnd",
    "anyconnect", "tailscaled", "windscribe", "surfshark",
    "mullvad", "cyberghost", "hide.me", "pia", "hoxxvpn",
    "tuxler", "urban-vpn", "urbanvpn", "shadowsocks",
]
_MARCADORES_AUXILIAR = ("dnsblock", "dns-block", "helper")

_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
_RE_ROTA = re.compile(rf"^\s*{_IP}\s+{_IP}\s+(.+?)\s+{_IP}\s+(\d+)\s*$")
_RE_IP = re.compile(rf"^{_IP}$")
_ROTAS_PADRAO = {("0.0.0.0", "0.0.0.0"), ("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")}


# --------------------------------------------------------------------------- #
# Execução de comandos / privilégios
# --------------------------------------------------------------------------- #
def _decodificar(dados):
    if platform.system() == "Windows":
        for enc in ("oem", "cp850", "utf-8"):
            try:
                return dados.decode(enc, errors="replace")
            except LookupError:
                continue
    return dados.decode("utf-8", errors="replace")


def _executar(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        return _decodificar(r.stdout)
    except Exception:  # noqa: BLE001
        return ""


def eh_administrador():
    try:
        if platform.system() == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------- #
# Interfaces
# --------------------------------------------------------------------------- #
def _interface_e_vpn(nome):
    nome = nome.lower()
    return any(kw in nome for kw in VPN_INTERFACE_KEYWORDS)


def _e_ignoravel(nome):
    nome = nome.lower()
    return nome in {"lo", "lo0"} or any(t in nome for t in _IGNORAR_NOMES)


def interface_esta_ativa(nome_interface):
    if not nome_interface:
        return False
    try:
        st = psutil.net_if_stats().get(nome_interface)
        return bool(st and st.isup)
    except Exception:  # noqa: BLE001
        return False


def ips_da_interface(nome):
    try:
        return [a.address for a in psutil.net_if_addrs().get(nome, []) if a.family == socket.AF_INET]
    except Exception:  # noqa: BLE001
        return []


def nome_interface_por_ip(ip):
    try:
        for nome, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address == ip:
                    return nome
    except Exception:  # noqa: BLE001
        pass
    return None


def listar_interfaces_ativas():
    try:
        return sorted(
            n for n, i in psutil.net_if_stats().items()
            if i.isup and "loopback" not in n.lower() and n.lower() not in {"lo", "lo0"}
        )
    except Exception:  # noqa: BLE001
        return []


# --------------------------------------------------------------------------- #
# Tabela de rotas
# --------------------------------------------------------------------------- #
def obter_tabela_rotas():
    """Tabela de rotas (IPv4 + IPv6) em texto, para anexar ao relatório."""
    if platform.system() == "Windows":
        texto = _executar(["route", "print", "-4"]) + "\n" + _executar(["route", "print", "-6"])
    else:
        texto = _executar(["ip", "route"]) or _executar(["netstat", "-rn"])
        v6 = _executar(["ip", "-6", "route"])
        texto = texto + ("\n" + v6 if v6 else "")
    return texto.strip() or "Indisponível"


def parse_rotas_ipv4(texto):
    """Interpreta a saída do `route print -4` (independe do idioma do Windows)."""
    rotas = []
    for linha in texto.splitlines():
        m = _RE_ROTA.match(linha)
        if not m:
            continue
        destino, mascara, gw, ip_if, metrica = m.groups()
        gw = gw.strip()
        rotas.append({
            "destino": destino,
            "mascara": mascara,
            "gateway": gw if _RE_IP.match(gw) else None,
            "interface_ip": ip_if,
            "metrica": int(metrica),
        })
    return rotas


def _parse_ip_route_linux(texto):
    rotas = []
    for linha in texto.splitlines():
        tok = linha.split()
        if not tok:
            continue
        try:
            destino = "0.0.0.0/0" if tok[0] == "default" else (tok[0] if "/" in tok[0] else tok[0] + "/32")
            rede = ipaddress.ip_network(destino, strict=False)
        except ValueError:
            continue

        def _depois(chave):
            return tok[tok.index(chave) + 1] if chave in tok and tok.index(chave) + 1 < len(tok) else None

        dev, src, gw, metrica = _depois("dev"), _depois("src"), _depois("via"), _depois("metric")
        ip_if = src or (ips_da_interface(dev)[0] if dev and ips_da_interface(dev) else "")
        rotas.append({
            "destino": str(rede.network_address),
            "mascara": str(rede.netmask),
            "gateway": gw if gw and _RE_IP.match(gw) else None,
            "interface_ip": ip_if,
            "metrica": int(metrica) if metrica and metrica.isdigit() else 0,
        })
    return rotas


def obter_rotas_ipv4():
    if platform.system() == "Windows":
        return parse_rotas_ipv4(_executar(["route", "print", "-4"]))
    return _parse_ip_route_linux(_executar(["ip", "-4", "route"]))


def melhor_rota_padrao(rotas):
    """Rota padrão efetiva: 0/0 ou o par 0/1 + 128/1 usado pelas VPNs, de menor métrica."""
    candidatas = [r for r in rotas if (r["destino"], r["mascara"]) in _ROTAS_PADRAO]
    return min(candidatas, key=lambda r: r["metrica"]) if candidatas else None


def endpoints_de_tunel(rotas, gateway_fisico):
    """Rotas /32 de IP público via gateway físico: normalmente o servidor da VPN."""
    achados = []
    for r in rotas:
        if r["mascara"] != "255.255.255.255" or r["gateway"] != gateway_fisico:
            continue
        try:
            ip = ipaddress.ip_address(r["destino"])
        except ValueError:
            continue
        if ip.is_global:
            achados.append(r["destino"])
    return sorted(set(achados))


# --------------------------------------------------------------------------- #
# Estado de referência (ANTES de ligar a VPN)
# --------------------------------------------------------------------------- #
def _fallback_interface_fisica():
    try:
        stats = psutil.net_if_stats()
        enderecos = psutil.net_if_addrs()
    except Exception:  # noqa: BLE001
        return None
    candidatas = []
    for nome, st in stats.items():
        if not st.isup or _e_ignoravel(nome) or _interface_e_vpn(nome):
            continue
        ips = [a.address for a in enderecos.get(nome, [])
               if a.family == socket.AF_INET and not a.address.startswith("169.254.")]
        if not ips:
            continue
        pontos = 10 if any(k in nome.lower() for k in PHYSICAL_INTERFACE_KEYWORDS) else 0
        candidatas.append((pontos, nome))
    candidatas.sort(key=lambda x: x[0], reverse=True)
    return candidatas[0][1] if candidatas else None


def obter_dns_interface(nome):
    """Servidores DNS configurados em UMA interface (Windows, via PowerShell)."""
    if not nome or platform.system() != "Windows":
        return []
    nome_esc = nome.replace("'", "''")
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
           f"(Get-DnsClientServerAddress -InterfaceAlias '{nome_esc}' -AddressFamily IPv4).ServerAddresses"]
    saida = _executar(cmd, timeout=15)
    return [l.strip() for l in saida.splitlines() if _RE_IP.match(l.strip())]


def capturar_estado_base():
    """Fotografia da máquina SEM VPN: gateway, interface física, adaptadores e processos."""
    rotas = obter_rotas_ipv4()
    rp = melhor_rota_padrao(rotas)
    gateway = rp["gateway"] if rp else None
    ip_fisico = rp["interface_ip"] if rp else None
    iface = nome_interface_por_ip(ip_fisico) if ip_fisico else None
    metodo = "rota_padrao"
    if not iface:
        iface = _fallback_interface_fisica()
        metodo = "fallback_heuristico" if iface else None

    stats = psutil.net_if_stats()
    enderecos = {
        n: [a.address for a in addrs if a.family in (socket.AF_INET, socket.AF_INET6)]
        for n, addrs in psutil.net_if_addrs().items()
    }
    processos = set()
    for p in psutil.process_iter(["name"]):
        try:
            if p.info["name"]:
                processos.add(p.info["name"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return {
        "gateway": gateway,
        "interface_fisica": iface,
        "ip_fisico": ip_fisico or (ips_da_interface(iface)[0] if iface and ips_da_interface(iface) else None),
        "metodo_interface_fisica": metodo,
        "interfaces_ativas": sorted(n for n, s in stats.items() if s.isup),
        "enderecos": enderecos,
        "rotas_ipv4": rotas,
        "dns_interface_fisica": obter_dns_interface(iface),
        "processos": sorted(processos),
    }


# --------------------------------------------------------------------------- #
# Detecção da VPN (DEPOIS de ligá-la), por diferença em relação ao estado base
# --------------------------------------------------------------------------- #
def detectar_interface_vpn(estado_base):
    """Retorna (interface, método). Ordem: dona da rota padrão > novo adaptador > nome."""
    fisica = estado_base.get("interface_fisica")
    base_ativas = set(estado_base.get("interfaces_ativas", []))

    rp = melhor_rota_padrao(obter_rotas_ipv4())
    if rp:
        nome = nome_interface_por_ip(rp["interface_ip"])
        if nome and nome != fisica and not _e_ignoravel(nome):
            return nome, "rota_padrao"

    try:
        stats = psutil.net_if_stats()
        enderecos = psutil.net_if_addrs()
    except Exception:  # noqa: BLE001
        return None, None
    novas = []
    for nome, st in stats.items():
        if not st.isup or nome == fisica or nome in base_ativas or _e_ignoravel(nome):
            continue
        if any(a.family == socket.AF_INET and not a.address.startswith("169.254.")
               for a in enderecos.get(nome, [])):
            novas.append(nome)
    if novas:
        preferidas = [n for n in novas if _interface_e_vpn(n)]
        return (preferidas or novas)[0], "novo_adaptador"
    return None, None


def _nome_confere(token, stem):
    if len(token) <= 3:
        return stem == token or stem.startswith((token + "-", token + ".", token + "_"))
    return token in stem


def detectar_processo_vpn(estado_base, nome_exato=None):
    """Retorna (nome_processo, info). Prefere processos que surgiram depois do baseline."""
    base = set(estado_base.get("processos", [])) if estado_base else set()
    candidatos = []
    for proc in psutil.process_iter(["name"]):
        try:
            nome = proc.info["name"]
            if not nome:
                continue
            stem = nome.lower().replace(".exe", "")
            if nome_exato:
                if nome_exato.lower() in (nome.lower(), stem):
                    candidatos.append((nome, proc))
            elif any(_nome_confere(t, stem) for t in PROCESSOS_CONHECIDOS):
                candidatos.append((nome, proc))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    if not nome_exato:
        candidatos = [c for c in candidatos
                      if not any(m in c[0].lower() for m in _MARCADORES_AUXILIAR)]
    if not candidatos:
        return None, {}
    candidatos.sort(key=lambda c: (c[0] in base, c[0].lower()))  # novos primeiro
    nome, proc = candidatos[0]
    info = {"pid": proc.pid, "nome": nome}
    for chave, fn in (("exe", proc.exe), ("cmdline", proc.cmdline)):
        try:
            info[chave] = fn()
        except Exception:  # noqa: BLE001
            info[chave] = None
    return nome, info


def listar_processos_novos(estado_base, limite=20):
    base = set(estado_base.get("processos", []))
    agora = set()
    for p in psutil.process_iter(["name"]):
        try:
            if p.info["name"]:
                agora.add(p.info["name"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return sorted(agora - base)[:limite]


def detectar_ambiente_vpn(estado_base, nome_processo_exato=None):
    """(interface_vpn, método, processo, info_processo, detalhe_rede)."""
    print("[*] Mapeando ambiente de rede pós-conexão (diferença em relação ao baseline)...")
    interface, metodo = detectar_interface_vpn(estado_base)
    processo, info = detectar_processo_vpn(estado_base, nome_processo_exato)
    return interface, metodo, processo, info, obter_informacoes_redes()


def obter_informacoes_redes():
    """IPs, interfaces e rotas em tipos nativos (serializáveis em JSON)."""
    rotas = obter_rotas_ipv4()
    rp = melhor_rota_padrao(rotas)
    dados = {
        "gateway_padrao": rp["gateway"] if rp else None,
        "rota_padrao_efetiva": rp,
        "rotas_ipv4": rotas,
        "tabela_rotas": obter_tabela_rotas(),
        "interfaces": {},
    }
    try:
        stats = psutil.net_if_stats()
        for iface, addrs in psutil.net_if_addrs().items():
            ips = [a.address for a in addrs if a.family in (socket.AF_INET, socket.AF_INET6)]
            st = stats.get(iface)
            dados["interfaces"][iface] = {
                "ips": ips,
                "status": {
                    "isup": bool(getattr(st, "isup", False)),
                    "duplex": int(getattr(st, "duplex", 0)),
                    "speed": int(getattr(st, "speed", 0)),
                    "mtu": int(getattr(st, "mtu", 0)),
                } if st else {},
            }
    except Exception:  # noqa: BLE001
        pass
    return dados


def obter_detalhes_interface(iface):
    ips = ips_da_interface(iface)
    gateway = None
    for r in sorted(obter_rotas_ipv4(), key=lambda r: r["metrica"]):
        if (r["destino"], r["mascara"]) == ("0.0.0.0", "0.0.0.0") and r["interface_ip"] in ips:
            gateway = r["gateway"]
            break
    return {"interface": iface, "ips": ips, "gateway_padrao": gateway}


# --------------------------------------------------------------------------- #
# IP externo, IPv6, geolocalização de saída
# --------------------------------------------------------------------------- #
def _tipo_erro(exc):
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "conexao"
    return "outro"


def _ip_do_trace(texto):
    return next((l.split("=", 1)[1].strip() for l in texto.splitlines() if l.startswith("ip=")), None)


def consultar_ipv4(timeout=6):
    """(ip, tipo_erro). Tenta ipify e, se falhar, o trace da Cloudflare."""
    erro = None
    try:
        ip = requests.get("https://api.ipify.org?format=json", timeout=timeout, proxies=SEM_PROXY).json().get("ip")
        if ip:
            return ip, None
    except Exception as exc:  # noqa: BLE001
        erro = _tipo_erro(exc)
    try:
        ip = _ip_do_trace(requests.get("https://1.1.1.1/cdn-cgi/trace", timeout=timeout, proxies=SEM_PROXY).text)
        if ip:
            return ip, None
    except Exception as exc:  # noqa: BLE001
        erro = _tipo_erro(exc)
    return None, erro


def consultar_ipv6(timeout=6):
    """(ip, tipo_erro) usando o trace da Cloudflare por endereço IPv6 literal."""
    try:
        texto = requests.get("https://[2606:4700:4700::1111]/cdn-cgi/trace", timeout=timeout, proxies=SEM_PROXY).text
        ip = _ip_do_trace(texto)
        return (ip, None) if ip else (None, "outro")
    except Exception as exc:  # noqa: BLE001
        return None, _tipo_erro(exc)


def mesmo_prefixo64(a, b):
    try:
        return ipaddress.ip_network(f"{a}/64", strict=False) == ipaddress.ip_network(f"{b}/64", strict=False)
    except ValueError:
        return a == b


def info_saida(ip):
    """País/ASN do IP de saída (ipwho.is, HTTPS). Retorna None se indisponível."""
    if not ip:
        return None
    try:
        d = requests.get(f"https://ipwho.is/{ip}", timeout=6, proxies=SEM_PROXY).json()
        if d.get("success") is False:
            return None
        con = d.get("connection") or {}
        return {
            "ip": ip,
            "pais": d.get("country"),
            "cidade": d.get("city"),
            "asn": con.get("asn"),
            "organizacao": con.get("org"),
            "isp": con.get("isp"),
        }
    except Exception:  # noqa: BLE001
        return None


def obter_ips_reais():
    print("[*] Detectando IPs públicos reais da máquina (bypass de proxies ativo)...")
    ips = {"v4": None, "v6": None}
    ips["v4"], erro4 = consultar_ipv4()
    if ips["v4"]:
        print(f"[+] IPv4 real base: {ips['v4']}")
    else:
        print(f"[-] Sem conectividade IPv4 base ({erro4}).")
    ips["v6"], _ = consultar_ipv6()
    if ips["v6"]:
        print(f"[+] IPv6 real base: {ips['v6']}")
    else:
        print("[-] Sem conectividade IPv6 nativa (o teste de IPv6 será 'não aplicável').")
    return ips


def obter_dns_real():
    """Lista de resolvedores vista pelo dnspython (no Windows junta TODOS os adaptadores).

    Use `capturar_estado_base()['dns_interface_fisica']` quando precisar do DNS da placa física.
    """
    if _dnsresolver is None:
        return []
    try:
        return [str(s) for s in _dnsresolver.Resolver().nameservers]
    except Exception:  # noqa: BLE001
        return []


def versoes_dependencias():
    versoes = {"python": sys.version.split()[0], "so": f"{platform.system()} {platform.release()}",
               "versao_so": platform.version()}
    for nome in ("scapy", "psutil", "requests", "speedtest", "matplotlib"):
        try:
            mod = __import__(nome)
            versoes[nome] = getattr(mod, "__version__", "?")
        except Exception:  # noqa: BLE001
            versoes[nome] = None
    return versoes
