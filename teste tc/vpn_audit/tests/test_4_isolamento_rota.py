import socket
import time

import urllib3
from scapy.all import IP, IPv6, TCP, UDP

from utils.captura import Captura, GrupoCapturas

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ALVOS_TCP_V4 = [("1.1.1.1", 80), ("1.1.1.1", 443), ("8.8.8.8", 443)]
ALVO_TCP_V6 = ("2606:4700:4700::1111", 443)
# Candidatos UDP; os que coincidirem com o DNS real da máquina são descartados para
# não confundir o tráfego do sistema com o do teste.
CANDIDATOS_UDP = [("9.9.9.9", 53), ("1.1.1.1", 443), ("8.8.4.4", 53)]


def _syn(ip, porta, v6, portas_tcp):
    familia = socket.AF_INET6 if v6 else socket.AF_INET
    s = socket.socket(familia, socket.SOCK_STREAM)
    s.settimeout(1.5)
    try:
        s.bind(("::" if v6 else "", 0))
        portas_tcp.add(s.getsockname()[1])  # a porta de origem identifica o nosso SYN
        try:
            s.connect((ip, porta))
        except OSError:
            pass
    finally:
        s.close()


def _udp(ip, porta, portas_udp):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("", 0))
        portas_udp.add(s.getsockname()[1])
        s.sendto(b"TEST_UDP_ROUTE", (ip, porta))
    except OSError:
        pass
    finally:
        s.close()


def _camada_ip(p):
    return p[IP] if p.haslayer(IP) else (p[IPv6] if p.haslayer(IPv6) else None)


def executar(interface_fisica, interface_vpn, testar_ipv6=False, dns_real=None):
    print("\n[*] 4. Testando Isolamento de Rotas Nativa (TCP/UDP, IPv4 e IPv6 quando disponível)...")
    resultado = {"status": "INCONCLUSIVO", "detalhes": "", "pacote_vazado": None,
                 "destinos_testados": [], "observados_no_tunel": [], "nao_observados": [],
                 "pacotes_vazados": 0}
    dns_real = set(dns_real or [])
    alvos_udp = [a for a in CANDIDATOS_UDP if a[0] not in dns_real]
    alvos_tcp = list(ALVOS_TCP_V4)
    if testar_ipv6:
        alvos_tcp.append(ALVO_TCP_V6)

    try:
        ips = sorted({a[0] for a in alvos_tcp + alvos_udp})
        filtro = "(" + " or ".join(f"host {ip}" for ip in ips) + ") and (tcp or udp)"
        cap_f = Captura(interface_fisica, filtro, "física")
        cap_v = Captura(interface_vpn, filtro, "VPN")
        portas_tcp, portas_udp = set(), set()
        print(f"    [*] Monitorando {len(alvos_tcp)} destinos TCP e {len(alvos_udp)} UDP "
              f"(IPv6 {'incluído' if testar_ipv6 else 'não testado: sem IPv6 nativo'})...")

        with GrupoCapturas(cap_f, cap_v):
            for ip, porta in alvos_tcp:
                v6 = ":" in ip
                print(f"        [>] TCP {'IPv6' if v6 else 'IPv4'} -> {ip}:{porta}")
                _syn(ip, porta, v6, portas_tcp)
                resultado["destinos_testados"].append(f"TCP/{porta}@{ip}")
            for ip, porta in alvos_udp:
                print(f"        [>] UDP -> {ip}:{porta}")
                _udp(ip, porta, portas_udp)
                resultado["destinos_testados"].append(f"UDP/{porta}@{ip}")
            time.sleep(1)

        def nossos(pacotes):
            saida = []
            for p in pacotes:
                ip = _camada_ip(p)
                if ip is None:
                    continue
                if p.haslayer(TCP) and p[TCP].sport in portas_tcp and (int(p[TCP].flags) & 0x12) == 0x02:
                    saida.append(("TCP", p[TCP].dport, ip.dst, p))
                elif p.haslayer(UDP) and p[UDP].sport in portas_udp:
                    saida.append(("UDP", p[UDP].dport, ip.dst, p))
            return saida

        vazados, no_tunel = nossos(cap_f.pacotes), nossos(cap_v.pacotes)
        resultado["pacotes_vazados"] = len(vazados)
        vistos = sorted({f"{proto}/{porta}@{dst}" for proto, porta, dst, _ in no_tunel})
        resultado["observados_no_tunel"] = vistos
        resultado["nao_observados"] = [d for d in resultado["destinos_testados"] if d not in vistos]

        if vazados:
            resultado["status"] = "FALHA"
            resultado["pacote_vazado"] = vazados[0][3].summary()
            resultado["detalhes"] = f"{len(vazados)} pacote(s) de teste saíram pela placa física."
            print("    [!] FALHA DE ISOLAMENTO: tráfego de teste ignorou a VPN e vazou!")
            print(f"        -> {resultado['pacote_vazado']}")
        elif not cap_f.iniciou:
            resultado["detalhes"] = f"Sensor da física não iniciou: {cap_f.erro}"
            print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
        elif not cap_v.iniciou:
            resultado["detalhes"] = f"Sensor da VPN não iniciou: {cap_v.erro}"
            print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
        elif vistos:
            resultado["status"] = "ISOLADO"
            resultado["detalhes"] = (f"{len(vistos)}/{len(resultado['destinos_testados'])} destinos observados "
                                     f"apenas no túnel; nenhum na física.")
            if resultado["nao_observados"]:
                resultado["detalhes"] += f" Não observados: {', '.join(resultado['nao_observados'])}."
            print(f"    [+] ISOLAMENTO CONFIRMADO: {resultado['detalhes']}")
            print("        (Vale para a VPN ativa; não prevê vazamentos após queda do túnel.)")
        else:
            resultado["detalhes"] = "Nenhum pacote de teste foi observado em nenhuma interface."
            print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
        return resultado

    except Exception as e:  # noqa: BLE001
        resultado["status"] = "ERRO"
        resultado["detalhes"] = str(e)
        print(f"    [-] ERRO CRÍTICO: {resultado['detalhes']}")
        return resultado
