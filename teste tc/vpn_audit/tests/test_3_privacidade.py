import socket
import ssl
import time

import requests
from scapy.all import DNS, DNSQR, IP, IPv6, TCP

from utils.captura import Captura, GrupoCapturas
from utils.network import consultar_ipv4, consultar_ipv6, mesmo_prefixo64

SEM_PROXY = {"http": None, "https": None}
DOMINIO_BASE = "dnsleaktest.com"


def _consulta_dns_wire(nome="example.com"):
    return bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname=nome)))


def _tentar_doh():
    """Consulta DoH real (RFC 8484) ao 1.1.1.1. Retorna True se houve resposta válida."""
    try:
        r = requests.post(
            "https://1.1.1.1/dns-query",
            headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"},
            data=_consulta_dns_wire(), timeout=5, proxies=SEM_PROXY,
        )
        return r.status_code == 200 and len(r.content) > 12
    except Exception:  # noqa: BLE001
        return False


def _tentar_dot():
    """Consulta DoT real (RFC 7858) ao 1.1.1.1:853. Retorna True se houve resposta."""
    try:
        wire = _consulta_dns_wire()
        ctx = ssl.create_default_context()
        with socket.create_connection(("1.1.1.1", 853), timeout=5) as bruto:
            with ctx.wrap_socket(bruto, server_hostname="1.1.1.1") as tls:
                tls.sendall(len(wire).to_bytes(2, "big") + wire)
                return len(tls.recv(512)) > 2
    except Exception:  # noqa: BLE001
        return False


def _qname(pkt):
    q = pkt[DNSQR].qname
    return (q.decode("utf-8", "ignore") if isinstance(q, bytes) else str(q)).lower()


def _ip_destino(pkt):
    if pkt.haslayer(IP):
        return pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].dst
    return None


def executar(ips_reais, dns_real, interface_fisica, interface_vpn):
    print("\n[*] 3. Testando Privacidade (IPv4, IPv6, DNS e canais DoH/DoT)...")
    resultado = {
        "status": "INCONCLUSIVO", "detalhes": "",
        "ip_saida_v4": None, "ip_saida_v6": None,
        "ipv4_status": "INCONCLUSIVO", "ipv6_status": "INCONCLUSIVO",
        "dns_status": "INCONCLUSIVO", "doh_dot_status": "INCONCLUSIVO",
        "dominios_dns": [], "dns_consultas_fisica": 0, "dns_consultas_vpn": 0,
        "dns_destinos_vazados": [], "dns_amostra_vazamento": None, "dns_protocolos": [],
        "doh_funcional": None, "dot_funcional": None,
        "doh_dot_pacotes_fisica": 0, "doh_dot_pacotes_vpn": 0,
    }
    notas = []

    # --- 3.1 IPv4 -------------------------------------------------------- #
    print("        [>] Checando IPv4 de saída...")
    ip_v4, erro_v4 = consultar_ipv4()
    resultado["ip_saida_v4"] = ip_v4
    if ip_v4 is None:
        estado_v4 = "ERRO" if erro_v4 == "outro" else "INCONCLUSIVO"
        print("    [-] INCONCLUSIVO: não foi possível obter o IPv4 externo.")
    elif ip_v4 == ips_reais.get("v4"):
        estado_v4 = "VAZADO"
        print(f"    [!] FALHA NO IP: IPv4 real exposto ({ip_v4}).")
        notas.append("IPv4 original vazou.")
    else:
        estado_v4 = "MASCARADO"
        print(f"    [+] IPv4 mascarado (saída: {ip_v4}).")
        notas.append("IPv4 mascarado.")
    resultado["ipv4_status"] = estado_v4

    # --- 3.2 IPv6 -------------------------------------------------------- #
    base_v6 = ips_reais.get("v6")
    ip_v6, erro_v6 = consultar_ipv6()
    resultado["ip_saida_v6"] = ip_v6
    if ip_v6:
        if base_v6 and mesmo_prefixo64(ip_v6, base_v6):  # prefixo /64: endereços temporários mudam
            estado_v6 = "VAZADO"
            print(f"    [!] FALHA CRÍTICA IPv6: prefixo real exposto ({ip_v6}).")
            notas.append("IPv6 nativo vazou.")
        else:
            estado_v6 = "MASCARADO"
            print(f"    [+] IPv6 ativo e mascarado ({ip_v6}).")
            notas.append("IPv6 mascarado.")
    elif base_v6:
        if erro_v6 in ("timeout", "conexao"):
            estado_v6 = "BLOQUEADO"  # inferido: havia IPv6 no baseline e agora não há
            print("    [+] IPv6 indisponível com a VPN ativa (bloqueio inferido a partir do baseline).")
            notas.append("IPv6 bloqueado (inferido).")
        else:
            estado_v6 = "ERRO"
            print("    [-] IPv6: erro inesperado ao consultar.")
    else:
        estado_v6 = "NAO_APLICAVEL"
        print("    [-] IPv6: não aplicável (a máquina não tinha IPv6 nativo no baseline).")
        notas.append("IPv6 não aplicável (ambiente sem IPv6).")
    resultado["ipv6_status"] = estado_v6

    # --- 3.3 DNS --------------------------------------------------------- #
    status_dns = "INCONCLUSIVO"
    try:
        marca = f"vpnaudit-{int(time.time() * 1000)}"
        dominios = [f"{marca}-{i}.{DOMINIO_BASE}" for i in range(3)]
        resultado["dominios_dns"] = dominios
        print(f"    [*] Escutando DNS (porta 53, TCP/UDP) para {len(dominios)} domínios únicos '{marca}-N'...")

        cap_f = Captura(interface_fisica, "port 53", "física")
        cap_v = Captura(interface_vpn, "port 53", "VPN")
        with GrupoCapturas(cap_f, cap_v):
            for dominio in dominios:
                try:
                    socket.getaddrinfo(dominio, 80)
                except OSError:
                    pass
                time.sleep(0.3)
            time.sleep(1)

        def so_nossas(pacotes):  # apenas CONSULTAS (qr==0) dos nossos domínios
            return [p for p in pacotes if p.haslayer(DNS) and p.haslayer(DNSQR)
                    and p[DNS].qr == 0 and marca in _qname(p)]

        vazadas, na_vpn = so_nossas(cap_f.pacotes), so_nossas(cap_v.pacotes)
        resultado["dns_consultas_fisica"], resultado["dns_consultas_vpn"] = len(vazadas), len(na_vpn)
        resultado["dns_protocolos"] = sorted({"TCP" if p.haslayer(TCP) else "UDP" for p in vazadas + na_vpn})

        if vazadas:
            status_dns = "FALHA"
            resultado["dns_destinos_vazados"] = sorted({d for d in map(_ip_destino, vazadas) if d})
            resultado["dns_amostra_vazamento"] = vazadas[0].summary()
            notas.append(f"DNS vazou: {len(vazadas)} consulta(s) para {resultado['dns_destinos_vazados']}.")
            print(f"    [!] FALHA NO DNS: {len(vazadas)} consulta(s) dos domínios de teste saíram pela física "
                  f"-> {resultado['dns_destinos_vazados']}")
        elif not cap_f.iniciou:
            notas.append(f"DNS inconclusivo: sensor da física não iniciou ({cap_f.erro}).")
            print("    [-] INCONCLUSIVO: sensor da física não iniciou.")
        elif not cap_v.iniciou:
            notas.append(f"DNS inconclusivo: sensor da VPN não iniciou ({cap_v.erro}).")
            print("    [-] INCONCLUSIVO: sensor da VPN não iniciou.")
        elif na_vpn:
            status_dns = "ISOLADO"
            notas.append(f"DNS isolado: {len(na_vpn)} consulta(s) apenas no túnel.")
            print("    [+] ISOLAMENTO CONFIRMADO: consultas DNS de teste retidas no túnel.")
        else:
            notas.append("Nenhuma consulta DNS de teste foi capturada (cache/resolvedor alternativo).")
            print("    [-] INCONCLUSIVO: nenhuma consulta de teste capturável.")
    except Exception as exc:  # noqa: BLE001
        status_dns = "ERRO"
        notas.append(f"Erro no DNS: {exc}")
        print(f"    [-] ERRO CRÍTICO DNS: {exc}")
    resultado["dns_status"] = status_dns

    # --- 3.4 Canais DoH/DoT (consulta real, mede ROTEAMENTO do canal cifrado) ----- #
    try:
        filtro = "(tcp port 443 or tcp port 853) and host 1.1.1.1"
        cap_f2 = Captura(interface_fisica, filtro, "física")
        cap_v2 = Captura(interface_vpn, filtro, "VPN")
        with GrupoCapturas(cap_f2, cap_v2):
            resultado["doh_funcional"] = _tentar_doh()
            resultado["dot_funcional"] = _tentar_dot()
        p_f = [p for p in cap_f2.pacotes if p.haslayer(TCP)]
        p_v = [p for p in cap_v2.pacotes if p.haslayer(TCP)]
        resultado["doh_dot_pacotes_fisica"], resultado["doh_dot_pacotes_vpn"] = len(p_f), len(p_v)
        if p_f:
            resultado["doh_dot_status"] = "FALHA"
            notas.append("Canais DoH/DoT saíram pela física.")
        elif not (cap_f2.iniciou and cap_v2.iniciou):
            notas.append("DoH/DoT inconclusivo: sensor não iniciou.")
        elif p_v:
            resultado["doh_dot_status"] = "ISOLADO"
            notas.append("Canais DoH/DoT roteados pelo túnel (mede roteamento, não o uso de DoH pelo sistema).")
        else:
            notas.append("DoH/DoT: nenhum pacote observado.")
    except Exception as exc:  # noqa: BLE001
        resultado["doh_dot_status"] = "ERRO"
        notas.append(f"Erro no DoH/DoT: {exc}")

    # --- Consolidação: o pior estado prevalece; IPv6 'não aplicável' não penaliza ---- #
    subs = [estado_v4, estado_v6, status_dns, resultado["doh_dot_status"]]
    if any(s in ("FALHA", "VAZADO") for s in subs):
        resultado["status"] = "FALHA"
    elif "ERRO" in subs:
        resultado["status"] = "ERRO"
    elif any(s == "INCONCLUSIVO" for s in subs):
        resultado["status"] = "INCONCLUSIVO"
    else:
        resultado["status"] = "ISOLADO"
    resultado["detalhes"] = " ".join(notas)
    return resultado
