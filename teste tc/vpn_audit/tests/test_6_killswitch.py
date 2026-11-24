import socket
import time

import psutil
import urllib3
from scapy.all import TCP, UDP

from utils.captura import Captura, GrupoCapturas, pacote_ts
from utils.network import (
    consultar_ipv4, interface_esta_ativa, ips_da_interface, melhor_rota_padrao,
    obter_rotas_ipv4, obter_tabela_rotas,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IP_ALVO = "8.8.4.4"
MARCADORES_AUXILIAR = ("dnsblock", "dns-block", "helper")


def _localizar(nome):
    achados = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            n = (proc.info["name"] or "").lower()
            if nome.lower() in (n, n[:-4] if n.endswith(".exe") else n):
                achados.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return achados


def _encerrar(procs):
    """Mata os processos e seus filhos. Retorna (info, sobreviventes)."""
    alvos = []
    for p in procs:
        try:
            alvos.extend(p.children(recursive=True))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        alvos.append(p)
    info = []
    for p in alvos:
        try:
            info.append({"pid": p.pid, "nome": p.name(), "exe": p.exe()})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            info.append({"pid": p.pid})
    for p in alvos:
        try:
            p.kill()
        except psutil.NoSuchProcess:
            pass
    _, vivos = psutil.wait_procs(alvos, timeout=5)
    return info, vivos


def _syn(porta_set):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.bind(("", 0))
        porta_set.add(s.getsockname()[1])
        try:
            s.connect((IP_ALVO, 443))
        except OSError:
            pass
    finally:
        s.close()


def _udp(destino, porta_set, carga):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("", 0))
        porta_set.add(s.getsockname()[1])
        s.sendto(carga, destino)
    except OSError:
        pass
    finally:
        s.close()


def _syns(pacotes, portas, t0):
    return [p for p in pacotes if p.haslayer(TCP) and p[TCP].sport in portas
            and (int(p[TCP].flags) & 0x12) == 0x02 and pacote_ts(p) > t0]


def _udps(pacotes, portas, t0):
    return [p for p in pacotes if p.haslayer(UDP) and p[UDP].sport in portas and pacote_ts(p) > t0]


def _mecanismo(rotas_depois, ips_vpn):
    rp = melhor_rota_padrao(rotas_depois)
    if rp is None:
        return "sem rota padrão após a queda (rede indisponível ou rotas removidas)"
    if rp["interface_ip"] in ips_vpn:
        return ("a rota padrão ainda aponta para o adaptador do túnel: bloqueio por rota órfã "
                "(não prova que exista kill-switch)")
    return "a rota padrão voltou à interface física e nada saiu: indício de firewall/kill-switch ativo"


def executar(nome_processo_vpn, interface_fisica, interface_vpn, gateway_fisico=None,
             ip_baseline_v4=None, tentativas=8, intervalo=1.0):
    print("\n[*] 6. Testando Kill-Switch (encerramento abrupto do cliente + tráfego pós-queda)...")
    resultado = {
        "status": "INCONCLUSIVO", "detalhes": "", "pacote_vazado": None,
        "tentativas_pos_queda": 0, "syns_pos_queda": 0, "udp_pos_queda": 0,
        "pacotes_tunel_pos_queda": 0, "ip_pos_queda": None,
        "captura_confirmada": False, "controle_captura_ok": None, "processo_terminou": False,
        "processos_encerrados": [], "mecanismo": None, "tempo_ate_primeiro_vazamento_s": None,
        "rotas_antes": None, "rotas_depois": None,
        "interface_vpn_antes": None, "interface_vpn_depois": None,
    }

    if not nome_processo_vpn or nome_processo_vpn == "nao-detectado":
        resultado["detalhes"] = "Processo da VPN não informado/detectado; kill-switch não executado."
        print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
        return resultado
    if any(m in nome_processo_vpn.lower() for m in MARCADORES_AUXILIAR):
        resultado["detalhes"] = (f"'{nome_processo_vpn}' parece ser um processo auxiliar; "
                                 "informe o processo principal da VPN (--nome-vpn).")
        print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
        return resultado
    procs = _localizar(nome_processo_vpn)
    if not procs:
        resultado["detalhes"] = f"Processo '{nome_processo_vpn}' não encontrado em execução."
        print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
        return resultado

    resultado["rotas_antes"] = obter_tabela_rotas()
    ips_vpn = ips_da_interface(interface_vpn) if interface_vpn else []
    resultado["interface_vpn_antes"] = interface_esta_ativa(interface_vpn)

    cap_fis = Captura(interface_fisica, None, "física")  # sem filtro: serve também de controle
    cap_vpn = Captura(interface_vpn, f"host {IP_ALVO}", "VPN")
    portas_tcp, portas_udp, portas_ctrl = set(), set(), set()
    hora_da_morte, erro, feitas = None, None, 0

    with GrupoCapturas(cap_fis, cap_vpn):
        print(f"    [!] Encerrando '{nome_processo_vpn}' ({len(procs)} processo(s)) à força...")
        try:
            info, vivos = _encerrar(procs)
            resultado["processos_encerrados"] = info
            if vivos:
                erro = ("INCONCLUSIVO", "O processo não morreu em 5 s; teste abortado.")
            else:
                resultado["processo_terminou"] = True
                hora_da_morte = time.time()
        except psutil.AccessDenied:
            erro = ("ERRO", "Permissão negada ao encerrar o processo: execute o terminal como Administrador.")
        except Exception as exc:  # noqa: BLE001
            erro = ("ERRO", f"Falha ao encerrar o processo: {exc}")

        if erro is None:
            time.sleep(0.5)
            resultado["rotas_depois"] = obter_tabela_rotas()
            rotas_depois = obter_rotas_ipv4()
            resultado["interface_vpn_depois"] = interface_esta_ativa(interface_vpn)
            print("    [>] Processo encerrado. Injetando tráfego pós-queda (TCP/443 e UDP/53)...")
            for _ in range(tentativas):
                _syn(portas_tcp)
                _udp((IP_ALVO, 53), portas_udp, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01")
                feitas += 1
                time.sleep(intervalo)
            if gateway_fisico:  # controle: um pacote que SEMPRE deve aparecer na física (LAN)
                for _ in range(3):
                    _udp((gateway_fisico, 9), portas_ctrl, b"CONTROLE_CAPTURA")
                    time.sleep(0.2)
            ip_pos, _ = consultar_ipv4(timeout=4)
            resultado["ip_pos_queda"] = ip_pos

    # ------------------------- avaliação ------------------------------------ #
    if erro:
        resultado["status"], resultado["detalhes"] = erro
        print(f"    [-] {resultado['status']}: {resultado['detalhes']}")
        return resultado

    resultado["tentativas_pos_queda"] = feitas
    resultado["captura_confirmada"] = cap_fis.iniciou
    if not cap_fis.iniciou:
        resultado["detalhes"] = f"Sensor da física não iniciou: {cap_fis.erro}"
        print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
        return resultado

    syns = _syns(cap_fis.pacotes, portas_tcp, hora_da_morte)
    udps = _udps(cap_fis.pacotes, portas_udp, hora_da_morte)
    no_tunel = _syns(cap_vpn.pacotes, portas_tcp, hora_da_morte) + _udps(cap_vpn.pacotes, portas_udp, hora_da_morte)
    resultado["syns_pos_queda"], resultado["udp_pos_queda"] = len(syns), len(udps)
    resultado["pacotes_tunel_pos_queda"] = len(no_tunel)
    ip_pos = resultado["ip_pos_queda"]
    controle_visto = bool(portas_ctrl) and any(
        p.haslayer(UDP) and p[UDP].sport in portas_ctrl for p in cap_fis.pacotes)
    trafego_geral = [p for p in cap_fis.pacotes if pacote_ts(p) > hora_da_morte]
    sniffer_vivo = controle_visto or len(trafego_geral) > 0
    resultado["controle_captura_ok"] = sniffer_vivo
    resultado["mecanismo"] = _mecanismo(rotas_depois, ips_vpn)

    vazados = sorted(syns + udps, key=pacote_ts)
    if vazados:
        resultado["status"] = "FALHA"
        resultado["pacote_vazado"] = vazados[0].summary()
        resultado["tempo_ate_primeiro_vazamento_s"] = round(pacote_ts(vazados[0]) - hora_da_morte, 2)
        resultado["detalhes"] = (f"Fail-Open: {len(syns)} SYN(s) TCP e {len(udps)} datagrama(s) UDP escaparam para a "
                                 f"rede física após a queda (primeiro após {resultado['tempo_ate_primeiro_vazamento_s']} s).")
        print(f"    [!] FALHA CRÍTICA NO KILL-SWITCH: {resultado['detalhes']}")
        print(f"        -> {resultado['pacote_vazado']}")
    elif ip_pos and ip_baseline_v4 and ip_pos == ip_baseline_v4:
        resultado["status"] = "FALHA"
        resultado["detalhes"] = f"Fail-Open: após a queda o IP real ({ip_pos}) voltou a ser a saída."
        print(f"    [!] FALHA CRÍTICA NO KILL-SWITCH: {resultado['detalhes']}")
    elif no_tunel or (ip_pos and ip_baseline_v4 and ip_pos != ip_baseline_v4):
        resultado["status"] = "NAO_APLICAVEL"
        resultado["detalhes"] = ("O encerramento do processo NÃO derrubou o túnel (o tráfego pós-queda ainda "
                                 "passou pela VPN). O processo alvo provavelmente é a interface; "
                                 "informe o processo/serviço que mantém o túnel (--nome-vpn).")
        print(f"    [-] NÃO APLICÁVEL: {resultado['detalhes']}")
    elif not sniffer_vivo:
        resultado["status"] = "INCONCLUSIVO"
        resultado["detalhes"] = ("Nada saiu, mas não há prova de que a captura física estava ativa "
                                 "(nenhum controle/tráfego visto); pode ser captura cega ou LAN bloqueada.")
        print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
    else:
        resultado["status"] = "BLOQUEADO"
        resultado["detalhes"] = (f"Fail-Closed: {feitas} tentativas pós-queda não chegaram à rede física; "
                                 f"mecanismo provável: {resultado['mecanismo']}.")
        print(f"    [+] BLOQUEIO CONFIRMADO: {resultado['detalhes']}")

    print("    [!] A VPN foi encerrada à força: reconecte-a antes de novas medições.")
    return resultado
