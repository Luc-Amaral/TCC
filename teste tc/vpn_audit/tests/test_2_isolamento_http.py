import socket

import requests
from scapy.all import IP, TCP

from utils.captura import Captura, GrupoCapturas

SEM_PROXY = {"http": None, "https": None}
HOST_ALVO = "neverssl.com"


def executar(interface_fisica, interface_vpn):
    print("\n[*] 2. Testando Isolamento HTTP (TCP/80, alvo restrito)...")
    resultado = {
        "status": "INCONCLUSIVO", "detalhes": "", "amostra_vazamento": None,
        "alvo_ip": None, "requisicao_ok": False, "http_status": None,
        "pacotes_fisica": 0, "pacotes_vpn": 0,
    }
    try:
        print("    [*] Resolvendo alvo HTTP para restringir a captura...")
        try:
            alvo_ip = socket.gethostbyname(HOST_ALVO)
        except OSError as exc:
            resultado["detalhes"] = f"Não foi possível resolver {HOST_ALVO}: {exc}"
            print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
            return resultado
        resultado["alvo_ip"] = alvo_ip

        filtro = f"tcp port 80 and host {alvo_ip}"
        cap_f = Captura(interface_fisica, filtro, "física")
        cap_v = Captura(interface_vpn, filtro, "VPN")

        print(f"    [*] Iniciando sniffers na física ({interface_fisica}) e na VPN ({interface_vpn})...")
        with GrupoCapturas(cap_f, cap_v):
            print(f"        [>] Requisição HTTP para {alvo_ip} (bypass de proxy)...")
            for tentativa in (1, 2):
                try:
                    resp = requests.get(f"http://{alvo_ip}", timeout=(4, 6), proxies=SEM_PROXY,
                                        headers={"Host": HOST_ALVO})
                    resultado["requisicao_ok"] = True
                    resultado["http_status"] = resp.status_code
                    break
                except Exception as exc:  # noqa: BLE001
                    resultado["detalhes"] += f"Tentativa {tentativa} falhou: {type(exc).__name__}. "

        def do_alvo(pacotes):
            return [p for p in pacotes if p.haslayer(TCP) and p.haslayer(IP)
                    and alvo_ip in (p[IP].dst, p[IP].src)]

        vazados, no_tunel = do_alvo(cap_f.pacotes), do_alvo(cap_v.pacotes)
        resultado["pacotes_fisica"], resultado["pacotes_vpn"] = len(vazados), len(no_tunel)

        if vazados:
            resultado["status"] = "FALHA"
            resultado["amostra_vazamento"] = vazados[0].summary()
            resultado["detalhes"] += "Pacote TCP/80 do alvo vazou na física."
            print("    [!] FALHA DE ISOLAMENTO: tráfego HTTP exposto na rede física.")
            print(f"        -> {resultado['amostra_vazamento']}")
        elif not cap_f.iniciou:
            resultado["detalhes"] += f"Sensor da física não iniciou: {cap_f.erro}"
            print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
        elif not cap_v.iniciou:
            resultado["detalhes"] += f"Sensor da VPN não iniciou: {cap_v.erro}"
            print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
        elif no_tunel:
            resultado["status"] = "ISOLADO"
            if resultado["requisicao_ok"]:
                resultado["detalhes"] += f"HTTP {resultado['http_status']} recebido; tráfego só no túnel."
            else:
                resultado["detalhes"] += ("Pacotes só no túnel, porém a requisição não completou "
                                          "(verifique se a VPN permite porta 80).")
            print("    [+] ISOLAMENTO CONFIRMADO: HTTP encapsulado no túnel."
                  + ("" if resultado["requisicao_ok"] else " (requisição não completou)"))
        else:
            resultado["detalhes"] += "Nenhum pacote TCP/80 do alvo visto em nenhuma interface."
            print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
        return resultado

    except Exception as e:  # noqa: BLE001
        resultado["status"] = "ERRO"
        resultado["detalhes"] = str(e)
        print(f"    [-] ERRO CRÍTICO: {resultado['detalhes']}")
        return resultado
