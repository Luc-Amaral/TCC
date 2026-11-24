import socket
import time

from scapy.all import Raw, UDP

from utils.captura import Captura, GrupoCapturas

ASSINATURA = b"VPN_TEST_PAYLOAD"
DESTINO_IP = "8.8.8.8"
DESTINO_PORTA = 9999


def executar(interface_fisica, interface_vpn):
    print("\n[*] 1. Testando Isolamento de Payload UDP (isolamento de rota; sem análise criptográfica)...")
    resultado = {
        "status": "INCONCLUSIVO", "detalhes": "",
        "pacote_fisica": None, "pacote_vpn": None,
        "pacotes_enviados": 0, "pacotes_fisica": 0, "pacotes_vpn": 0,
    }
    try:
        filtro = f"udp and dst host {DESTINO_IP} and dst port {DESTINO_PORTA}"
        cap_f = Captura(interface_fisica, filtro, "física")
        cap_v = Captura(interface_vpn, filtro, "VPN")
        portas_origem = set()

        print(f"    [*] Iniciando sensores na física ({interface_fisica}) e na VPN ({interface_vpn})...")
        with GrupoCapturas(cap_f, cap_v):
            print(f"        [>] Disparando payload '{ASSINATURA.decode()}' para {DESTINO_IP}:{DESTINO_PORTA}...")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.bind(("", 0))
                portas_origem.add(s.getsockname()[1])  # atribui os pacotes ao nosso teste
                for _ in range(3):
                    try:
                        s.sendto(ASSINATURA, (DESTINO_IP, DESTINO_PORTA))
                        resultado["pacotes_enviados"] += 1
                    except OSError:
                        pass
                    time.sleep(0.5)
            finally:
                s.close()

        if resultado["pacotes_enviados"] == 0:
            resultado["detalhes"] = "Falha de roteamento nativo: o socket não conseguiu enviar o datagrama."
            print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
            return resultado

        def nossos(pacotes):
            return [p for p in pacotes
                    if p.haslayer(UDP) and p[UDP].sport in portas_origem
                    and p.haslayer(Raw) and ASSINATURA in p[Raw].load]

        vazados = nossos(cap_f.pacotes)
        no_tunel = nossos(cap_v.pacotes)
        resultado["pacotes_fisica"], resultado["pacotes_vpn"] = len(vazados), len(no_tunel)

        if vazados:  # vazamento é conclusivo mesmo que o sensor da VPN tenha falhado
            resultado["status"] = "FALHA"
            resultado["pacote_fisica"] = vazados[0].summary()
            resultado["detalhes"] = "O payload vazou em texto claro na rede física."
            print("    [!] FALHA DE ISOLAMENTO: o pacote saiu pela interface física.")
            print(f"        -> {resultado['pacote_fisica']}")
        elif not cap_f.iniciou:
            resultado["detalhes"] = f"Sensor da física não iniciou: {cap_f.erro}"
            print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
        elif not cap_v.iniciou:
            resultado["detalhes"] = f"Sensor da VPN não iniciou: {cap_v.erro}"
            print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
        elif no_tunel:
            resultado["status"] = "ISOLADO"
            resultado["pacote_vpn"] = no_tunel[0].summary()
            resultado["detalhes"] = "Payload visto só no adaptador virtual; nenhuma cópia na física."
            print("    [+] ISOLAMENTO CONFIRMADO: o pacote transitou apenas pela interface da VPN.")
            print("        (Atesta isolamento de rota, não força criptográfica.)")
        else:
            resultado["detalhes"] = "Pacote injetado mas não observado em nenhuma interface (firewall/descartado)."
            print(f"    [-] INCONCLUSIVO: {resultado['detalhes']}")
        return resultado

    except Exception as e:  # noqa: BLE001
        resultado["status"] = "ERRO"
        resultado["detalhes"] = f"Erro no motor de captura: {e}"
        print(f"    [-] ERRO CRÍTICO: {resultado['detalhes']}")
        return resultado
