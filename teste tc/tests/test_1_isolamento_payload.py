import socket
import time
from scapy.all import AsyncSniffer, Raw

def executar(interface_fisica, interface_vpn):
    print("\n[*] 1. Testando Isolamento de Payload UDP (Sem aferição criptográfica)...")
    assinatura = b"VPN_TEST_PAYLOAD"
    destino_ip = "8.8.8.8"
    destino_porta = 9999
    
    resultado = {"status": "INCONCLUSIVO", "detalhes": "", "pacote_fisica": None, "pacote_vpn": None}

    try:
        filtro = f"udp and dst port {destino_porta}"
        print(f"    [*] Iniciando sniffer na física ({interface_fisica}) e na VPN ({interface_vpn})...")
        
        sniffer_fisica = AsyncSniffer(iface=interface_fisica, filter=filtro)
        sniffer_vpn = AsyncSniffer(iface=interface_vpn, filter=filtro)
        
        try:
            sniffer_fisica.start()
            sniffer_vpn.start()
            time.sleep(1)

            print(f"        [>] Injetando payload '{assinatura.decode()}' para {destino_ip}:{destino_porta}...")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            pacotes_enviados = 0
            for _ in range(3):
                try:
                    s.sendto(assinatura, (destino_ip, destino_porta))
                    pacotes_enviados += 1
                    time.sleep(0.5)
                except Exception:
                    pass
            s.close()
            time.sleep(1)
        finally:
            sniffer_fisica.stop()
            sniffer_vpn.stop()

        if pacotes_enviados == 0:
            resultado["detalhes"] = "Falha de roteamento nativo: socket falhou na injeção."
            print(f"    [-] AVISO: {resultado['detalhes']}")
            return resultado

        pacotes_vazados = [p for p in sniffer_fisica.results if p.haslayer(Raw) and assinatura in p[Raw].load]
        pacotes_encapsulados = [p for p in sniffer_vpn.results if p.haslayer(Raw) and assinatura in p[Raw].load]

        if pacotes_vazados:
            resultado["status"] = "FALHA"
            resultado["pacote_fisica"] = pacotes_vazados[0].summary()
            resultado["detalhes"] = "O payload não foi isolado e vazou em texto claro na rede física."
            print("    [!] FALHA DE ISOLAMENTO: O roteamento falhou em reter o pacote no túnel.")
            print(f"        -> Vazamento capturado: {resultado['pacote_fisica']}")
            
        elif pacotes_encapsulados and not pacotes_vazados:
            resultado["status"] = "SUCESSO"
            resultado["pacote_vpn"] = pacotes_encapsulados[0].summary()
            resultado["detalhes"] = "Isolamento de payload L4 confirmado no adaptador virtual."
            print("    [+] ISOLAMENTO CONFIRMADO: O pacote transitou exclusivamente pela interface da VPN.")
            
        else:
            resultado["status"] = "INCONCLUSIVO"
            resultado["detalhes"] = "Pacote destruído pelo firewall local ou dropado pelo SO."
            print("    [-] RESULTADO INCONCLUSIVO: O pacote foi injetado, mas sumiu da rede (Dropado/Firewall).")

        return resultado

    except Exception as e:
        resultado["status"] = "ERRO"
        resultado["detalhes"] = f"Erro no motor Scapy: {str(e)}"
        print(f"    [-] ERRO CRÍTICO: {resultado['detalhes']}")
        return resultado