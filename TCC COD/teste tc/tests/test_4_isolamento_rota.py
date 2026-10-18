import time
import urllib3
import socket
from scapy.all import AsyncSniffer, TCP, UDP

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def executar(interface_fisica, interface_vpn):
    print(f"\n[*] 4. Testando Isolamento de Rotas Nativa (Multi-Protocolo)...")
    
    alvos_v4_tcp = [("1.1.1.1", 80), ("1.1.1.1", 443), ("8.8.8.8", 443)]
    alvo_v6_tcp = ("2606:4700:4700::1111", 443)
    alvos_udp = [("8.8.8.8", 53), ("1.1.1.1", 443)]
    
    resultado = {"status": "INCONCLUSIVO", "detalhes": "", "pacote_vazado": None}

    try:
        alvos_ips = "host 1.1.1.1 or host 8.8.8.8 or host 2606:4700:4700::1111"
        filtro_bpf = f"({alvos_ips}) and ((tcp port 80 or tcp port 443) or (udp dst port 53 or udp dst port 443))"
        print(f"    [*] Monitorando TCP/80, TCP/443, UDP/53 e UDP/443 na física e na VPN...")
        
        sniffer_fisica = AsyncSniffer(iface=interface_fisica, filter=filtro_bpf)
        sniffer_vpn = AsyncSniffer(iface=interface_vpn, filter=filtro_bpf)
        
        try:
            sniffer_fisica.start()
            sniffer_vpn.start()
            time.sleep(1)

            trafego_real = 0
            
            # Disparos IPv4 TCP
            for ip, porta in alvos_v4_tcp:
                print(f"        [>] Disparando TCP IPv4 para {ip}:{porta}...")
                trafego_real += 1
                try:
                    conexao = socket.create_connection((ip, porta), timeout=1)
                    conexao.close()
                except Exception:
                    pass
                
            # Disparo IPv6 TCP
            print(f"        [>] Disparando TCP IPv6 para {alvo_v6_tcp[0]}:{alvo_v6_tcp[1]}...")
            trafego_real += 1
            try:
                conexao = socket.create_connection(alvo_v6_tcp, timeout=1)
                conexao.close()
            except Exception:
                pass
            
            # Disparo UDP
            for alvo_udp in alvos_udp:
                print(f"        [>] Disparando tráfego Raw UDP para {alvo_udp[0]}:{alvo_udp[1]}...")
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.sendto(b"TEST_UDP_ROUTE", alvo_udp)
                    s.close()
                    trafego_real += 1
                except Exception:
                    pass

            time.sleep(1)
        finally:
            sniffer_fisica.stop()
            sniffer_vpn.stop()

        # Isola TCP SYN ou tráfego UDP
        pkts_fisica = [p for p in sniffer_fisica.results if (p.haslayer(TCP) and p[TCP].flags == 'S') or p.haslayer(UDP)]
        pkts_vpn = [p for p in sniffer_vpn.results if (p.haslayer(TCP) and p[TCP].flags == 'S') or p.haslayer(UDP)]

        if trafego_real == 0 and not pkts_fisica and not pkts_vpn:
            resultado["detalhes"] = "Nenhuma tentativa real de tráfego foi registada pelos geradores."
            print("    [-] RESULTADO INCONCLUSIVO: O tráfego de inicialização não ocorreu com sucesso.")
            return resultado

        if pkts_fisica:
            resultado["status"] = "FALHA"
            resultado["pacote_vazado"] = pkts_fisica[0].summary()
            resultado["detalhes"] = f"{len(pkts_fisica)} pacotes de rota nativa expostos na placa física."
            print("    [!] FALHA DE ISOLAMENTO: Tráfego de inicialização ignorou a VPN e vazou!")
            print(f"        -> Vazamento capturado: {resultado['pacote_vazado']}")
            
        elif pkts_vpn and not pkts_fisica:
            resultado["status"] = "ISOLADO"
            resultado["detalhes"] = "Rota blindada para TCP/80, TCP/443, IPv6 TCP/443, UDP/53 e UDP/443."
            print("    [+] ISOLAMENTO CONFIRMADO: Pacotes interceptados exclusivamente dentro da VPN.")
            print("        (Nota: Este teste apenas comprova a rota com a VPN ativa, não prevê vazamentos pós-queda).")
            
        else:
            resultado["status"] = "INCONCLUSIVO"
            resultado["detalhes"] = "Tráfego disperso. Comportamento L4 não identificado."
            print("    [-] RESULTADO INCONCLUSIVO: Falha ao rastrear os pacotes gerados.")

        return resultado
        
    except Exception as e:
        resultado["status"] = "ERRO"
        resultado["detalhes"] = str(e)
        print(f"    [-] ERRO CRÍTICO: {resultado['detalhes']}")
        return resultado