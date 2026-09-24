import socket
import threading
import time

import requests
from scapy.all import sniff, TCP
import urllib3

# Desativa alertas de certificado ao acessar IP direto
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def executar(interface_fisica):
    print(f"\n[*] 4. Testando Robustez (Vazamento de Rota / Fallback)...")
    vazamento_local = False
    alvos = ["1.1.1.1", "8.8.8.8"]

    def forcar_trafego():
        time.sleep(1)
        for ip in alvos:
            try:
                print(f"        [>] Disparando TCP SYN (HTTPS) direto para {ip}...")
                requests.get(f'https://{ip}', timeout=3, verify=False)
            except Exception:
                pass

    threading.Thread(target=forcar_trafego).start()
    print(f"    [*] Monitorando a interface física ({interface_fisica}) por TCP SYN vazados...")

    try:
        # Filtro BPF restrito: apenas tráfego HTTPS direcionado aos nossos alvos
        filtro_bpf = "tcp port 443 and (host 1.1.1.1 or host 8.8.8.8)"
        pacotes = sniff(iface=interface_fisica, filter=filtro_bpf, timeout=8)
        
        for p in pacotes:
            # Confirma cirurgicamente se é o pacote de inicialização da nossa requisição (Flag 'S' = SYN)
            if p.haslayer(TCP) and p[TCP].flags == 'S':
                print(f"    [!] FALHA NA ROBUSTEZ: Conexão exposta fora do túnel!")
                print(f"        -> Vazamento capturado: {p.summary()}")
                vazamento_local = True
                break

        if not vazamento_local:
            print("    [+] SUCESSO: Rota blindada. Nenhum pacote de inicialização vazou para a rede física.")
            
    except Exception as e:
        print(f"    [-] Erro ao monitorar fallback de roteamento: {e}")
        return False

    return not vazamento_local