import time
import requests
import threading
from scapy.all import sniff

def executar(interface_fisica):
    print("\n[*] 2. Testando Integridade (Porta 80 HTTP)...")
    
    def gerar_trafego_http():
        time.sleep(1)
        print("        [>] Acessando http://neverssl.com para forçar tráfego sem criptografia...")
        try: requests.get('http://neverssl.com', timeout=4)
        except: pass

    threading.Thread(target=gerar_trafego_http).start()
    print(f"    [*] Escutando pacotes TCP/80 na interface física ({interface_fisica})...")
    
    try:
        pacotes = sniff(iface=interface_fisica, filter="tcp port 80", timeout=5)
        if len(pacotes) > 0:
            print(f"    [!] FALHA NA INTEGRIDADE: {len(pacotes)} pacote(s) HTTP vazando na rede local!")
            print(f"        -> Amostra 1: {pacotes[0].summary()}")
            if len(pacotes) > 1:
                print(f"        -> Amostra 2: {pacotes[1].summary()}")
            return False
        
        print("    [+] SUCESSO: Nenhum tráfego porta 80 detectado fora do túnel.")
        return True
    except Exception as e:
        print(f"    [-] Erro no Scapy: {e}")
        return False