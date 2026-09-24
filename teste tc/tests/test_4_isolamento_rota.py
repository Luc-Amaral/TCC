import time
import requests
import urllib3
from scapy.all import AsyncSniffer, TCP

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def executar(interface_fisica, interface_vpn):
    print(f"\n[*] 4. Testando Isolamento de Rota Nativa (Filtro TCP SYN Strict)...")
    alvos = ["1.1.1.1", "8.8.8.8"]
    resultado = {"status": "INCONCLUSIVO", "detalhes": "", "pacote_vazado": None}

    try:
        filtro_bpf = "tcp port 443 and (host 1.1.1.1 or host 8.8.8.8)"
        print(f"    [*] Monitorando TCP SYN HTTPS na física ({interface_fisica}) e na VPN ({interface_vpn})...")
        
        sniffer_fisica = AsyncSniffer(iface=interface_fisica, filter=filtro_bpf)
        sniffer_vpn = AsyncSniffer(iface=interface_vpn, filter=filtro_bpf)
        
        try:
            sniffer_fisica.start()
            sniffer_vpn.start()
            time.sleep(1)

            for ip in alvos:
                print(f"        [>] Disparando pacote de inicialização direta (SYN) para https://{ip}...")
                try: 
                    requests.get(f'https://{ip}', timeout=2, verify=False, proxies={"http": None, "https": None})
                except requests.RequestException: 
                    pass
            time.sleep(1)
        finally:
            sniffer_fisica.stop()
            sniffer_vpn.stop()

        syn_fisica = [p for p in sniffer_fisica.results if p.haslayer(TCP) and p[TCP].flags == 'S']
        syn_vpn = [p for p in sniffer_vpn.results if p.haslayer(TCP) and p[TCP].flags == 'S']

        if syn_fisica:
            resultado["status"] = "FALHA"
            resultado["pacote_vazado"] = syn_fisica[0].summary()
            resultado["detalhes"] = "Pacote SYN exposto na placa física."
            print("    [!] FALHA DE ROTA: Conexão direta de roteamento exposta fora do túnel.")
            print(f"        -> Vazamento capturado: {resultado['pacote_vazado']}")
            
        elif syn_vpn and not syn_fisica:
            resultado["status"] = "SUCESSO"
            resultado["detalhes"] = "Rota blindada (Sistema Operativo respeitou a tabela virtual)."
            print("    [+] ISOLAMENTO DE ROTA CONFIRMADO: Pacotes SYN capturados exclusivamente dentro da VPN.")
            
        else:
            resultado["status"] = "INCONCLUSIVO"
            resultado["detalhes"] = "Tráfego de inicialização TCP SYN não registado nos sensores."
            print("    [-] RESULTADO INCONCLUSIVO: O tráfego de inicialização (SYN) não foi registado.")

        return resultado
        
    except Exception as e:
        resultado["status"] = "ERRO"
        resultado["detalhes"] = str(e)
        print(f"    [-] ERRO CRÍTICO: {resultado['detalhes']}")
        return resultado