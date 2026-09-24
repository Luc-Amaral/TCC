import time
import socket
import threading
from scapy.all import sniff, Raw

def executar(interface_fisica):
    print("\n[*] 1. Testando Criptografia (Payload via Socket do SO)...")
    assinatura = b"TCC_LUCAS_VPN_TEST_PAYLOAD"
    
    # Dicionário para permitir que a thread compartilhe os resultados com a função principal
    resultado = {"vazou": False, "erro_socket": None, "pacote_vazado": None}

    def disparar_socket():
        time.sleep(1)
        try:
            print(f"        [>] Injetando pacote UDP com a string: '{assinatura.decode()}'...")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            for _ in range(3):
                s.sendto(assinatura, ("8.8.8.8", 9999))
                time.sleep(0.5)
            s.close()
        except Exception as e:
            # Se a VPN quebrar a rota, o Python vai capturar o erro aqui
            resultado["erro_socket"] = str(e)

    threading.Thread(target=disparar_socket).start()
    print(f"    [*] Monitorando interface física ({interface_fisica}) por 5 segundos...")

    try:
        pacotes = sniff(iface=interface_fisica, timeout=5)
        
        for pacote in pacotes:
            if pacote.haslayer(Raw) and assinatura in pacote[Raw].load:
                resultado["vazou"] = True
                resultado["pacote_vazado"] = pacote
                break

        # 1. Verifica se a VPN causou um buraco negro no roteamento
        if resultado["erro_socket"]:
            print(f"    [!] FALHA NA CRIPTOGRAFIA / ROTEAMENTO: O Windows não conseguiu enviar o pacote!")
            print(f"        -> A VPN quebrou a conectividade da máquina (Erro: {resultado['erro_socket']}).")
            return False

        # 2. Verifica se o pacote foi ejetado sem criptografia
        if resultado["vazou"]:
            print("    [!] FALHA NA CRIPTOGRAFIA: Assinatura vazou em texto claro na rede física!")
            print(f"        -> Pacote interceptado: {resultado['pacote_vazado'].summary()}")
            return False

        # 3. Se enviou sem erros e não vazou no Wi-Fi, foi devidamente encapsulado
        print("    [+] SUCESSO: Tráfego devidamente encapsulado/criptografado pela VPN.")
        return True
        
    except Exception as e:
        print(f"    [-] Erro no Scapy: {e}")
        return False