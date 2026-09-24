import socket
import threading
import time

from scapy.all import Raw, sniff


def executar(interface_fisica):
    print("\n[*] 1. Testando Criptografia (Payload via Socket do SO)...")
    assinatura = b"VPN_TEST_PAYLOAD"

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

        if resultado["erro_socket"]:
            print(f"    [-] AVISO: houve erro de roteamento/envio do pacote")
            print(f"        -> Detalhe: {resultado['erro_socket']}")
            print("    [!] RESULTADO: INCONCLUSIVO para criptografia. A verificação não confirmou vazamento, mas também não provou encapsulamento completo.")
            return None

        if resultado["vazou"]:
            print("    [!] FALHA NA CRIPTOGRAFIA: Assinatura vazou em texto claro na rede física!")
            print(f"        -> Pacote interceptado: {resultado['pacote_vazado'].summary()}")
            return False

        print("    [+] SUCESSO: Tráfego devidamente encapsulado/criptografado pela VPN.")
        return True

    except Exception as e:
        print(f"    [-] Erro no Scapy: {e}")
        print("    [!] RESULTADO: INCONCLUSIVO para criptografia. O ambiente não permitiu confirmar a checagem.")
        return None