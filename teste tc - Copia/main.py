import sys
from utils.network import obter_ip_real, obter_dns_real, detectar_ambiente_vpn
from core.nucleo_exec import VPNSecurityTester

if __name__ == "__main__":
    print("=== Preparação para os Testes ===")
    
    MEU_IP_REAL = obter_ip_real()
    MEUS_DNS_REAIS = obter_dns_real()
    
    if not MEU_IP_REAL or not MEUS_DNS_REAIS:
        sys.exit(1)
        
    print("\n" + "=" * 50)
    print(">>> LIGUE O CLIENTE VPN <<<")
    input("Pressione [ENTER] APENAS QUANDO A VPN ESTIVER CONECTADA...")
    
    INTERFACE_VPN, NOME_PROCESSO_VPN, TIPO_VPN = detectar_ambiente_vpn()
    
    if not INTERFACE_VPN: INTERFACE_VPN = input("Digite a interface da VPN (ex: tun0): ").strip()
    if not NOME_PROCESSO_VPN: NOME_PROCESSO_VPN = input("Digite o processo (ex: openvpn): ").strip()

    INTERFACE_FISICA = "Wi-Fi" # Cabo ou wlp3s0 para Wi-Fi

    tester = VPNSecurityTester(MEU_IP_REAL, MEUS_DNS_REAIS, NOME_PROCESSO_VPN, INTERFACE_VPN, INTERFACE_FISICA)
    tester.run_all_tests()