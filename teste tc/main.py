import argparse
import sys

from core.nucleo_exec import VPNSecurityTester
from utils.network import detectar_ambiente_vpn, listar_interfaces_ativas, obter_detalhes_interface, obter_dns_real, obter_ips_reais


def _parse_args():
    parser = argparse.ArgumentParser(description='Auditoria Estrita de Isolamento de Roteamento L3/L4.')
    parser.add_argument('--interface-vpn', help='Interface da VPN, se a detecção automática falhar.')
    parser.add_argument('--interface-fisica', help='Interface física da máquina, se a detecção automática falhar.')
    parser.add_argument('--nome-vpn', help='Nome do processo da VPN, se a detecção automática falhar.')
    parser.add_argument('--sem-prompt', action='store_true', help='Não interromper a execução para pedir entradas manuais.')
    parser.add_argument('--salvar-relatorio', action='store_true', help='Grava um relatório JSON em disco ao final.')
    return parser.parse_args()


def _confirmar_interface_fisica(interface_fisica, modo_silencioso=False):
    if not interface_fisica:
        return None

    print('\n[!] Interface física escolhida pelo sistema: ' + interface_fisica)
    detalhes = obter_detalhes_interface(interface_fisica)
    print(f"    IP(s): {', '.join(detalhes.get('ips') or ['não identificado'])}")
    print(f"    Gateway padrão: {detalhes.get('gateway_padrao') or 'não identificado'}")
    
    if modo_silencioso:
        return interface_fisica

    print('[*] Interfaces ativas disponíveis:')
    for iface in listar_interfaces_ativas():
        detalhe = obter_detalhes_interface(iface)
        ips = ', '.join(detalhe.get('ips') or ['sem IP'])
        gateway = detalhe.get('gateway_padrao') or 'sem gateway'
        print(f'    - {iface}: IP={ips}; Gateway={gateway}')

    resposta = input(f"Confirma que '{interface_fisica}' é a interface correta para monitorar tráfego local? [S/n]: ").strip().lower()
    if resposta in ('', 's', 'sim', 'y', 'yes'):
        return interface_fisica

    nova_interface = input('Digite a interface física correta (ex: Wi-Fi, Ethernet, en0, eth0): ').strip()
    return nova_interface or interface_fisica


if __name__ == "__main__":
    print("=== Preparação para os Testes (Baseline) ===")
    args = _parse_args()

    MEUS_IPS_REAIS = obter_ips_reais()
    MEUS_DNS_REAIS = obter_dns_real()

    if not MEUS_IPS_REAIS.get('v4') or not MEUS_DNS_REAIS:
        print("[-] Falha ao estabelecer o baseline da rede. Verifique a sua ligação à internet.")
        sys.exit(1)

    print("\n" + "=" * 50)
    print(">>> LIGUE O CLIENTE VPN <<<")
    if not args.sem_prompt:
        input("Pressione [ENTER] APENAS QUANDO A VPN ESTIVER CONECTADA...")

    INTERFACE_VPN, NOME_PROCESSO_VPN, TIPO_VPN, INTERFACE_FISICA, DETALHES_REDE = detectar_ambiente_vpn()

    if args.interface_vpn:
        INTERFACE_VPN = args.interface_vpn
    if args.nome_vpn:
        NOME_PROCESSO_VPN = args.nome_vpn
    if args.interface_fisica:
        INTERFACE_FISICA = args.interface_fisica

    if not INTERFACE_VPN:
        if args.sem_prompt:
            raise SystemExit('Interface da VPN não foi detectada e o modo sem prompt foi habilitado.')
        INTERFACE_VPN = input("Digite a interface da VPN (ex: tun0, utun3, wg0): ").strip()
    if not NOME_PROCESSO_VPN:
        if args.sem_prompt:
            NOME_PROCESSO_VPN = 'desconhecido'
        else:
            NOME_PROCESSO_VPN = input("Digite o processo da VPN (ex: openvpn, wg, nordvpn): ").strip()
    if not INTERFACE_FISICA:
        if args.sem_prompt:
            raise SystemExit('Interface física não foi detectada e o modo sem prompt foi habilitado.')
        INTERFACE_FISICA = input("Digite a interface física da máquina (ex: Wi-Fi, Ethernet, en0, eth0): ").strip()

    INTERFACE_FISICA = _confirmar_interface_fisica(INTERFACE_FISICA, args.sem_prompt)

    tester = VPNSecurityTester(
        MEUS_IPS_REAIS,
        MEUS_DNS_REAIS,
        NOME_PROCESSO_VPN,
        INTERFACE_VPN,
        INTERFACE_FISICA,
        info_rede=DETALHES_REDE,
        salvar_relatorio=args.salvar_relatorio,
    )
    tester.run_all_tests()