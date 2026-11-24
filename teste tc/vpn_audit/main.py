import argparse
import sys

from core.nucleo_exec import VPNSecurityTester
from tests import test_5_desempenho
from utils.network import (
    capturar_estado_base, detectar_ambiente_vpn, eh_administrador, interface_esta_ativa,
    listar_interfaces_ativas, listar_processos_novos, obter_detalhes_interface, obter_dns_real,
    obter_ips_reais,
)


def _parse_args():
    p = argparse.ArgumentParser(description="Auditoria de isolamento de roteamento L3/L4 para VPNs.")
    p.add_argument("--interface-vpn", help="Interface da VPN, se a detecção automática falhar.")
    p.add_argument("--interface-fisica", help="Interface física, se a detecção automática falhar.")
    p.add_argument("--nome-vpn", help="Nome do processo PRINCIPAL da VPN (usado no teste de kill-switch).")
    p.add_argument("--rotulo", help="Nome comercial da VPN para relatórios/gráficos (ex.: 'TunnelBear').")
    p.add_argument("--versao-cliente", help="Versão do cliente VPN testado (registrada no JSON).")
    p.add_argument("--servidor-vpn", help="País/cidade do servidor VPN escolhido (registrado no JSON).")
    p.add_argument("--sem-prompt", action="store_true", help="Não pedir entradas manuais.")
    p.add_argument("--salvar-relatorio", action="store_true", help="Grava JSON, gráficos e tabela-resumo.")
    p.add_argument("--pasta-saida", default="resultados", help="Pasta dos relatórios (padrão: resultados).")
    p.add_argument("--repeticoes-qos", type=int, default=3, help="Repetições do Speedtest (padrão: 3).")
    p.add_argument("--forcar-testes", action="store_true",
                   help="Roda os testes mesmo que o túnel não pareça estabelecido.")
    p.add_argument("--pular-killswitch", action="store_true", help="Não executa o teste de kill-switch.")
    p.add_argument("--anonimizar", action="store_true", help="Mascara IP real e MACs no JSON salvo.")
    p.add_argument("--permitir-sem-admin", action="store_true",
                   help="Continua mesmo sem privilégio de administrador (kill-switch e captura podem falhar).")
    return p.parse_args()


def _confirmar_interface_fisica(interface_fisica, gateway, silencioso=False):
    if not interface_fisica:
        return None
    print(f"\n[!] Interface física (detectada ANTES da VPN): {interface_fisica}")
    detalhes = obter_detalhes_interface(interface_fisica)
    print(f"    IP(s): {', '.join(detalhes.get('ips') or ['não identificado'])}")
    print(f"    Gateway padrão (baseline): {gateway or 'não identificado'}")
    if silencioso:
        return interface_fisica
    resposta = input(f"Confirma que '{interface_fisica}' é a interface física correta? [S/n]: ").strip().lower()
    if resposta in ("", "s", "sim", "y", "yes"):
        return interface_fisica
    return input("Digite a interface física correta (ex.: Wi-Fi, Ethernet): ").strip() or interface_fisica


def main():
    args = _parse_args()
    print("=== Preparação para os Testes (Baseline, SEM VPN) ===")

    if not eh_administrador():
        print("[!] Este terminal NÃO é administrador/root: a captura de pacotes e o encerramento do "
              "processo da VPN podem falhar.")
        if not args.permitir_sem_admin:
            print("    Abra o terminal como Administrador (ou use --permitir-sem-admin para prosseguir).")
            sys.exit(1)

    ips_reais = obter_ips_reais()
    if not ips_reais.get("v4"):
        print("[-] ERRO CRÍTICO: falha ao estabelecer o baseline de IPv4.")
        sys.exit(1)

    print("[*] Capturando estado de rede de referência (interface física, gateway, adaptadores)...")
    base = capturar_estado_base()
    interface_fisica = args.interface_fisica or base.get("interface_fisica")
    if not interface_fisica:
        if args.sem_prompt:
            sys.exit("Interface física não detectada e --sem-prompt habilitado.")
        interface_fisica = input("Digite a interface física (ex.: Wi-Fi, Ethernet): ").strip()
    interface_fisica = _confirmar_interface_fisica(interface_fisica, base.get("gateway"), args.sem_prompt)
    if not interface_esta_ativa(interface_fisica):
        sys.exit(f"Interface física '{interface_fisica}' não está ativa; auditoria cancelada.")

    dns_fisico = base.get("dns_interface_fisica") or []
    dns_real = dns_fisico or obter_dns_real()
    print(f"[+] DNS da interface física: {', '.join(dns_real) if dns_real else 'não identificado'}"
          + ("" if dns_fisico else "  (lista agregada do sistema; pode conter adaptadores antigos)"))

    print("\n[*] Capturando baseline de velocidade (SEM VPN)...")
    desempenho_base = test_5_desempenho.executar(repeticoes=args.repeticoes_qos, titulo="Baseline QoS (sem VPN)")
    if desempenho_base.get("status") == "CONCLUIDO":
        print(f"    [+] Baseline QoS: {desempenho_base['detalhes']}")
    else:
        print("    [-] Aviso: baseline QoS incompleto; os gráficos de QoS ficarão indisponíveis.")

    print("\n" + "=" * 50)
    print(">>> LIGUE O CLIENTE VPN <<<")
    print("    Dica: feche navegadores e apps que usem rede, para reduzir ruído na captura.")
    if not args.sem_prompt:
        input("Pressione [ENTER] APENAS QUANDO A VPN ESTIVER CONECTADA E ESTABILIZADA (~10 s)...")

    interface_vpn, metodo_iface, nome_processo, info_proc, detalhe_rede = detectar_ambiente_vpn(base, args.nome_vpn)
    interface_vpn = args.interface_vpn or interface_vpn
    nome_processo = args.nome_vpn or nome_processo
    if interface_vpn:
        print(f"[+] Interface da VPN: {interface_vpn} (método: {metodo_iface or 'informada pelo usuário'})")
    else:
        print("[!] Nenhuma interface de VPN detectada (nenhuma rota/adaptador novo). "
              "O túnel pode não estar estabelecido ou a VPN pode ser baseada em proxy.")
        if not args.sem_prompt:
            print("    Interfaces ativas: " + ", ".join(listar_interfaces_ativas()))
            interface_vpn = input("Digite a interface da VPN (ENTER para seguir sem interface): ").strip() or None

    if not nome_processo:
        novos = listar_processos_novos(base)
        print("[!] Processo principal da VPN não identificado automaticamente.")
        if novos:
            print("    Processos novos desde o baseline: " + ", ".join(novos))
        if not args.sem_prompt:
            nome_processo = input("Digite o nome do processo principal da VPN (ENTER para pular): ").strip() or None
    if not nome_processo:
        nome_processo = "nao-detectado"
        print("    O teste de kill-switch ficará INCONCLUSIVO.")

    meta = {
        "rotulo": args.rotulo or nome_processo,
        "versao_cliente": args.versao_cliente,
        "servidor_vpn": args.servidor_vpn,
        "metodo_deteccao_interface": metodo_iface,
        "processo": info_proc,
        "interface_fisica_metodo": base.get("metodo_interface_fisica"),
        "dns_interface_fisica": dns_fisico,
        "executado_como_admin": eh_administrador(),
    }

    tester = VPNSecurityTester(
        ips_reais, dns_real, nome_processo, interface_vpn, interface_fisica,
        info_rede=detalhe_rede, salvar_relatorio=args.salvar_relatorio,
        baseline_velocidade=desempenho_base, gateway_fisico=base.get("gateway"),
        forcar_testes=args.forcar_testes, pular_killswitch=args.pular_killswitch,
        repeticoes_qos=args.repeticoes_qos, pasta_saida=args.pasta_saida,
        anonimizar=args.anonimizar, meta=meta,
    )
    relatorio = tester.run_all_tests()

    veredicto = relatorio.get("veredicto_final")
    sys.exit(0 if veredicto == "APROVADO NO ESCOPO" else 1 if veredicto == "REPROVADO" else 2)


if __name__ == "__main__":
    main()
