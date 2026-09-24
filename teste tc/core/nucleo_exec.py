import json
from datetime import datetime

from tests import test_1_criptografia, test_2_integridade, test_3_privacidade, test_4_robustez  # test_5_killswitch


class VPNSecurityTester:
    def __init__(self, ip_real, dns_real, vpn_process_name, interface_rede, interface_fisica, info_rede=None, salvar_relatorio=False):
        self.ip_real = ip_real
        self.dns_real = dns_real
        self.vpn_process_name = vpn_process_name
        self.interface_rede = interface_rede
        self.interface_fisica = interface_fisica
        self.info_rede = info_rede or {}
        self.salvar_relatorio = salvar_relatorio
        self.resultados = {}

    def run_all_tests(self):
        print(f"\n=== Iniciando Bateria de Testes ===")
        print(f"Interface Física Monitorada: {self.interface_fisica}")
        print(f"Interface VPN Monitorada: {self.interface_rede}")
        print(f"Processo da VPN: {self.vpn_process_name}")
        print("-" * 50)

        self.resultados['Criptografia'] = test_1_criptografia.executar(self.interface_fisica)
        self.resultados['Integridade (Porta 80)'] = test_2_integridade.executar(self.interface_fisica)
        self.resultados['Privacidade (IP/DNS)'] = test_3_privacidade.executar(self.ip_real, self.dns_real, self.interface_fisica)
        self.resultados['Robustez (Rota)'] = test_4_robustez.executar(self.interface_fisica)
        # self.resultados['Kill-Switch (Crash)'] = test_5_killswitch.executar(self.vpn_process_name, self.ip_real)

        relatorio = self._gerar_relatorio()
        if self.salvar_relatorio:
            self._salvar_relatorio(relatorio)

    def _gerar_relatorio(self):
        print("\n" + "=" * 50)
        print("RESUMO CONSOLIDADO DOS TESTES")
        print("=" * 50)
        for teste, resultado in self.resultados.items():
            valor = resultado if resultado is not None else 'INCONCLUSIVO'
            print(f"{teste:<25} : {valor}")
        print("=" * 50 + "\n")

        relatorio = {
            'timestamp': datetime.now().isoformat(timespec='seconds'),
            'ip_real': self.ip_real,
            'dns_real': list(self.dns_real),
            'processo_vpn': self.vpn_process_name,
            'interface_vpn': self.interface_rede,
            'interface_fisica': self.interface_fisica,
            'resultados': self.resultados,
            'rede': self.info_rede,
        }
        return relatorio

    def _salvar_relatorio(self, relatorio):
        nome_arquivo = f"relatorio_vpn_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(nome_arquivo, 'w', encoding='utf-8') as arquivo:
                json.dump(relatorio, arquivo, indent=2, ensure_ascii=False)
            print(f"[+] Relatório salvo em: {nome_arquivo}")
        except Exception as e:
            print(f"[-] Não foi possível salvar o relatório: {e}")