from tests import test_1_criptografia, test_2_integridade, test_3_privacidade, test_4_robustez #test_5_killswitch

class VPNSecurityTester:
    def __init__(self, ip_real, dns_real, vpn_process_name, interface_rede, interface_fisica):
        self.ip_real = ip_real
        self.dns_real = dns_real
        self.vpn_process_name = vpn_process_name
        self.interface_rede = interface_rede
        self.interface_fisica = interface_fisica
        self.resultados = {}

    def run_all_tests(self):
        print(f"\n=== Iniciando Bateria de Testes ===")
        print(f"Interface Física Monitorada: {self.interface_fisica}")
        print(f"Interface VPN Monitorada: {self.interface_rede}")
        print("-" * 50)

        self.resultados['Criptografia'] = test_1_criptografia.executar(self.interface_fisica)
        self.resultados['Integridade (Porta 80)'] = test_2_integridade.executar(self.interface_fisica)
        
        # Teste 3 agora recebe a interface física para farejar DNS leak
        self.resultados['Privacidade (IP/DNS)'] = test_3_privacidade.executar(self.ip_real, self.dns_real, self.interface_fisica)
        
        self.resultados['Robustez (Nmap)'] = test_4_robustez.executar(self.interface_rede)
        #self.resultados['Kill-Switch (Crash)'] = test_5_killswitch.executar(self.vpn_process_name, self.ip_real)

        self._gerar_relatorio()

    def _gerar_relatorio(self):
        print("\n" + "=" * 50)
        print("RESUMO CONSOLIDADO DOS TESTES")
        print("=" * 50)
        for teste, resultado in self.resultados.items():
            print(f"{teste:<25} : {resultado}")
        print("=" * 50 + "\n")