import json
import platform
from datetime import datetime

from tests import test_1_isolamento_payload, test_2_isolamento_http, test_3_privacidade, test_4_isolamento_rota, test_5_killswitch


class VPNSecurityTester:
    def __init__(self, ips_reais, dns_real, vpn_process_name, interface_rede, interface_fisica, info_rede=None, salvar_relatorio=False):
        self.ips_reais = ips_reais
        self.dns_real = dns_real
        self.vpn_process_name = vpn_process_name
        self.interface_vpn = interface_rede
        self.interface_fisica = interface_fisica
        self.info_rede = info_rede or {}
        self.salvar_relatorio = salvar_relatorio
        self.resultados = {}
        
        self.escopo_auditoria = {
            "sistema_operacional": platform.system() + " " + platform.release(),
            "protocolos_monitorados": ["UDP/9999", "TCP/80", "TCP/53", "UDP/53", "TCP/443 (SYN)"],
            "bypass_proxy_local": True,
            "analise_criptografica": "Não testada (Validação restrita a isolamento de rotas L3/L4)"
        }

    def run_all_tests(self):
        print(f"\n=== Iniciando Auditoria de Rede (Escopo Restrito) ===")
        print(f"Interface Física : {self.interface_fisica}")
        print(f"Interface VPN    : {self.interface_vpn}")
        print(f"Processo Alvo    : {self.vpn_process_name}")
        print("-" * 50)

        self.resultados['Isolamento de Payload UDP'] = test_1_isolamento_payload.executar(self.interface_fisica, self.interface_vpn)
        self.resultados['Isolamento HTTP'] = test_2_isolamento_http.executar(self.interface_fisica, self.interface_vpn)
        self.resultados['Privacidade (IP/DNS/IPv6)'] = test_3_privacidade.executar(self.ips_reais, self.dns_real, self.interface_fisica, self.interface_vpn)
        self.resultados['Isolamento de Rota Nativa'] = test_4_isolamento_rota.executar(self.interface_fisica, self.interface_vpn)
        self.resultados['Kill-Switch (Isolamento Cronológico)'] = test_5_killswitch.executar(self.vpn_process_name, self.interface_fisica)

        relatorio = self._gerar_relatorio()
        if self.salvar_relatorio:
            self._salvar_relatorio(relatorio)

    def _avaliar_politica_resultado(self):
        status_geral = "APROVADO NO ESCOPO"
        for dados in self.resultados.values():
            status_teste = dados.get('status', 'ERRO')
            if status_teste == "FALHA":
                return "REPROVADO (Vazamento Local Detectado)"
            elif status_teste in ["ERRO", "INCONCLUSIVO"]:
                status_geral = "NÃO COMPROVADO (Evidências insuficientes ou erro forense)"
        return status_geral

    def _gerar_relatorio(self):
        veredicto = self._avaliar_politica_resultado()
        
        print("\n" + "=" * 50)
        print("RESUMO CONSOLIDADO E VEREDICTO FINAL")
        print("=" * 50)
        for teste, dados in self.resultados.items():
            status = dados.get('status', 'ERRO')
            print(f"{teste:<38} : {status}")
        print("-" * 50)
        print(f"VEREDICTO: {veredicto}")
        print("=" * 50 + "\n")

        relatorio = {
            'timestamp': datetime.now().isoformat(timespec='seconds'),
            'veredicto_final': veredicto,
            'escopo_auditoria': self.escopo_auditoria,
            'ip_real_base': self.ips_reais,
            'processo_vpn_alvo': self.vpn_process_name,
            'interfaces': {
                'vpn': self.interface_vpn,
                'fisica': self.interface_fisica
            },
            'resultados': self.resultados,
            'estado_rede': self.info_rede,
        }
        return relatorio

    def _salvar_relatorio(self, relatorio):
        nome_arquivo = f"auditoria_vpn_{self.vpn_process_name.replace('.exe', '')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(nome_arquivo, 'w', encoding='utf-8') as arquivo:
                json.dump(relatorio, arquivo, indent=2, ensure_ascii=False)
            print(f"[+] Relatório salvo em: {nome_arquivo}")
        except Exception as e:
            print(f"[-] Erro crítico ao salvar o relatório: {e}")