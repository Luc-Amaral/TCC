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
            "sistema_operacional": f"{platform.system()} {platform.release()}",
            "protocolos_monitorados": [
                "TCP/80", "TCP/443", "TCP/853 (DoT)", "UDP/53", "UDP/443",
                "DoH/HTTPS", "IPv4", "IPv6"
            ],
            "bypass_proxy_local": True,
            "analise_criptografica": "Não testada. Restrito a auditoria L3/L4 (Isolamento de rotas e Fallback)",
            "comportamento_esperado_queda": "Fail-Closed (Bloqueio estrito de tráfego físico pós-queda)"
        }

    def run_all_tests(self):
        print(f"\n=== Iniciando Auditoria de Rede (Escopo Restrito) ===")
        print(f"Interface Física : {self.interface_fisica}")
        print(f"Interface VPN    : {self.interface_vpn}")
        print(f"Processo Alvo    : {self.vpn_process_name}")
        print("-" * 50)

        self.resultados['Isolamento de Payload UDP'] = self._executar_com_protecao(
            test_1_isolamento_payload.executar, self.interface_fisica, self.interface_vpn
        )
        self.resultados['Isolamento HTTP'] = self._executar_com_protecao(
            test_2_isolamento_http.executar, self.interface_fisica, self.interface_vpn
        )
        self.resultados['Privacidade (IP/DNS/IPv6)'] = self._executar_com_protecao(
            test_3_privacidade.executar, self.ips_reais, self.dns_real, self.interface_fisica, self.interface_vpn
        )
        self.resultados['Isolamento de Rotas (Multi-Protocolo)'] = self._executar_com_protecao(
            test_4_isolamento_rota.executar, self.interface_fisica, self.interface_vpn
        )
        self.resultados['Kill-Switch (Isolamento Cronológico)'] = self._executar_com_protecao(
            test_5_killswitch.executar, self.vpn_process_name, self.interface_fisica, self.interface_vpn
        )

        relatorio = self._gerar_relatorio()
        if self.salvar_relatorio:
            relatorio['relatorio_salvo'] = self._salvar_relatorio(relatorio)
        return relatorio

    @staticmethod
    def _executar_com_protecao(funcao, *args):
        try:
            return funcao(*args)
        except Exception as exc:
            return {
                'status': 'ERRO',
                'detalhes': f'Excecao nao tratada no teste: {exc}',
            }

    def _avaliar_politica_resultado(self):
        if not self.resultados: return "NAO COMPROVADO"
        
        estados_aprovados = {"SUCESSO", "ISOLADO", "BLOQUEADO"}
        estados = [dados.get('status', 'ERRO') for dados in self.resultados.values()]
        
        if "FALHA" in estados: return "REPROVADO"
        if "ERRO" in estados or "INCONCLUSIVO" in estados: return "NAO COMPROVADO"
        
        if all(s in estados_aprovados for s in estados): return "APROVADO NO ESCOPO"
        
        return "NAO COMPROVADO"

    def _gerar_relatorio(self):
        veredicto = self._avaliar_politica_resultado()

        print("\n" + "=" * 50)
        print("RESUMO CONSOLIDADO E VEREDICTO FINAL")
        print("=" * 50)

        aprovados = {
            "SUCESSO", "ISOLADO", "BLOQUEADO"
        }
        grupos = {
            "APROVADOS": [],
            "INCONCLUSIVOS": [],
            "FALHAS": [],
            "ERROS": [],
        }
        for teste, dados in self.resultados.items():
            status = dados.get('status', 'ERRO')
            if status in aprovados:
                grupos["APROVADOS"].append((teste, status))
            elif status == "INCONCLUSIVO":
                grupos["INCONCLUSIVOS"].append((teste, status))
            elif status == "FALHA":
                grupos["FALHAS"].append((teste, status))
            else:
                grupos["ERROS"].append((teste, status))

        print("APROVADOS:")
        self._imprimir_grupo(grupos["APROVADOS"])
        print("INCONCLUSIVOS:")
        self._imprimir_grupo(grupos["INCONCLUSIVOS"])
        print("FALHAS:")
        self._imprimir_grupo(grupos["FALHAS"])
        print("ERROS:")
        self._imprimir_grupo(grupos["ERROS"])

        privacidade = self.resultados.get('Privacidade (IP/DNS/IPv6)')
        if isinstance(privacidade, dict):
            print("PRIVACIDADE DETALHADA:")
            print(f"  IPv4 : {privacidade.get('ipv4_status', 'INCONCLUSIVO')}")
            print(f"  IPv6 : {privacidade.get('ipv6_status', 'INCONCLUSIVO')}")
            print(f"  DNS  : {privacidade.get('dns_status', 'INCONCLUSIVO')}")
            print(f"  DoH/DoT : {privacidade.get('doh_dot_status', 'INCONCLUSIVO')}")

        print("-" * 50)
        print(f"VEREDICTO: {veredicto}")
        if veredicto == "APROVADO NO ESCOPO":
            print("NOTA: A VPN foi aprovada nos cenários e protocolos definidos para esta auditoria.")
        print("=" * 50 + "\n")

        relatorio = {
            'timestamp': datetime.now().isoformat(timespec='seconds'),
            'veredicto_final': veredicto,
            'escopo_auditoria': self.escopo_auditoria,
            'baseline_ips': self.ips_reais,
            'baseline_dns': list(self.dns_real),
            'processo_vpn_alvo': self.vpn_process_name,
            'interfaces': {
                'vpn': self.interface_vpn,
                'fisica': self.interface_fisica
            },
            'resultados': self.resultados,
            'estado_rede': self.info_rede,
        }
        return relatorio

    @staticmethod
    def _imprimir_grupo(itens):
        if not itens:
            print("  (nenhum)")
            return
        for teste, status in itens:
            print(f"  - {teste:<36} : {status}")

    def _salvar_relatorio(self, relatorio):
        nome_arquivo = f"auditoria_vpn_{self.vpn_process_name.replace('.exe', '')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(nome_arquivo, 'w', encoding='utf-8') as arquivo:
                json.dump(relatorio, arquivo, indent=2, ensure_ascii=False)
            print(f"[+] Relatório JSON salvo em: {nome_arquivo}")
            return True
        except Exception as e:
            print(f"[-] Erro crítico ao salvar o relatório JSON: {e}")
            return False