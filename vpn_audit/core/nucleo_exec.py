import json
import os
import platform
import re
import socket
import time
from datetime import datetime

from scapy.all import UDP

from tests import (
    test_1_isolamento_payload, test_2_isolamento_http, test_3_privacidade,
    test_4_isolamento_rota, test_5_desempenho, test_6_killswitch,
)
from utils import graficos
from utils.captura import Captura
from utils.network import consultar_ipv4, info_saida, interface_esta_ativa, versoes_dependencias

T_UDP = "Isolamento de Payload UDP"
T_HTTP = "Isolamento HTTP"
T_PRIV = "Privacidade (IP/DNS/IPv6)"
T_ROTAS = "Isolamento de Rotas (Multi-Protocolo)"
T_QOS = "Impacto de Desempenho (QoS)"
T_KILL = "Kill-Switch (Isolamento Cronológico)"
NOMES_TESTES = [T_UDP, T_HTTP, T_PRIV, T_ROTAS, T_QOS, T_KILL]
# Testes cuja aprovação depende de a captura na interface física estar realmente viva.
TESTES_DEPENDEM_DA_CAPTURA = [T_UDP, T_HTTP, T_PRIV, T_ROTAS, T_KILL]

ESTADOS_APROVADOS = {"SUCESSO", "ISOLADO", "BLOQUEADO", "CONCLUIDO"}

_RE_MAC = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
_RE_MAC_ROUTE = re.compile(r"(?<=\.\.\.)(?:[0-9A-Fa-f]{2} ){5}[0-9A-Fa-f]{2}")


class VPNSecurityTester:
    def __init__(self, ips_reais, dns_real, vpn_process_name, interface_rede, interface_fisica,
                 info_rede=None, salvar_relatorio=False, baseline_velocidade=None,
                 gateway_fisico=None, forcar_testes=False, pular_killswitch=False,
                 repeticoes_qos=3, pasta_saida="resultados", anonimizar=False, meta=None):
        self.ips_reais = ips_reais
        self.dns_real = list(dns_real or [])
        self.vpn_process_name = vpn_process_name
        self.interface_vpn = interface_rede
        self.interface_fisica = interface_fisica
        self.info_rede = info_rede or {}
        self.salvar_relatorio = salvar_relatorio
        self.baseline_velocidade = baseline_velocidade or {}
        self.gateway_fisico = gateway_fisico
        self.forcar_testes = forcar_testes
        self.pular_killswitch = pular_killswitch
        self.repeticoes_qos = repeticoes_qos
        self.pasta_saida = pasta_saida
        self.anonimizar = anonimizar
        self.meta = meta or {}
        self.resultados = {}
        self.precondicao = {}
        self.controle = {}

        self.escopo_auditoria = {
            "sistema_operacional": f"{platform.system()} {platform.release()}",
            "protocolos_monitorados": ["TCP/80", "TCP/443", "TCP/853 (DoT)", "UDP/53", "UDP/443",
                                       "DoH/HTTPS", "IPv4", "IPv6 (somente se houver IPv6 nativo)"],
            "bypass_proxy_local": True,
            "analise_criptografica": "Não testada. Restrito a L3/L4 (isolamento de rota, kill-switch e QoS)",
            "comportamento_esperado_queda": "Fail-Closed (nenhum tráfego do teste na interface física após a queda)",
            "tipo_de_vpn_coberto": "Clientes de desktop com adaptador virtual; extensões de navegador/proxy ficam fora do escopo",
            "qos_no_veredito": False,
        }

    # ------------------------------------------------------------------ #
    # Pré-condições
    # ------------------------------------------------------------------ #
    def _verificar_precondicao(self):
        """O túnel está de fato estabelecido? (IP de saída diferente do real)."""
        ip, _ = consultar_ipv4()
        base = self.ips_reais.get("v4")
        iface_ativa = interface_esta_ativa(self.interface_vpn)
        ip_mudou = bool(ip and base and ip != base)
        estabelecido = ip_mudou if ip else iface_ativa
        info = info_saida(ip) if (ip and estabelecido) else None
        if estabelecido:
            detalhe = f"IP de saída {ip} difere do IP real." if ip_mudou else "IP de saída indisponível; interface VPN ativa."
        else:
            detalhe = (f"IP de saída ({ip}) igual ao IP real" if ip else "IP de saída indisponível e interface VPN inativa") \
                      + "; nenhum tráfego foi mascarado: o túnel não parece estabelecido."
        return {"ip_saida_v4": ip, "ip_mudou": ip_mudou, "interface_vpn_ativa": iface_ativa,
                "tunel_estabelecido": bool(estabelecido), "detalhe": detalhe, "info_saida": info}

    def _controle_captura(self):
        """Controle positivo: um datagrama ao gateway DEVE aparecer na captura física."""
        gw = self.gateway_fisico
        if not gw:
            return {"executado": False, "ok": None, "detalhe": "gateway físico desconhecido"}
        cap = Captura(self.interface_fisica, f"udp and dst host {gw} and dst port 9", "física")
        portas = set()
        cap.iniciar()
        time.sleep(0.7)
        if cap.iniciou:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.bind(("", 0))
                portas.add(s.getsockname()[1])
                for _ in range(3):
                    s.sendto(b"CONTROLE_CAPTURA", (gw, 9))
                    time.sleep(0.1)
            except OSError:
                pass
            finally:
                s.close()
            # Fallback: se o firewall/WFP da VPN bloqueou socket UDP para LAN, injeta direto via Scapy L3
            porta_l3 = 54321
            portas.add(porta_l3)
            try:
                from scapy.all import IP, send
                send(IP(dst=gw)/UDP(sport=porta_l3, dport=9)/b"CONTROLE_CAPTURA",
                     iface=self.interface_fisica, verbose=False)
            except Exception:
                pass
        time.sleep(1)
        pacotes = cap.parar()
        visto = any(p.haslayer(UDP) and p[UDP].sport in portas for p in pacotes)
        if not cap.iniciou:
            return {"executado": True, "ok": False, "detalhe": f"sensor não iniciou: {cap.erro}"}
        return {"executado": True, "ok": visto,
                "detalhe": "captura física confirmada" if visto else
                           "o datagrama de controle ao gateway não foi visto (captura cega ou LAN bloqueada)"}

    # ------------------------------------------------------------------ #
    # Execução
    # ------------------------------------------------------------------ #
    @staticmethod
    def _executar_com_protecao(funcao, *args, **kwargs):
        try:
            return funcao(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001
            return {"status": "ERRO", "detalhes": f"Exceção não tratada no teste: {exc}"}

    def run_all_tests(self):
        print("\n=== Iniciando Auditoria de Rede (Escopo Restrito) ===")
        print(f"Interface Física : {self.interface_fisica}")
        print(f"Interface VPN    : {self.interface_vpn}")
        print(f"Processo Alvo    : {self.vpn_process_name}")
        print("-" * 50)

        print("[*] Verificando pré-condições (túnel estabelecido e captura funcional)...")
        self.precondicao = self._verificar_precondicao()
        print(f"    {'[+]' if self.precondicao['tunel_estabelecido'] else '[!]'} {self.precondicao['detalhe']}")
        self.controle = self._controle_captura()
        if self.controle["ok"] is False:
            print(f"    [!] Controle da captura física FALHOU: {self.controle['detalhe']}")
        elif self.controle["ok"]:
            print("    [+] Controle da captura física OK (sensor enxerga a interface física).")

        if not self.precondicao["tunel_estabelecido"] and not self.forcar_testes:
            print("[!] Túnel não estabelecido: testes NÃO executados (use --forcar-testes para rodá-los mesmo assim).")
            for nome in NOMES_TESTES:
                self.resultados[nome] = {"status": "NAO_APLICAVEL",
                                         "detalhes": "Túnel não estabelecido: " + self.precondicao["detalhe"]}
            return self._finalizar()

        r, f, v4 = self._executar_com_protecao, self.interface_fisica, self.interface_vpn
        self.resultados[T_UDP] = r(test_1_isolamento_payload.executar, f, v4)
        self.resultados[T_HTTP] = r(test_2_isolamento_http.executar, f, v4)
        self.resultados[T_PRIV] = r(test_3_privacidade.executar, self.ips_reais, self.dns_real, f, v4)
        self.resultados[T_ROTAS] = r(test_4_isolamento_rota.executar, f, v4,
                                     testar_ipv6=bool(self.ips_reais.get("v6")), dns_real=self.dns_real)
        self.resultados[T_QOS] = r(test_5_desempenho.executar,
                                   repeticoes=self.repeticoes_qos,
                                   servidor_id=self.baseline_velocidade.get("servidor_id"),
                                   ip_baseline_v4=self.ips_reais.get("v4"),
                                   titulo="Impacto de Desempenho (QoS) - VPN ativa")
        if self.pular_killswitch:
            self.resultados[T_KILL] = {"status": "NAO_APLICAVEL", "detalhes": "Ignorado por opção (--pular-killswitch)."}
        else:  # o teste 6 SEMPRE encerra o processo da VPN e por isso roda por último
            self.resultados[T_KILL] = r(test_6_killswitch.executar, self.vpn_process_name, f, v4,
                                        self.gateway_fisico, self.ips_reais.get("v4"))
        self._aplicar_rebaixamento()
        return self._finalizar()

    def _aplicar_rebaixamento(self):
        """Sem prova de que a captura física funciona, 'nada visto' não é evidência de isolamento."""
        if self.controle.get("ok") is not False:
            return
        for nome in TESTES_DEPENDEM_DA_CAPTURA:
            dados = self.resultados.get(nome, {})
            if dados.get("status") in ("ISOLADO", "BLOQUEADO"):
                dados["status_original"] = dados["status"]
                dados["status"] = "INCONCLUSIVO"
                dados["detalhes"] = (dados.get("detalhes", "") +
                                     " [Rebaixado: o controle positivo da captura física falhou.]").strip()

    # ------------------------------------------------------------------ #
    # Veredito e relatório
    # ------------------------------------------------------------------ #
    def _avaliar_politica_resultado(self):
        if not self.resultados:
            return "NAO COMPROVADO"
        if not self.precondicao.get("tunel_estabelecido", True) and not self.forcar_testes:
            return "TUNEL NAO ESTABELECIDO"
        seguranca = {k: v for k, v in self.resultados.items() if k != T_QOS}  # QoS é informativo
        estados = [d.get("status", "ERRO") for d in seguranca.values()]
        if "FALHA" in estados:
            return "REPROVADO"
        if all(s in ESTADOS_APROVADOS for s in estados):
            return "APROVADO NO ESCOPO"
        return "NAO COMPROVADO"

    @staticmethod
    def _imprimir_grupo(itens):
        if not itens:
            print("  (nenhum)")
            return
        for teste, status in itens:
            print(f"  - {teste:<38} : {status}")

    def _gerar_relatorio(self):
        veredicto = self._avaliar_politica_resultado()
        print("\n" + "=" * 50)
        print("RESUMO CONSOLIDADO E VEREDICTO FINAL")
        print("=" * 50)
        grupos = {"APROVADOS": [], "INCONCLUSIVOS": [], "NAO APLICAVEIS": [], "FALHAS": [], "ERROS": []}
        for teste, dados in self.resultados.items():
            st = dados.get("status", "ERRO")
            if st in ESTADOS_APROVADOS:
                grupos["APROVADOS"].append((teste, st))
            elif st == "INCONCLUSIVO":
                grupos["INCONCLUSIVOS"].append((teste, st))
            elif st == "NAO_APLICAVEL":
                grupos["NAO APLICAVEIS"].append((teste, st))
            elif st == "FALHA":
                grupos["FALHAS"].append((teste, st))
            else:
                grupos["ERROS"].append((teste, st))
        for nome, itens in grupos.items():
            print(f"{nome}:")
            self._imprimir_grupo(itens)

        priv = self.resultados.get(T_PRIV)
        if isinstance(priv, dict) and "ipv4_status" in priv:
            print("PRIVACIDADE DETALHADA:")
            for rotulo, chave in (("IPv4", "ipv4_status"), ("IPv6", "ipv6_status"),
                                  ("DNS", "dns_status"), ("DoH/DoT", "doh_dot_status")):
                print(f"  {rotulo:<8}: {priv.get(chave, 'INCONCLUSIVO')}")
        print("-" * 50)
        print(f"VEREDICTO (segurança; QoS não entra): {veredicto}")
        if veredicto == "APROVADO NO ESCOPO":
            print("NOTA: aprovada nos cenários e protocolos definidos; não equivale a 'VPN segura'.")
        print("=" * 50 + "\n")

        return {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "veredicto_final": veredicto,
            "tunel_estabelecido": self.precondicao.get("tunel_estabelecido"),
            "execucao_forcada": self.forcar_testes,
            "precondicao_tunel": self.precondicao,
            "controle_captura_fisica": self.controle,
            "escopo_auditoria": self.escopo_auditoria,
            "ambiente": versoes_dependencias(),
            "metadados": self.meta,
            "baseline_ips": self.ips_reais,
            "baseline_dns": self.dns_real,
            "baseline_velocidade": self.baseline_velocidade,
            "rotulo": self.meta.get("rotulo") or self.vpn_process_name,
            "processo_vpn_alvo": self.vpn_process_name,
            "interfaces": {"vpn": self.interface_vpn, "fisica": self.interface_fisica},
            "resultados": self.resultados,
            "estado_rede": self.info_rede,
        }

    def _finalizar(self):
        relatorio = self._gerar_relatorio()
        if self.salvar_relatorio:
            caminho = self._salvar_relatorio(relatorio)
            relatorio["relatorio_salvo"] = bool(caminho)
            if caminho:
                pasta = os.path.dirname(os.path.abspath(caminho))
                for etapa in (lambda: graficos.gerar_graficos_individuais(caminho, relatorio),
                              lambda: graficos.gerar_comparativo_seguranca(pasta),
                              lambda: graficos.gerar_comparativo_qos(pasta),
                              lambda: graficos.gerar_tabela_resumo(pasta)):
                    try:  # um erro de gráfico não pode perder o relatório já salvo
                        etapa()
                    except Exception as exc:  # noqa: BLE001
                        print(f"[!] Falha ao gerar gráfico/tabela: {exc}")
        return relatorio

    # ------------------------------------------------------------------ #
    def _mascarar(self, obj):
        ips = [v for v in (self.ips_reais.get("v4"), self.ips_reais.get("v6")) if v]

        def tratar(s):
            for ip in ips:
                s = s.replace(ip, "<IP_REAL>")
            return _RE_MAC_ROUTE.sub("<MAC>", _RE_MAC.sub("<MAC>", s))

        if isinstance(obj, dict):
            return {k: self._mascarar(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._mascarar(v) for v in obj]
        return tratar(obj) if isinstance(obj, str) else obj

    def _salvar_relatorio(self, relatorio):
        os.makedirs(self.pasta_saida, exist_ok=True)
        nome = re.sub(r"[^A-Za-z0-9._-]+", "_", str(self.meta.get("rotulo") or self.vpn_process_name).replace(".exe", ""))
        caminho = os.path.join(self.pasta_saida, f"auditoria_vpn_{nome}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        try:
            dados = self._mascarar(relatorio) if self.anonimizar else relatorio
            with open(caminho, "w", encoding="utf-8") as arq:
                json.dump(dados, arq, indent=2, ensure_ascii=False, default=str)
            print(f"[+] Relatório JSON salvo em: {caminho}")
            return caminho
        except Exception as e:  # noqa: BLE001
            print(f"[-] Erro crítico ao salvar o relatório JSON: {e}")
            return None
