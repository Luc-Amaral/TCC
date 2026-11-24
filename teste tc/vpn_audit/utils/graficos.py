"""Gráficos e tabela-resumo a partir dos JSONs de auditoria.

Correções em relação à versão anterior:
  * um único vocabulário de status (aceita também os nomes antigos, p.ex. IPv4_VAZADO,
    IPv6_ATIVO_MASCARADO), de modo que vazamento aparece VERMELHO e não laranja;
  * o heatmap de segurança não inclui QoS (que é informativo e não "passa/reprova");
  * QoS com um painel por métrica (unidades distintas), variação percentual e barras de
    dispersão quando há várias medições; legenda fora das barras;
  * estado "NAO_APLICAVEL" (cinza) para túnel não estabelecido / teste inaplicável;
  * rótulos com nome comercial (campo `rotulo`) e data+hora;
  * tabela CSV pronta para a monografia (resumo_multi_vpn.csv).
"""
import csv
import glob
import json
import os
from typing import Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.colors import ListedColormap  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

T_UDP = "Isolamento de Payload UDP"
T_HTTP = "Isolamento HTTP"
T_PRIV = "Privacidade (IP/DNS/IPv6)"
T_ROTAS = "Isolamento de Rotas (Multi-Protocolo)"
T_QOS = "Impacto de Desempenho (QoS)"
T_KILL = "Kill-Switch (Isolamento Cronológico)"

_COR = {"ok": "#27ae60", "falha": "#c0392b", "incon": "#f39c12", "na": "#7f8c8d"}
_BG = "#f8f9fa"
_BASE, _VPN = "#2c3e50", "#e74c3c"

_OK = {"ISOLADO", "BLOQUEADO", "SUCESSO", "CONCLUIDO", "MASCARADO"}
_FALHA = {"FALHA", "VAZADO"}
_NA = {"NAO_APLICAVEL", "NAO APLICAVEL"}

_ROTULO = {"ISOLADO": "ISOLADO", "BLOQUEADO": "BLOQUEADO", "SUCESSO": "SUCESSO", "CONCLUIDO": "CONCLUÍDO",
           "MASCARADO": "MASCARADO", "FALHA": "FALHA", "VAZADO": "VAZADO", "INCONCLUSIVO": "INCONCLUSIVO",
           "ERRO": "ERRO", "NAO_APLICAVEL": "N/A"}
_ABREV = {"ISOLADO": "ISOL", "BLOQUEADO": "BLOQ", "SUCESSO": "OK", "CONCLUIDO": "OK", "MASCARADO": "MASC",
          "FALHA": "FALHA", "VAZADO": "VAZA", "INCONCLUSIVO": "INCON", "ERRO": "ERRO", "NAO_APLICAVEL": "N/A"}

# (rótulo da coluna, teste, sub-métrica)
_COLUNAS = [
    ("Payload\nUDP", T_UDP, None), ("HTTP", T_HTTP, None),
    ("IPv4", T_PRIV, "ipv4_status"), ("IPv6", T_PRIV, "ipv6_status"),
    ("DNS", T_PRIV, "dns_status"), ("DoH/DoT", T_PRIV, "doh_dot_status"),
    ("Rotas", T_ROTAS, None), ("Kill-\nSwitch", T_KILL, None),
]
_COLS_PRIV = (2, 5)  # índices (inclusivos) das colunas de privacidade

_METRICAS = [("ping_ms", "Latência - Ping (ms)"), ("download_mbps", "Download (Mbps)"),
             ("upload_mbps", "Upload (Mbps)")]


# --------------------------------------------------------------------------- #
# Normalização de status
# --------------------------------------------------------------------------- #
def _norm(st) -> str:
    s = str(st or "ERRO").upper().strip()
    for prefixo in ("IPV4_", "IPV6_", "ATIVO_"):
        s = s.replace(prefixo, "")
    return {"EXPOSTO": "VAZADO"}.get(s, s)


def _cat(st) -> str:
    n = _norm(st)
    if n in _OK:
        return "ok"
    if n in _FALHA:
        return "falha"
    if n in _NA:
        return "na"
    return "incon"


def _rot(st, abrev=False) -> str:
    n = _norm(st)
    tabela = _ABREV if abrev else _ROTULO
    return tabela.get(n, n[:5] if abrev else n)


def _valor(rel, teste, sub: Optional[str] = None):
    dados = rel.get("resultados", {}).get(teste, {})
    if sub:
        return dados.get(sub) or dados.get("status", "ERRO")
    return dados.get("status", "ERRO")


def _nome_vpn(rel) -> str:
    return rel.get("rotulo") or rel.get("processo_vpn_alvo") or "?"


def _quando(rel) -> str:
    return str(rel.get("timestamp", ""))[:16].replace("T", " ")


def _legenda_status():
    return [Patch(color=_COR["ok"], label="Aprovado / Isolado"), Patch(color=_COR["falha"], label="Falha / Vazamento"),
            Patch(color=_COR["incon"], label="Inconclusivo / Erro"), Patch(color=_COR["na"], label="Não aplicável")]


# --------------------------------------------------------------------------- #
# Gráfico individual de segurança
# --------------------------------------------------------------------------- #
def gerar_grafico_seguranca(caminho_json: str, rel: dict) -> Optional[str]:
    testes = [(T_UDP, "Isolamento de\nPayload UDP"), (T_HTTP, "Isolamento HTTP"),
              (T_PRIV, "Privacidade\n(IP/DNS/IPv6)"), (T_ROTAS, "Isolamento de Rotas\n(Multi-Protocolo)"),
              (T_KILL, "Kill-Switch")]
    n = len(testes)
    fig, ax = plt.subplots(figsize=(11, 1.15 * n + 2.4))
    fig.patch.set_facecolor(_BG)

    for i, (chave, rotulo) in enumerate(testes):
        y = n - 1 - i
        dados = rel.get("resultados", {}).get(chave, {})
        if chave == T_PRIV and "ipv4_status" in dados and dados.get("status") != "NAO_APLICAVEL":
            subs = [("IPv4", dados.get("ipv4_status")), ("IPv6", dados.get("ipv6_status")),
                    ("DNS", dados.get("dns_status")), ("DoH/DoT", dados.get("doh_dot_status"))]
            for j, (nome, st) in enumerate(subs):
                ax.barh(y, 0.245, left=j * 0.25 + 0.0025, height=0.62, color=_COR[_cat(st)], edgecolor="white")
                ax.text(j * 0.25 + 0.125, y, f"{nome}\n{_rot(st)}", ha="center", va="center",
                        color="white", fontsize=9, fontweight="bold")
        else:
            st = dados.get("status", "ERRO")
            ax.barh(y, 1, height=0.62, color=_COR[_cat(st)], edgecolor="white")
            ax.text(0.5, y, _rot(st), ha="center", va="center", color="white", fontsize=12, fontweight="bold")
            if chave == T_KILL and "syns_pos_queda" in dados:
                ax.text(0.5, y - 0.27,
                        f"{dados.get('tentativas_pos_queda', 0)} tentativas | {dados.get('syns_pos_queda', 0)} SYN e "
                        f"{dados.get('udp_pos_queda', 0)} UDP na física",
                        ha="center", va="center", color="white", fontsize=8)

    ax.set_xlim(0, 1)
    ax.set_ylim(-0.6, n - 0.4)
    ax.set_yticks(range(n))
    ax.set_yticklabels([r for _, r in reversed(testes)], fontsize=10)
    ax.set_xticks([])
    ax.set_title("Resultado por Teste de Segurança", fontsize=13, fontweight="bold", pad=12)
    sub = f"Veredicto: {rel.get('veredicto_final', '?')}  |  {_quando(rel)}"
    if rel.get("tunel_estabelecido") is False:
        sub += "  |  TÚNEL NÃO ESTABELECIDO"
    fig.suptitle(f"Auditoria de Segurança VPN - {_nome_vpn(rel)}\n{sub}", fontsize=12, fontweight="bold")
    fig.legend(handles=_legenda_status(), loc="lower center", ncol=4, frameon=False, fontsize=9)
    fig.tight_layout(rect=(0, 0.06, 1, 0.93))
    saida = os.path.splitext(caminho_json)[0] + "_seguranca.png"
    fig.savefig(saida, dpi=160, bbox_inches="tight", facecolor=_BG)
    plt.close(fig)
    print(f"[+] Gráfico de segurança salvo em: {saida}")
    return saida


# --------------------------------------------------------------------------- #
# QoS
# --------------------------------------------------------------------------- #
def _qos(rel):
    """(baseline, vpn) como dicts; None quando a medição não está concluída."""
    base = rel.get("baseline_velocidade") or {}
    vpn = rel.get("resultados", {}).get(T_QOS) or {}
    def completo(d):
        return d.get("status") == "CONCLUIDO" and all(d.get(k) is not None for k, _ in _METRICAS)

    return (base if completo(base) else None), (vpn if completo(vpn) else None)


def _delta(chave, base, vpn) -> str:
    if not base or vpn is None:
        return ""
    return f"×{vpn / base:.1f}" if chave == "ping_ms" else f"{(vpn - base) / base * 100:+.0f}%"


def _erro_dispersao(valor, amostras):
    if amostras and len(amostras) > 1 and valor is not None:
        return [[max(valor - min(amostras), 0)], [max(max(amostras) - valor, 0)]]
    return None


def gerar_grafico_qos(caminho_json: str, rel: dict) -> Optional[str]:
    base, vpn = _qos(rel)
    if base is None:
        print("[-] QoS: baseline indisponível ou incompleto; gráfico individual não gerado.")
        return None
    fig, eixos = plt.subplots(1, 3, figsize=(13, 4.6))
    fig.patch.set_facecolor(_BG)
    for ax, (chave, titulo) in zip(eixos, _METRICAS):
        vb = base.get(chave)
        vv = vpn.get(chave) if vpn else None
        valores = [vb, vv if vv is not None else 0]
        err_b = _erro_dispersao(vb, (base.get("amostras") or {}).get(chave))
        err_v = _erro_dispersao(vv, ((vpn or {}).get("amostras") or {}).get(chave))
        barras = ax.bar([0, 1], valores, color=[_BASE, _VPN], width=0.6, edgecolor="white")
        for x, err, val in ((0, err_b, vb), (1, err_v, vv)):
            if err and val is not None:
                ax.errorbar(x, val, yerr=err, color="black", capsize=4, lw=1)
        ax.set_xticks([0, 1])
        ax.set_xticklabels(["Baseline\n(sem VPN)", "Com VPN"])
        ax.set_title(titulo, fontweight="bold")
        ax.grid(axis="y", ls="--", alpha=0.4)
        ax.set_axisbelow(True)
        topo = max([v for v in valores if v] or [1])
        ax.set_ylim(0, topo * 1.25)
        ax.text(0, (vb or 0) + topo * 0.02, f"{vb}", ha="center", va="bottom", fontweight="bold", fontsize=9)
        if vv is not None:
            ax.text(1, vv + topo * 0.02, f"{vv}\n{_delta(chave, vb, vv)}", ha="center", va="bottom",
                    fontweight="bold", fontsize=9)
        else:
            ax.text(1, topo * 0.05, "medição\nindisponível", ha="center", va="bottom", fontsize=9)
        del barras
    fig.suptitle(f"Impacto de Desempenho (QoS) - {_nome_vpn(rel)} | {_quando(rel)}", fontweight="bold")
    amostras = (vpn or {}).get("repeticoes")
    if amostras:
        fig.text(0.5, 0.01, f"Mediana de {amostras} medições; barras de erro = mín-máx.", ha="center", fontsize=8)
    fig.tight_layout(rect=(0, 0.04, 1, 0.94))
    saida = os.path.splitext(caminho_json)[0] + "_qos.png"
    fig.savefig(saida, dpi=160, bbox_inches="tight", facecolor=_BG)
    plt.close(fig)
    print(f"[+] Gráfico de QoS salvo em: {saida}")
    return saida


def gerar_graficos_individuais(caminho_json: str, rel: dict):
    gerar_grafico_seguranca(caminho_json, rel)
    gerar_grafico_qos(caminho_json, rel)


# --------------------------------------------------------------------------- #
# Comparativos multi-VPN
# --------------------------------------------------------------------------- #
def _carregar_relatorios(pasta: str):
    relatorios = []
    for caminho in sorted(glob.glob(os.path.join(pasta, "auditoria_vpn_*.json"))):
        try:
            with open(caminho, "r", encoding="utf-8") as arq:
                rel = json.load(arq)
            rel["_arquivo"] = os.path.basename(caminho)
            relatorios.append(rel)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[!] Ignorando '{caminho}': {exc}")
    relatorios.sort(key=lambda r: str(r.get("timestamp", "")))
    return relatorios


def gerar_comparativo_seguranca(pasta: str) -> Optional[str]:
    relatorios = _carregar_relatorios(pasta)
    if not relatorios:
        return None
    ordem = {"ok": 0, "falha": 1, "incon": 2, "na": 3}
    matriz = np.array([[ordem[_cat(_valor(r, t, s))] for _, t, s in _COLUNAS] for r in relatorios])
    nl, nc = matriz.shape

    fig, ax = plt.subplots(figsize=(max(10, nc * 1.35 + 3), max(3.6, nl * 0.95 + 2.6)))
    fig.patch.set_facecolor(_BG)
    ax.imshow(matriz, cmap=ListedColormap([_COR["ok"], _COR["falha"], _COR["incon"], _COR["na"]]),
              vmin=0, vmax=3, aspect="auto")
    for i, r in enumerate(relatorios):
        for j, (_, t, s) in enumerate(_COLUNAS):
            ax.text(j, i, _rot(_valor(r, t, s), abrev=True), ha="center", va="center",
                    color="white", fontsize=9, fontweight="bold")
    ax.set_xticks(range(nc))
    ax.set_xticklabels([c[0] for c in _COLUNAS], fontsize=9)
    ax.set_yticks(range(nl))
    ax.set_yticklabels([f"{_nome_vpn(r)}\n{_quando(r)}" for r in relatorios], fontsize=9)
    ax.set_xticks(np.arange(-0.5, nc, 1), minor=True)
    ax.set_yticks(np.arange(-0.5, nl, 1), minor=True)
    ax.grid(which="minor", color="white", lw=2)
    ax.tick_params(which="both", length=0)

    j0, j1 = _COLS_PRIV
    ax.add_patch(plt.Rectangle((j0 - 0.5, -0.5), j1 - j0 + 1, nl, fill=False, lw=3, edgecolor="black", zorder=10))
    tf = ax.get_xaxis_transform()
    ax.text((j0 + j1) / 2, 1.03, "Privacidade (IPv4 · IPv6 · DNS · DoH/DoT)", transform=tf, ha="center",
            va="bottom", fontsize=10, fontweight="bold")
    fig.suptitle("Comparativo de Segurança Multi-VPN - Resultado por Teste e Sub-métrica "
                 "(QoS é apresentado à parte)", fontsize=12, fontweight="bold")
    fig.legend(handles=_legenda_status(), loc="lower center", ncol=4, frameon=False, fontsize=9)
    fig.subplots_adjust(left=0.2, right=0.98, top=0.82, bottom=0.2)
    saida = os.path.join(pasta, "comparativo_seguranca_multi_vpn.png")
    fig.savefig(saida, dpi=160, bbox_inches="tight", facecolor=_BG)
    plt.close(fig)
    print(f"[+] Comparativo de segurança salvo em: {saida}")
    return saida


def gerar_comparativo_qos(pasta: str) -> Optional[str]:
    validos = [(r, *_qos(r)) for r in _carregar_relatorios(pasta)]
    validos = [(r, b, v) for r, b, v in validos if b and v]
    if not validos:
        print("[-] Comparativo de QoS: nenhuma auditoria com baseline e medição com VPN concluídas.")
        return None
    nomes = [f"{_nome_vpn(r)}\n{_quando(r)}" for r, _, _ in validos]
    x = np.arange(len(validos))
    fig, eixos = plt.subplots(1, 3, figsize=(max(13, len(validos) * 2.6), 5.4))
    fig.patch.set_facecolor(_BG)
    for ax, (chave, titulo) in zip(eixos, _METRICAS):
        bs = [b.get(chave) for _, b, _ in validos]
        vs = [v.get(chave) for _, _, v in validos]
        ax.bar(x - 0.18, bs, 0.36, color=_BASE, edgecolor="white")
        ax.bar(x + 0.18, vs, 0.36, color=_VPN, edgecolor="white")
        topo = max([a for a in bs + vs if a] or [1])
        for i, (b, v) in enumerate(zip(bs, vs)):
            ax.text(i - 0.18, (b or 0) + topo * 0.01, f"{b:g}", ha="center", va="bottom", fontsize=8)
            ax.text(i + 0.18, (v or 0) + topo * 0.01, f"{v:g}\n{_delta(chave, b, v)}", ha="center",
                    va="bottom", fontsize=8, fontweight="bold")
        ax.set_ylim(0, topo * 1.3)
        ax.set_xticks(x)
        ax.set_xticklabels(nomes, rotation=20, ha="right", fontsize=8)
        ax.set_title(titulo, fontweight="bold")
        ax.grid(axis="y", ls="--", alpha=0.4)
        ax.set_axisbelow(True)
    fig.suptitle("Comparativo de Desempenho (QoS) - Baseline vs. Com VPN  (ping: fator; banda: variação %)",
                 fontweight="bold")
    fig.legend(handles=[Patch(color=_BASE, label="Baseline (sem VPN)"), Patch(color=_VPN, label="Com VPN")],
               loc="lower center", ncol=2, frameon=False)
    fig.tight_layout(rect=(0, 0.06, 1, 0.94))
    saida = os.path.join(pasta, "comparativo_qos_multi_vpn.png")
    fig.savefig(saida, dpi=160, bbox_inches="tight", facecolor=_BG)
    plt.close(fig)
    print(f"[+] Comparativo de QoS salvo em: {saida}")
    return saida


# --------------------------------------------------------------------------- #
# Tabela-resumo (CSV, separador ';' e vírgula decimal: abre direto no Excel PT-BR)
# --------------------------------------------------------------------------- #
def _fmt(v) -> str:
    if v is None or v == "":
        return ""
    return f"{v:.2f}".replace(".", ",") if isinstance(v, float) else str(v)


def gerar_tabela_resumo(pasta: str) -> Optional[str]:
    relatorios = _carregar_relatorios(pasta)
    if not relatorios:
        return None
    cab = ["vpn", "data_hora", "veredicto", "tunel_estabelecido", "payload_udp", "http", "ipv4", "ipv6", "dns",
           "doh_dot", "rotas", "kill_switch", "ping_base_ms", "ping_vpn_ms", "ping_fator", "down_base_mbps",
           "down_vpn_mbps", "down_variacao_pct", "up_base_mbps", "up_vpn_mbps", "up_variacao_pct", "arquivo"]
    saida = os.path.join(pasta, "resumo_multi_vpn.csv")
    with open(saida, "w", newline="", encoding="utf-8-sig") as arq:
        w = csv.writer(arq, delimiter=";")
        w.writerow(cab)
        for r in relatorios:
            base, vpn = _qos(r)
            linha = [_nome_vpn(r), _quando(r), r.get("veredicto_final", ""), r.get("tunel_estabelecido", "")]
            linha += [_rot(_valor(r, t, s)) for _, t, s in _COLUNAS]
            for chave in ("ping_ms", "download_mbps", "upload_mbps"):
                b = base.get(chave) if base else None
                v = vpn.get(chave) if vpn else None
                if chave == "ping_ms":
                    comp = round(v / b, 2) if (b and v is not None) else None
                else:
                    comp = round((v - b) / b * 100, 1) if (b and v is not None) else None
                linha += [_fmt(b), _fmt(v), _fmt(comp)]
            linha.append(r.get("_arquivo", ""))
            w.writerow(linha)
    print(f"[+] Tabela-resumo salva em: {saida}")
    return saida
