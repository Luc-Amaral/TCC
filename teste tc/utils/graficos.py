import os
import matplotlib
matplotlib.use('Agg')  # Backend sem GUI — seguro para execução em console/servidor
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np


# ---------------------------------------------------------------------------
# Paleta de cores consistente em todo o dashboard
# ---------------------------------------------------------------------------
_COR_BASELINE = '#2c3e50'   # Azul-escuro: leitura sem VPN
_COR_VPN      = '#e74c3c'   # Vermelho:    leitura com VPN
_COR_OK       = '#27ae60'   # Verde:       testes aprovados
_COR_FALHA    = '#c0392b'   # Vermelho-escuro: falhas de segurança
_COR_INCON    = '#f39c12'   # Laranja:     inconclusivo/erro


def _anotar_barras(ax, barras):
    """Coloca o valor numérico no topo de cada barra."""
    for barra in barras:
        altura = barra.get_height()
        if altura > 0:
            ax.text(
                barra.get_x() + barra.get_width() / 2.0,
                altura,
                f'{altura:g}',
                va='bottom', ha='center', fontsize=8, fontweight='bold'
            )


def _extrair_qos(relatorio_dict):
    """
    Extrai métricas de QoS do baseline (sem VPN) e do resultado do Teste 6
    (com VPN).  Retorna (labels, val_base, val_vpn) — zeros quando ausente.
    """
    labels = ['Ping (ms)', 'Download (Mbps)', 'Upload (Mbps)']

    baseline = relatorio_dict.get('baseline_velocidade') or {}
    vpn_perf = (relatorio_dict.get('resultados') or {}).get('Impacto de Desempenho (QoS)') or {}

    val_base = [
        baseline.get('ping_ms', 0) or 0,
        baseline.get('download_mbps', 0) or 0,
        baseline.get('upload_mbps', 0) or 0,
    ]
    val_vpn = [
        vpn_perf.get('ping_ms', 0) or 0,
        vpn_perf.get('download_mbps', 0) or 0,
        vpn_perf.get('upload_mbps', 0) or 0,
    ]
    return labels, val_base, val_vpn


def _extrair_contagem_seguranca(relatorio_dict):
    """
    Varre os resultados dos testes L3/L4 (exclui o de desempenho) e agrupa
    por categoria de resultado.
    """
    contagem = {'ISOLADO/BLOQUEADO': 0, 'FALHA': 0, 'INCONCLUSIVO/ERRO': 0}
    resultados = relatorio_dict.get('resultados') or {}
    for nome, dados in resultados.items():
        if 'Desempenho' in nome or not isinstance(dados, dict):
            continue
        st = dados.get('status', 'ERRO')
        if st in ('ISOLADO', 'BLOQUEADO', 'SUCESSO'):
            contagem['ISOLADO/BLOQUEADO'] += 1
        elif st == 'FALHA':
            contagem['FALHA'] += 1
        else:
            contagem['INCONCLUSIVO/ERRO'] += 1
    return contagem


# ---------------------------------------------------------------------------
# Painel 1 — Barras agrupadas: Baseline vs. Com VPN
# ---------------------------------------------------------------------------
def _plotar_barras_qos(ax, labels, val_base, val_vpn):
    x = np.arange(len(labels))
    largura = 0.32

    barras_b = ax.bar(x - largura / 2, val_base, largura,
                      label='Baseline (Sem VPN)', color=_COR_BASELINE,
                      edgecolor='white', linewidth=0.5)
    barras_v = ax.bar(x + largura / 2, val_vpn, largura,
                      label='Com VPN', color=_COR_VPN,
                      edgecolor='white', linewidth=0.5)

    _anotar_barras(ax, barras_b)
    _anotar_barras(ax, barras_v)

    ax.set_title('Impacto na Velocidade e Latência (QoS)', fontweight='bold', pad=10)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel('Valor medido')
    ax.legend(loc='upper right', fontsize=8)
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    ax.set_axisbelow(True)

    # Aviso visual se não houver dados
    if all(v == 0 for v in val_base + val_vpn):
        ax.text(0.5, 0.5, 'Dados de QoS indisponíveis',
                transform=ax.transAxes, ha='center', va='center',
                fontsize=11, color='gray', style='italic')


# ---------------------------------------------------------------------------
# Painel 2 — Barras horizontais: status individual por teste
# ---------------------------------------------------------------------------

# Mapeamento de status → (cor, rótulo legível)
_STATUS_MAP = {
    'ISOLADO':      (_COR_OK,    'ISOLADO'),
    'BLOQUEADO':    (_COR_OK,    'BLOQUEADO'),
    'SUCESSO':      (_COR_OK,    'SUCESSO'),
    'CONCLUIDO':    (_COR_OK,    'CONCLUÍDO'),
    'FALHA':        (_COR_FALHA, 'FALHA'),
    'INCONCLUSIVO': (_COR_INCON, 'INCONCLUSIVO'),
    'ERRO':         (_COR_INCON, 'ERRO'),
}

# Nomes curtos para exibição no eixo Y
_NOMES_CURTOS = {
    'Isolamento de Payload UDP':             'Payload UDP',
    'Isolamento HTTP':                       'HTTP',
    'Privacidade (IP/DNS/IPv6)':             'Privacidade',
    'Isolamento de Rotas (Multi-Protocolo)': 'Rotas',
    'Impacto de Desempenho (QoS)':           'QoS',
    'Kill-Switch (Isolamento Cronológico)':  'Kill-Switch',
}


def _plotar_status_testes(ax, relatorio_dict):
    """
    Gráfico de barras horizontais mostrando o resultado de cada teste
    individualmente: verde = aprovado, vermelho = falha, laranja = inconclusivo.
    """
    resultados = relatorio_dict.get('resultados') or {}

    if not resultados:
        ax.text(0.5, 0.5, 'Sem resultados de testes disponíveis',
                transform=ax.transAxes, ha='center', va='center',
                fontsize=10, color='gray', style='italic')
        ax.axis('off')
        return

    nomes   = list(resultados.keys())
    labels  = [_NOMES_CURTOS.get(n, n) for n in nomes]
    cores   = []
    rotulos = []

    for nome in nomes:
        st = (resultados[nome] or {}).get('status', 'ERRO')
        cor, rotulo = _STATUS_MAP.get(st, (_COR_INCON, st))
        cores.append(cor)
        rotulos.append(rotulo)

    y = np.arange(len(labels))
    barras = ax.barh(y, [1] * len(labels), color=cores,
                     edgecolor='white', linewidth=0.8, height=0.55)

    # Rótulo do status centralizado dentro de cada barra
    for barra, rotulo in zip(barras, rotulos):
        ax.text(
            0.5, barra.get_y() + barra.get_height() / 2,
            rotulo, va='center', ha='center',
            fontsize=9, fontweight='bold', color='white',
        )

    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlim(0, 1)
    ax.set_xticks([])
    ax.set_title('Resultado por Teste de Segurança', fontweight='bold', pad=10)
    ax.invert_yaxis()  # Teste 1 no topo

    # Legenda de cores
    legenda = [
        mpatches.Patch(color=_COR_OK,    label='Aprovado'),
        mpatches.Patch(color=_COR_FALHA, label='Falha'),
        mpatches.Patch(color=_COR_INCON, label='Inconclusivo / Erro'),
    ]
    ax.legend(handles=legenda, fontsize=7, loc='lower right')


# ---------------------------------------------------------------------------
# Painel 3 — Heatmap comparativo entre todas as VPNs já auditadas
# ---------------------------------------------------------------------------

# Valor numérico para colorir a célula: 0=aprovado, 1=falha, 2=inconclusivo
_STATUS_VALOR = {
    'ISOLADO':      0, 'BLOQUEADO': 0, 'SUCESSO':   0, 'CONCLUIDO': 0,
    'FALHA':        1,
    'INCONCLUSIVO': 2, 'ERRO':      2,
}
# Texto curto exibido dentro de cada célula do heatmap
_STATUS_ABREV = {
    'ISOLADO': 'ISOL', 'BLOQUEADO': 'BLOQ', 'SUCESSO': 'OK',
    'CONCLUIDO': 'OK', 'FALHA': 'FALHA', 'INCONCLUSIVO': 'INCON', 'ERRO': 'ERRO',
}
_CMAP_HEATMAP = matplotlib.colors.ListedColormap([_COR_OK, _COR_FALHA, _COR_INCON])

# Colunas fixas (ordem de exibição no heatmap)
_COLUNAS_HEATMAP = [
    ('Isolamento de Payload UDP',             'Payload\nUDP'),
    ('Isolamento HTTP',                        'HTTP'),
    ('Privacidade (IP/DNS/IPv6)',              'Privaci-\ndade'),
    ('Isolamento de Rotas (Multi-Protocolo)', 'Rotas'),
    ('Impacto de Desempenho (QoS)',           'QoS'),
    ('Kill-Switch (Isolamento Cronológico)',  'Kill-\nSwitch'),
]


def _carregar_todos_relatorios(pasta: str) -> list[dict]:
    """Lê todos os JSONs de auditoria na pasta, ordenados por timestamp."""
    import glob, json
    padrao = os.path.join(pasta, 'auditoria_vpn_*.json')
    relatorios = []
    for caminho in sorted(glob.glob(padrao)):
        try:
            with open(caminho, encoding='utf-8') as f:
                relatorios.append(json.load(f))
        except Exception:
            pass
    return relatorios


def _plotar_heatmap_comparativo(ax, pasta: str):
    """
    Heatmap com todas as VPNs auditadas (linhas) × testes (colunas).
    Cada célula é colorida por resultado e anotada com o status abreviado.
    """
    relatorios = _carregar_todos_relatorios(pasta)

    if not relatorios:
        ax.text(0.5, 0.5, 'Nenhuma auditoria\nencontrada na pasta',
                transform=ax.transAxes, ha='center', va='center',
                fontsize=10, color='gray', style='italic')
        ax.axis('off')
        return

    colunas_chave  = [c[0] for c in _COLUNAS_HEATMAP]
    colunas_labels = [c[1] for c in _COLUNAS_HEATMAP]

    # Monta rótulo de linha: "NomeVPN\nDD/MM/AAAA"
    linhas_labels = []
    matriz_val    = []
    matriz_txt    = []

    for rel in relatorios:
        vpn  = rel.get('processo_vpn_alvo', '?')
        ts   = rel.get('timestamp', '')
        data = ts[:10] if ts else ''
        linhas_labels.append(f"{vpn}\n{data}")

        resultados = rel.get('resultados') or {}
        fila_val, fila_txt = [], []
        for chave in colunas_chave:
            dados = resultados.get(chave) or {}
            st    = dados.get('status', 'ERRO')
            fila_val.append(_STATUS_VALOR.get(st, 2))
            fila_txt.append(_STATUS_ABREV.get(st, st[:4]))
        matriz_val.append(fila_val)
        matriz_txt.append(fila_txt)

    dados_np = np.array(matriz_val, dtype=float)

    im = ax.imshow(dados_np, cmap=_CMAP_HEATMAP, vmin=0, vmax=2, aspect='auto')

    # Anotações de texto em cada célula
    for i in range(len(linhas_labels)):
        for j in range(len(colunas_labels)):
            ax.text(j, i, matriz_txt[i][j],
                    ha='center', va='center',
                    fontsize=7, fontweight='bold', color='white')

    ax.set_xticks(range(len(colunas_labels)))
    ax.set_xticklabels(colunas_labels, fontsize=7, ha='center')
    ax.set_yticks(range(len(linhas_labels)))
    ax.set_yticklabels(linhas_labels, fontsize=7)
    ax.set_title('Comparativo\nMulti-VPN', fontweight='bold', pad=10)

    # Legenda compacta
    legenda = [
        mpatches.Patch(color=_COR_OK,    label='Aprovado'),
        mpatches.Patch(color=_COR_FALHA, label='Falha'),
        mpatches.Patch(color=_COR_INCON, label='Inconclusivo'),
    ]
    ax.legend(handles=legenda, fontsize=6, loc='upper right',
              bbox_to_anchor=(1, -0.15), ncol=3)


# ---------------------------------------------------------------------------
# Função pública principal
# ---------------------------------------------------------------------------
def gerar_dashboard(caminho_json: str, relatorio_dict: dict) -> str | None:
    """
    Gera e salva o dashboard analítico em PNG ao lado do JSON de auditoria.

    Parâmetros
    ----------
    caminho_json   : caminho completo do relatório JSON (usado para nomear o PNG)
    relatorio_dict : dicionário já carregado com os dados da auditoria

    Retorna o caminho do PNG gerado ou None em caso de falha.
    """
    try:
        print("\n[*] Gerando Dashboard Analítico (Matplotlib)...")

        labels, val_base, val_vpn = _extrair_qos(relatorio_dict)
        # Pasta onde estão todos os JSONs de auditoria
        pasta = os.path.dirname(os.path.abspath(caminho_json))

        # Layout: 1 linha × 3 colunas; heatmap ocupa mais espaço por ter mais dados
        fig, axes = plt.subplots(
            1, 3,
            figsize=(20, 6),
            gridspec_kw={'width_ratios': [2, 2, 1.8]},
        )
        fig.patch.set_facecolor('#f8f9fa')

        vpn_nome    = relatorio_dict.get('processo_vpn_alvo', 'VPN')
        veredicto   = relatorio_dict.get('veredicto_final', 'DESCONHECIDO')
        timestamp   = relatorio_dict.get('timestamp', '')
        titulo = (
            f"Auditoria VPN — Processo: {vpn_nome}  |  "
            f"Veredicto: {veredicto}  |  {timestamp}"
        )
        fig.suptitle(titulo, fontsize=12, fontweight='bold', y=1.01)

        _plotar_barras_qos(axes[0], labels, val_base, val_vpn)
        _plotar_status_testes(axes[1], relatorio_dict)
        _plotar_heatmap_comparativo(axes[2], pasta)

        plt.tight_layout()

        nome_png = caminho_json.replace('.json', '_dashboard.png')
        plt.savefig(nome_png, dpi=150, bbox_inches='tight',
                    facecolor=fig.get_facecolor())
        plt.close(fig)  # libera memória

        print(f"    [+] Dashboard salvo: {nome_png}")
        return nome_png

    except Exception as exc:
        print(f"    [-] Falha ao gerar Dashboard Analítico: {exc}")
        return None


# ---------------------------------------------------------------------------
# Figura comparativa de QoS — um painel por métrica, todas as VPNs
# ---------------------------------------------------------------------------

def gerar_comparativo_qos(pasta: str) -> str | None:
    """
    Gera uma figura com 3 subplots (Ping, Download, Upload), cada um
    contendo barras agrupadas Baseline vs. Com VPN para CADA VPN auditada.

    Salva como  comparativo_qos_multi_vpn.png  dentro de `pasta`.
    Retorna o caminho do PNG ou None em caso de falha.
    """
    try:
        relatorios = _carregar_todos_relatorios(pasta)

        # Filtra apenas os que têm dados de QoS completos (baseline E resultado)
        validos = []
        for rel in relatorios:
            bl  = rel.get('baseline_velocidade') or {}
            qos = (rel.get('resultados') or {}).get('Impacto de Desempenho (QoS)') or {}
            if bl.get('status') == 'CONCLUIDO' and qos.get('status') == 'CONCLUIDO':
                validos.append(rel)

        if not validos:
            print("    [!] Comparativo QoS: nenhuma auditoria com dados de velocidade encontrada.")
            return None

        print(f"\n[*] Gerando Comparativo QoS Multi-VPN ({len(validos)} VPN(s))...")

        # --- Coleta de dados ---
        vpn_labels = []
        ping_base, ping_vpn = [], []
        down_base, down_vpn = [], []
        up_base,   up_vpn   = [], []

        for rel in validos:
            vpn_labels.append(rel.get('processo_vpn_alvo', '?'))
            bl  = rel['baseline_velocidade']
            qos = rel['resultados']['Impacto de Desempenho (QoS)']
            ping_base.append(bl.get('ping_ms',       0) or 0)
            ping_vpn.append( qos.get('ping_ms',      0) or 0)
            down_base.append(bl.get('download_mbps', 0) or 0)
            down_vpn.append( qos.get('download_mbps',0) or 0)
            up_base.append(  bl.get('upload_mbps',   0) or 0)
            up_vpn.append(   qos.get('upload_mbps',  0) or 0)

        # --- Layout: 1 linha × 3 colunas (uma por métrica) ---
        largura_fig = max(10, 3 * len(validos) + 6)
        fig, axes = plt.subplots(1, 3, figsize=(largura_fig, 6))
        fig.patch.set_facecolor('#f8f9fa')
        fig.suptitle(
            'Comparativo de Desempenho (QoS) — Baseline vs. Com VPN',
            fontsize=14, fontweight='bold', y=1.02
        )

        metricas = [
            ('Latência — Ping (ms)',         ping_base, ping_vpn, 'ms'),
            ('Velocidade — Download (Mbps)', down_base, down_vpn, 'Mbps'),
            ('Velocidade — Upload (Mbps)',   up_base,   up_vpn,   'Mbps'),
        ]

        x      = np.arange(len(vpn_labels))
        largura = 0.35

        for ax, (titulo, val_b, val_v, unidade) in zip(axes, metricas):
            bars_b = ax.bar(x - largura / 2, val_b, largura,
                            label='Baseline (Sem VPN)', color=_COR_BASELINE,
                            edgecolor='white', linewidth=0.5)
            bars_v = ax.bar(x + largura / 2, val_v, largura,
                            label='Com VPN', color=_COR_VPN,
                            edgecolor='white', linewidth=0.5)

            _anotar_barras(ax, bars_b)
            _anotar_barras(ax, bars_v)

            ax.set_title(titulo, fontweight='bold', pad=10)
            ax.set_xticks(x)
            ax.set_xticklabels(vpn_labels, rotation=20, ha='right', fontsize=8)
            ax.set_ylabel(unidade)
            ax.legend(fontsize=8)
            ax.grid(axis='y', linestyle='--', alpha=0.4)
            ax.set_axisbelow(True)

        plt.tight_layout()
        nome_png = os.path.join(pasta, 'comparativo_qos_multi_vpn.png')
        plt.savefig(nome_png, dpi=150, bbox_inches='tight',
                    facecolor=fig.get_facecolor())
        plt.close(fig)

        print(f"    [+] Comparativo QoS salvo: {nome_png}")
        return nome_png

    except Exception as exc:
        print(f"    [-] Falha ao gerar Comparativo QoS: {exc}")
        return None