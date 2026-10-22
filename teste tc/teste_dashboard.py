"""
Script de validação: gera dashboards PNG a partir de todos os JSONs de
auditoria já existentes na pasta do projeto, SEM executar testes de rede.

Uso (no ambiente virtual ativado):
    python teste_dashboard.py
"""
import sys
import json
import glob
import os

# Garante que os módulos do projeto são encontrados
sys.path.insert(0, os.path.dirname(__file__))

from utils import graficos

def carregar_json(caminho):
    with open(caminho, encoding='utf-8') as f:
        return json.load(f)

def main():
    jsons = glob.glob("auditoria_vpn_*.json")
    if not jsons:
        print("[!] Nenhum JSON de auditoria encontrado na pasta atual.")
        print("    Execute o teste completo com --salvar-relatorio primeiro.")
        sys.exit(1)

    print(f"[*] {len(jsons)} relatório(s) encontrado(s). Gerando dashboards...")
    for caminho in jsons:
        print(f"\n  -> {caminho}")
        relatorio = carregar_json(caminho)

        # Injetar dados fictícios de QoS caso o JSON seja antigo (sem baseline_velocidade)
        if 'baseline_velocidade' not in relatorio:
            print("     [!] JSON antigo: sem campo 'baseline_velocidade'. "
                  "Injetando dados de exemplo para demonstração.")
            relatorio['baseline_velocidade'] = {
                'status': 'CONCLUIDO',
                'ping_ms': 25.5,
                'download_mbps': 100.0,
                'upload_mbps': 40.0,
            }
            # Simula resultado do Teste 6 com impacto típico de VPN
            relatorio.setdefault('resultados', {})
            relatorio['resultados']['Impacto de Desempenho (QoS)'] = {
                'status': 'CONCLUIDO',
                'ping_ms': 42.3,
                'download_mbps': 68.5,
                'upload_mbps': 27.1,
            }

        resultado = graficos.gerar_dashboard(caminho, relatorio)
        if resultado:
            print(f"     [+] OK: {resultado}")
        else:
            print(f"     [-] FALHA ao gerar o dashboard.")

if __name__ == '__main__':
    main()

