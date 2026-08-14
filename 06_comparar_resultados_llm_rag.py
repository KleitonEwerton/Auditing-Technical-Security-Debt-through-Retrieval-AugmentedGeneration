"""
Comparação direta entre resultados LLM-only e RAG.
Gera um relatório consolidado com métricas lado a lado e deltas.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from collections import Counter
from typing import Dict, List


ARQUIVO_LLM_PADRAO = "resultados_llm.json"
ARQUIVO_RAG_PADRAO = "resultados_rag.json"
ARQUIVO_SAIDA_PADRAO = "comparacao_llm_vs_rag.json"
SCRIPT_REPROCESSAMENTO = "05_reprocessar_resultados.py"

CWE_TO_STRIDE = {
    "CWE-22": ["Information Disclosure"],
    "CWE-78": ["Elevation of Privilege", "Tampering"],
    "CWE-79": ["Tampering", "Elevation of Privilege", "Information Disclosure"],
    "CWE-89": ["Tampering", "Information Disclosure"],
    "CWE-90": ["Information Disclosure", "Elevation of Privilege"],
    "CWE-327": ["Information Disclosure", "Spoofing"],
    "CWE-328": ["Information Disclosure", "Spoofing"],
    "CWE-330": ["Spoofing", "Information Disclosure"],
    "CWE-501": ["Elevation of Privilege", "Spoofing"],
    "CWE-614": ["Information Disclosure"],
    "CWE-643": ["Information Disclosure", "Elevation of Privilege"],
}


def carregar_resultados(arquivo: str) -> List[Dict]:
    try:
        with open(arquivo, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ Arquivo {arquivo} não encontrado")
        return []


def extrair_casos_invalidos(resultados: List[Dict]) -> List[Dict]:
    invalidos = []
    for item in resultados:
        resultado_llm = item.get('resultado_llm', {})
        if item.get('erro') or item.get('erro_reprocessamento'):
            invalidos.append(item)
            continue
        if isinstance(resultado_llm, dict) and (
            resultado_llm.get('error') == 'Resposta não é JSON válido' or 'raw_response' in resultado_llm
        ):
            invalidos.append(item)
    return invalidos


def nome_reprocessado(caminho_arquivo: str) -> str:
    p = Path(caminho_arquivo)
    return str(p.with_name(f"{p.stem}_reprocessado{p.suffix}"))


def preparar_resultados(caminho_arquivo: str, auto_reprocessar: bool):
    resultados = carregar_resultados(caminho_arquivo)
    if not resultados:
        return None, None

    invalidos = extrair_casos_invalidos(resultados)
    if not invalidos:
        return resultados, caminho_arquivo

    print(f"⚠️ Foram encontrados {len(invalidos)} casos inválidos em {caminho_arquivo}.")

    if not auto_reprocessar:
        arquivo_saida = nome_reprocessado(caminho_arquivo)
        print("❌ Comparação interrompida para evitar métricas distorcidas.")
        print("👉 Reprocesse antes de comparar:")
        print(
            f"python {SCRIPT_REPROCESSAMENTO} --input {caminho_arquivo} --output {arquivo_saida}"
        )
        print("Ou execute novamente com --auto-reprocess para automatizar esse passo.")
        return None, None

    arquivo_saida = nome_reprocessado(caminho_arquivo)
    print(f"🔄 Reprocessando automaticamente: {caminho_arquivo}")
    subprocess.run(
        [
            sys.executable,
            SCRIPT_REPROCESSAMENTO,
            "--input",
            caminho_arquivo,
            "--output",
            arquivo_saida,
        ],
        check=True,
    )

    resultados_reprocessados = carregar_resultados(arquivo_saida)
    invalidos_restantes = extrair_casos_invalidos(resultados_reprocessados)
    if invalidos_restantes:
        print(
            f"❌ Ainda restaram {len(invalidos_restantes)} casos inválidos após reprocessamento em {arquivo_saida}."
        )
        return None, None

    print(f"✅ Reprocessamento concluído. Comparação seguirá com: {arquivo_saida}")
    return resultados_reprocessados, arquivo_saida


def normalizar_resposta_llm(resultado_llm):
    if not isinstance(resultado_llm, dict):
        return None

    if 'error' in resultado_llm and 'raw_response' in resultado_llm:
        raw_response = resultado_llm['raw_response'].strip()
        try:
            if raw_response.startswith("```json"):
                raw_response = raw_response.split("```json", 1)[1].split("```", 1)[0]
            elif raw_response.startswith("```"):
                raw_response = raw_response.split("```", 1)[1]
                if raw_response.startswith("json"):
                    raw_response = raw_response[4:]
                raw_response = raw_response.split("```", 1)[0]
            return json.loads(raw_response.strip())
        except Exception:
            return None

    return resultado_llm


def extrair_metricas(resultados: List[Dict]) -> Dict:
    total = len(resultados)
    validos = 0
    invalidos = 0
    cwe_acertos = 0
    cwe_total = 0
    stride_total = 0
    stride_aceitos = 0
    distribuicao_stride = Counter()
    distribuicao_cwe = Counter()

    for item in resultados:
        resultado_llm = item.get('resultado_llm', {})
        resultado_llm = normalizar_resposta_llm(resultado_llm)
        if not resultado_llm or item.get('erro'):
            invalidos += 1
            continue

        try:
            ground_truth = json.loads(item.get('ground_truth', '{}'))
            cwe_esperado = ground_truth.get('weakness', {}).get('id', '')
        except Exception:
            invalidos += 1
            continue

        cwe_predito = resultado_llm.get('cwe_id', 'None')
        stride_predito = resultado_llm.get('stride', 'Unknown')

        validos += 1
        cwe_total += 1
        distribuicao_cwe[cwe_predito] += 1

        if cwe_predito == cwe_esperado:
            cwe_acertos += 1

        if stride_predito and stride_predito not in {'Unknown', 'None'}:
            stride_total += 1
            stride_aceitos += 1
            distribuicao_stride[stride_predito] += 1

    cwe_accuracy = (cwe_acertos / cwe_total * 100) if cwe_total else 0.0
    stride_coverage = (stride_aceitos / validos * 100) if validos else 0.0

    return {
        'total': total,
        'validos': validos,
        'invalidos': invalidos,
        'cwe': {
            'acertos': cwe_acertos,
            'total': cwe_total,
            'acuracia_percentual': round(cwe_accuracy, 2),
        },
        'stride': {
            'classificados': stride_aceitos,
            'total_validos': validos,
            'cobertura_percentual': round(stride_coverage, 2),
            'distribuicao': dict(distribuicao_stride),
        },
        'distribuicao_cwe_predita': dict(distribuicao_cwe),
    }


def montar_comparacao(metricas_llm: Dict, metricas_rag: Dict) -> Dict:
    def delta(a, b):
        return round(a - b, 2)

    return {
        'cwe_accuracy_delta': delta(metricas_rag['cwe']['acuracia_percentual'], metricas_llm['cwe']['acuracia_percentual']),
        'stride_coverage_delta': delta(metricas_rag['stride']['cobertura_percentual'], metricas_llm['stride']['cobertura_percentual']),
        'validos_delta': metricas_rag['validos'] - metricas_llm['validos'],
        'invalidos_delta': metricas_rag['invalidos'] - metricas_llm['invalidos'],
        'melhor_em_cwe': 'RAG' if metricas_rag['cwe']['acuracia_percentual'] > metricas_llm['cwe']['acuracia_percentual'] else 'LLM' if metricas_rag['cwe']['acuracia_percentual'] < metricas_llm['cwe']['acuracia_percentual'] else 'Empate',
        'melhor_em_stride': 'RAG' if metricas_rag['stride']['cobertura_percentual'] > metricas_llm['stride']['cobertura_percentual'] else 'LLM' if metricas_rag['stride']['cobertura_percentual'] < metricas_llm['stride']['cobertura_percentual'] else 'Empate',
    }


def main():
    parser = argparse.ArgumentParser(description="Compara resultados LLM-only e RAG.")
    parser.add_argument("--llm", default=ARQUIVO_LLM_PADRAO, help="Arquivo JSON do baseline LLM-only")
    parser.add_argument("--rag", default=ARQUIVO_RAG_PADRAO, help="Arquivo JSON do resultado RAG")
    parser.add_argument("--output", default=ARQUIVO_SAIDA_PADRAO, help="Arquivo JSON de saída")
    parser.add_argument(
        "--auto-reprocess",
        action="store_true",
        help="Se houver erros em LLM/RAG, executa automaticamente o 05_reprocessar_resultados.py",
    )
    args = parser.parse_args()

    try:
        resultados_llm, llm_origem = preparar_resultados(args.llm, args.auto_reprocess)
        resultados_rag, rag_origem = preparar_resultados(args.rag, args.auto_reprocess)
    except subprocess.CalledProcessError as e:
        print(f"❌ Falha ao executar reprocessamento automático: {e}")
        return

    if resultados_llm is None or resultados_rag is None:
        return

    metricas_llm = extrair_metricas(resultados_llm)
    metricas_rag = extrair_metricas(resultados_rag)
    comparacao = montar_comparacao(metricas_llm, metricas_rag)

    relatorio = {
        'arquivos': {
            'llm': llm_origem,
            'rag': rag_origem,
        },
        'llm': metricas_llm,
        'rag': metricas_rag,
        'comparacao': comparacao,
        'stride_ground_truth_map': CWE_TO_STRIDE,
    }

    print("=" * 80)
    print("📊 COMPARAÇÃO LLM vs RAG")
    print("=" * 80)
    print(f"LLM  - CWE Accuracy: {metricas_llm['cwe']['acuracia_percentual']:.2f}% | STRIDE Coverage: {metricas_llm['stride']['cobertura_percentual']:.2f}%")
    print(f"RAG  - CWE Accuracy: {metricas_rag['cwe']['acuracia_percentual']:.2f}% | STRIDE Coverage: {metricas_rag['stride']['cobertura_percentual']:.2f}%")
    print(f"DELTA - CWE Accuracy: {comparacao['cwe_accuracy_delta']:+.2f} pp | STRIDE Coverage: {comparacao['stride_coverage_delta']:+.2f} pp")
    print(f"Melhor em CWE: {comparacao['melhor_em_cwe']}")
    print(f"Melhor em STRIDE: {comparacao['melhor_em_stride']}")

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(relatorio, f, indent=2, ensure_ascii=False)

    print(f"\n📁 Relatório salvo em: {args.output}")


if __name__ == "__main__":
    main()
