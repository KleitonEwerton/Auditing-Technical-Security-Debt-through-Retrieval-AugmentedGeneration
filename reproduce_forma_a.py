"""
reproduce_forma_a.py - Automação da Forma A de reprodução dos experimentos.

Executa automaticamente os scripts necessários para reproduzir as três
reivindicações principais do artigo a partir dos resultados já entregues,
sem necessidade de API externa, GPU ou modelos de embeddings.

Reivindicações reproduzidas:
  #1 - Acurácia RAG 90,88% vs LLM 70,44% (delta +20,44 pp)
  #2 - F1-score ponderado de 0,9142 (configuração RAG)
  #3 - Significância estatística via McNemar (p = 3,85 × 10⁻³⁴)

Uso:
    python reproduce_forma_a.py

Compatível com Windows, Linux e macOS (não usa shell scripts).
"""
import subprocess
import sys
import json
from pathlib import Path

# Valores esperados conforme o artigo
VALORES_ESPERADOS = {
    "cwe_accuracy_rag": 90.88,
    "cwe_accuracy_llm": 70.44,
    "delta_accuracy": 20.44,
    "f1_score_ponderado": 0.9142,
    "mcnemar_p": 3.851859888774472e-34,
    "total_alinhados": 548,
    "rag_only_correct": 112,
    "both_wrong": 50,
}

TOLERANCIA = 0.01  # tolerância para comparações de ponto flutuante


def executar_script(script: str, args: list = None) -> bool:
    """Executa um script Python e retorna True se bem-sucedido."""
    cmd = [sys.executable, script] + (args or [])
    print(f"\n{'='*80}")
    print(f"▶  Executando: {' '.join(cmd)}")
    print(f"{'='*80}")
    resultado = subprocess.run(cmd, capture_output=False)
    if resultado.returncode != 0:
        print(f"\n❌ ERRO: {script} encerrou com código {resultado.returncode}")
        return False
    return True


def verificar_arquivo(caminho: str) -> bool:
    """Verifica se um arquivo existe e não está vazio."""
    p = Path(caminho)
    if not p.exists():
        print(f"❌ Arquivo não encontrado: {caminho}")
        return False
    if p.stat().st_size == 0:
        print(f"❌ Arquivo vazio: {caminho}")
        return False
    return True


def comparar_valor(nome: str, obtido, esperado, tolerancia: float = TOLERANCIA) -> bool:
    """Compara um valor obtido com o esperado e reporta."""
    diferenca = abs(obtido - esperado)
    dentro = diferenca <= tolerancia
    status = "✅" if dentro else "⚠️ "
    print(f"  {status} {nome}: obtido={obtido} | esperado={esperado} | Δ={diferenca:.6f}")
    return dentro


def main():
    print("=" * 80)
    print("🔬 REPRODUÇÃO FORMA A - Reivindicações Experimentais do Artigo")
    print("=" * 80)
    print("Nota: Forma A opera sobre os resultados já entregues.")
    print("      Não requer API externa, GPU ou modelos de embeddings.\n")

    # Verificar arquivos necessários
    arquivos_necessarios = [
        "resultados_rag.json",
        "resultados_llm.json",
    ]
    for arquivo in arquivos_necessarios:
        if not verificar_arquivo(arquivo):
            print(f"\n❌ Arquivo ausente: {arquivo}. Abortando.")
            sys.exit(1)

    erros = []

    # =========================================================================
    # Reivindicação #1: Acurácia RAG vs LLM
    # =========================================================================
    print("\n" + "=" * 80)
    print("📊 REIVINDICAÇÃO #1 — Acurácia RAG 90,88% vs LLM 70,44% (+20,44 pp)")
    print("=" * 80)
    ok = executar_script("06_comparar_resultados_llm_rag.py")
    if not ok:
        erros.append("Script 06 falhou")
    elif verificar_arquivo("comparacao_llm_vs_rag.json"):
        with open("comparacao_llm_vs_rag.json", "r", encoding="utf-8") as f:
            comp = json.load(f)
        print("\n🔍 Verificando valores:")
        if not comparar_valor("CWE Accuracy RAG (%)", comp["rag"]["cwe"]["acuracia_percentual"], VALORES_ESPERADOS["cwe_accuracy_rag"]):
            erros.append("Acurácia RAG divergente")
        if not comparar_valor("CWE Accuracy LLM (%)", comp["llm"]["cwe"]["acuracia_percentual"], VALORES_ESPERADOS["cwe_accuracy_llm"]):
            erros.append("Acurácia LLM divergente")
        delta = comp["comparacao"]["cwe_accuracy_delta"]
        if not comparar_valor("Delta CWE Accuracy (pp)", delta, VALORES_ESPERADOS["delta_accuracy"]):
            erros.append("Delta acurácia divergente")

    # =========================================================================
    # Reivindicação #2: F1-score ponderado
    # =========================================================================
    print("\n" + "=" * 80)
    print("📊 REIVINDICAÇÃO #2 — F1-score ponderado de 0,9142 (configuração RAG)")
    print("=" * 80)
    ok = executar_script("04_analise_avancada.py", ["--input", "resultados_rag.json", "--output", "analise_rag_avancada.json"])
    if not ok:
        erros.append("Script 04 falhou")
    elif verificar_arquivo("analise_rag_avancada.json"):
        with open("analise_rag_avancada.json", "r", encoding="utf-8") as f:
            analise = json.load(f)
        f1 = analise.get("metricas_globais", {}).get("weighted_avg", {}).get("f1_score", 0)
        print("\n🔍 Verificando valores:")
        if not comparar_valor("F1-score ponderado RAG", f1, VALORES_ESPERADOS["f1_score_ponderado"]):
            erros.append("F1-score divergente")

    # =========================================================================
    # Reivindicação #3: Teste de McNemar
    # =========================================================================
    print("\n" + "=" * 80)
    print("📊 REIVINDICAÇÃO #3 — Teste de McNemar (p = 3,85 × 10⁻³⁴)")
    print("=" * 80)
    ok = executar_script("07_mcnemar_test.py", ["--llm", "resultados_llm.json", "--rag", "resultados_rag.json", "--output", "mcnemar_report.json"])
    if not ok:
        erros.append("Script 07 falhou")
    elif verificar_arquivo("mcnemar_report.json"):
        with open("mcnemar_report.json", "r", encoding="utf-8") as f:
            mcnemar = json.load(f)
        print("\n🔍 Verificando valores:")
        comparar_valor("Total alinhados", mcnemar.get("total_alinhados", 0), VALORES_ESPERADOS["total_alinhados"], tolerancia=0)
        comparar_valor("RAG-only correct", mcnemar.get("rag_only_correct", 0), VALORES_ESPERADOS["rag_only_correct"], tolerancia=0)
        comparar_valor("Both wrong", mcnemar.get("both_wrong", 0), VALORES_ESPERADOS["both_wrong"], tolerancia=0)
        p = mcnemar.get("exact_two_sided_p", 1.0)
        p_esperado = VALORES_ESPERADOS["mcnemar_p"]
        dentro = abs(p - p_esperado) / max(abs(p_esperado), 1e-100) < 0.01
        status = "✅" if dentro else "⚠️ "
        print(f"  {status} p-valor McNemar: obtido={p:.3e} | esperado={p_esperado:.3e}")
        if not dentro:
            erros.append("p-valor McNemar divergente")

    # =========================================================================
    # Sumário final
    # =========================================================================
    print("\n" + "=" * 80)
    print("📋 SUMÁRIO DA REPRODUÇÃO")
    print("=" * 80)
    if not erros:
        print("✅ TODAS AS REIVINDICAÇÕES REPRODUZIDAS COM SUCESSO!")
        print("\nArtefatos gerados:")
        print("  📁 comparacao_llm_vs_rag.json  → Reivindicação #1")
        print("  📁 analise_rag_avancada.json   → Reivindicação #2")
        print("  📁 mcnemar_report.json         → Reivindicação #3")
    else:
        print(f"⚠️  {len(erros)} divergência(s) detectada(s):")
        for e in erros:
            print(f"   • {e}")
        print("\nIsto pode indicar variação esperada por LLMs não-determinísticos (Forma B)")
        print("ou diferença na versão do arquivo de resultados.")
        sys.exit(1)


if __name__ == "__main__":
    main()
