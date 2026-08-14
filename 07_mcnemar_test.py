#!/usr/bin/env python3
"""07_mcnemar_test.py

Calcula o Teste de McNemar entre duas saídas de resultados (LLM vs RAG).

Uso:
  py 07_mcnemar_test.py --llm resultados_llm.json --rag resultados_rag.json --output mcnemar_report.json

O script alinha itens por `id_original` (ou `teste_idx`), compara as predições
de `resultado_llm.cwe_id` em cada arquivo contra o `ground_truth` e constrói
a tabela de contingência (both_correct, llm_only_correct, rag_only_correct, both_wrong).

Retorna p-valor exato (binomial two-sided) e aproximação qui-quadrado com
correção de continuidade (df=1).
"""
import argparse
import json
import math
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple


SCRIPT_REPROCESSAMENTO = "05_reprocessar_resultados.py"


def load_results(path: Path) -> Dict[str, dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    mapping = {}
    for item in data:
        key = item.get("id_original")
        if key is None:
            key = str(item.get("teste_idx"))
        mapping[key] = item
    return mapping


def extrair_casos_invalidos(resultados: List[dict]) -> List[dict]:
    invalidos = []
    for item in resultados:
        resultado_llm = item.get("resultado_llm", {})
        if item.get("erro") or item.get("erro_reprocessamento"):
            invalidos.append(item)
            continue
        if isinstance(resultado_llm, dict) and (
            resultado_llm.get("error") == "Resposta não é JSON válido" or "raw_response" in resultado_llm
        ):
            invalidos.append(item)
    return invalidos


def nome_reprocessado(caminho_arquivo: Path) -> Path:
    return caminho_arquivo.with_name(f"{caminho_arquivo.stem}_reprocessado{caminho_arquivo.suffix}")


def preparar_arquivo_resultado(caminho_arquivo: Path, auto_reprocessar: bool) -> Path:
    if not caminho_arquivo.exists():
        return None

    dados = json.loads(caminho_arquivo.read_text(encoding="utf-8"))
    invalidos = extrair_casos_invalidos(dados)
    if not invalidos:
        return caminho_arquivo

    print(f"⚠️ Foram encontrados {len(invalidos)} casos inválidos em {caminho_arquivo}.")
    saida_reprocessada = nome_reprocessado(caminho_arquivo)

    if not auto_reprocessar:
        print("❌ Teste de McNemar interrompido para evitar distorção estatística.")
        print("👉 Reprocesse antes de rodar o teste:")
        print(
            f"python {SCRIPT_REPROCESSAMENTO} --input {caminho_arquivo} --output {saida_reprocessada}"
        )
        print("Ou execute novamente com --auto-reprocess para automatizar esse passo.")
        return None

    print(f"🔄 Reprocessando automaticamente: {caminho_arquivo}")
    subprocess.run(
        [
            sys.executable,
            SCRIPT_REPROCESSAMENTO,
            "--input",
            str(caminho_arquivo),
            "--output",
            str(saida_reprocessada),
        ],
        check=True,
    )

    dados_reprocessados = json.loads(saida_reprocessada.read_text(encoding="utf-8"))
    invalidos_restantes = extrair_casos_invalidos(dados_reprocessados)
    if invalidos_restantes:
        print(
            f"❌ Ainda restaram {len(invalidos_restantes)} casos inválidos após reprocessamento em {saida_reprocessada}."
        )
        return None

    print(f"✅ Reprocessamento concluído. Teste seguirá com: {saida_reprocessada}")
    return saida_reprocessada


def extract_ground_truth_cwe(item: dict) -> str:
    gt = item.get("ground_truth")
    if gt is None:
        return None
    if isinstance(gt, str):
        try:
            gt_j = json.loads(gt)
        except Exception:
            return None
    else:
        gt_j = gt
    w = gt_j.get("weakness") if isinstance(gt_j, dict) else None
    if isinstance(w, dict):
        return w.get("id")
    return None


def pred_cwe_from_item(item: dict) -> str:
    # Many result files put the prediction under 'resultado_llm'. We accept missing/None.
    r = item.get("resultado_llm") or item.get("resultado") or {}
    if not isinstance(r, dict):
        return None
    return r.get("cwe_id")


def mcnemar_counts(llm_map: Dict[str, dict], rag_map: Dict[str, dict]) -> Tuple[int,int,int,int,int]:
    both_correct = 0
    llm_only = 0
    rag_only = 0
    both_wrong = 0
    total = 0
    for key, llm_item in llm_map.items():
        if key not in rag_map:
            continue
        rag_item = rag_map[key]
        gt = extract_ground_truth_cwe(llm_item) or extract_ground_truth_cwe(rag_item)
        if gt is None:
            continue
        llm_pred = pred_cwe_from_item(llm_item)
        rag_pred = pred_cwe_from_item(rag_item)
        llm_ok = (llm_pred == gt)
        rag_ok = (rag_pred == gt)
        total += 1
        if llm_ok and rag_ok:
            both_correct += 1
        elif llm_ok and not rag_ok:
            llm_only += 1
        elif rag_ok and not llm_ok:
            rag_only += 1
        else:
            both_wrong += 1
    return total, both_correct, llm_only, rag_only, both_wrong


def exact_mcnemar_p(b: int, c: int) -> float:
    # two-sided exact binomial test (McNemar)
    n = b + c
    if n == 0:
        return float('nan')
    x = min(b, c)
    # cumulative probability of observing <= x successes under Binomial(n, 0.5)
    cumulative = 0.0
    for k in range(0, x + 1):
        cumulative += math.comb(n, k) * (0.5 ** n)
    p_two_sided = min(1.0, 2.0 * cumulative)
    return p_two_sided


def approx_chi2_p(b: int, c: int) -> Tuple[float, float]:
    # continuity-corrected chi-square statistic and p-value for df=1
    n = b + c
    if n == 0:
        return float('nan'), float('nan')
    chi2 = ((abs(b - c) - 1) ** 2) / n
    # For df=1, CDF(x) = erf(sqrt(x/2)), so sf = 1 - erf(sqrt(x/2))
    p = 1.0 - math.erf(math.sqrt(chi2 / 2.0))
    return chi2, p


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--llm", default="resultados_llm.json", help="arquivo de resultados LLM")
    parser.add_argument("--rag", default="resultados_rag.json", help="arquivo de resultados RAG")
    parser.add_argument("--output", default="mcnemar_report.json", help="arquivo de saída JSON")
    parser.add_argument(
        "--auto-reprocess",
        action="store_true",
        help="Se houver erros em LLM/RAG, executa automaticamente o 05_reprocessar_resultados.py",
    )
    args = parser.parse_args()

    llm_path = Path(args.llm)
    rag_path = Path(args.rag)
    if not llm_path.exists() or not rag_path.exists():
        print(f"Arquivo não encontrado: {llm_path} ou {rag_path}")
        return

    try:
        llm_path = preparar_arquivo_resultado(llm_path, args.auto_reprocess)
        rag_path = preparar_arquivo_resultado(rag_path, args.auto_reprocess)
    except subprocess.CalledProcessError as e:
        print(f"Falha no reprocessamento automático: {e}")
        return

    if llm_path is None or rag_path is None:
        return

    llm_map = load_results(llm_path)
    rag_map = load_results(rag_path)

    total, both_correct, llm_only, rag_only, both_wrong = mcnemar_counts(llm_map, rag_map)
    b = llm_only
    c = rag_only
    exact_p = exact_mcnemar_p(b, c)
    chi2_stat, chi2_p = approx_chi2_p(b, c)

    report = {
        "total_alinhados": total,
        "both_correct": both_correct,
        "llm_only_correct": llm_only,
        "rag_only_correct": rag_only,
        "both_wrong": both_wrong,
        "discordant_b": b,
        "discordant_c": c,
        "exact_two_sided_p": exact_p,
        "chi2_continuity_corrected_stat": chi2_stat,
        "chi2_p_value": chi2_p,
    }

    Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
