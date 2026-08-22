"""
08_analise_similaridade_treino_teste.py - Análise de deduplicação e similaridade entre
as partições de treinamento e teste do OWASP Benchmark.

Motivação: Como o OWASP Benchmark é gerado a partir de templates e os documentos
indexados no ChromaDB incluem os respectivos rótulos em texto, esta análise verifica
se o ganho observado na configuração RAG pode ter sido influenciado por exemplos
quase idênticos distribuídos entre treino e teste.

Metodologia:
  - Usa TF-IDF sobre os campos 'input' (código Java) para calcular similaridade coseno
  - NÃO requer GPU, modelos de embeddings externos ou API
  - Reporta: similaridade máxima por exemplo de teste, distribuição por faixas,
    e exemplos com alta similaridade (>= limiar configurável)

Uso:
    python 08_analise_similaridade_treino_teste.py
    python 08_analise_similaridade_treino_teste.py --threshold 0.95 --top 20
    python 08_analise_similaridade_treino_teste.py --output similaridade_report.json
"""
import argparse
import json
import os
from collections import Counter

ARQUIVO_COMPLETO = "dataset_completo_mestrado.jsonl"
ARQUIVO_TESTE = "dataset_teste_reservado.jsonl"
ARQUIVO_SAIDA_PADRAO = "analise_similaridade_treino_teste.json"
LIMIAR_PADRAO = 0.95


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analisa similaridade TF-IDF entre partições de treino e teste."
    )
    parser.add_argument(
        "--completo", default=ARQUIVO_COMPLETO,
        help="Arquivo JSONL com o dataset completo (usado para identificar exemplos de treino)"
    )
    parser.add_argument(
        "--teste", default=ARQUIVO_TESTE,
        help="Arquivo JSONL com os exemplos de teste"
    )
    parser.add_argument(
        "--output", default=ARQUIVO_SAIDA_PADRAO,
        help="Arquivo JSON de saída com o relatório de similaridade"
    )
    parser.add_argument(
        "--threshold", type=float, default=LIMIAR_PADRAO,
        help=f"Limiar de similaridade coseno para reportar pares de alta similaridade (padrão: {LIMIAR_PADRAO})"
    )
    parser.add_argument(
        "--top", type=int, default=10,
        help="Número de pares com maior similaridade a detalhar no relatório (padrão: 10)"
    )
    return parser.parse_args()


def carregar_jsonl(caminho: str) -> list:
    registros = []
    with open(caminho, "r", encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if linha:
                try:
                    registros.append(json.loads(linha))
                except json.JSONDecodeError:
                    continue
    return registros


def _chave_registro(r: dict) -> str:
    """Gera uma chave única e determinística para um registro.

    Usa o campo 'id' quando presente. Se ausente (como no dataset deste
    projeto, que possui apenas 'instruction', 'input' e 'output'), a chave
    é construída concatenando os primeiros 200 caracteres de 'input' e
    'output' — reprodução da mesma separação determinística usada em
    00_gerar_dataset_final.py.
    """
    if "id" in r and r["id"]:
        return str(r["id"])
    return (r.get("input", "")[:200] + "||" + r.get("output", "")[:200])


def extrair_chaves(registros: list) -> set:
    return {_chave_registro(r) for r in registros}


def main():
    args = parse_args()

    print("=" * 80)
    print("🔍 ANÁLISE DE SIMILARIDADE TREINO ↔ TESTE (TF-IDF + Coseno)")
    print("=" * 80)

    # Verificar arquivos
    for caminho in [args.completo, args.teste]:
        if not os.path.exists(caminho):
            print(f"❌ Arquivo não encontrado: {caminho}")
            return

    # Importar dependências (apenas biblioteca padrão + scikit-learn)
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
        import numpy as np
    except ImportError:
        print("❌ scikit-learn não encontrado. Instale com: pip install scikit-learn")
        return

    # Carregar dados
    print(f"\n📂 Carregando dataset completo: {args.completo}")
    todos = carregar_jsonl(args.completo)
    print(f"   → {len(todos)} registros carregados")

    print(f"📂 Carregando dataset de teste: {args.teste}")
    teste = carregar_jsonl(args.teste)
    print(f"   → {len(teste)} registros de teste carregados")

    # Detectar se os registros têm campo 'id' e avisar quando ausente
    amostra = todos[:1] + teste[:1] if todos or teste else []
    usa_id = any("id" in r and r["id"] for r in amostra)
    if not usa_id:
        print(
            "\n⚠️  Campo 'id' não encontrado nos registros."
        )
        print(
            "   Usando chave composta (input[:200] + output[:200]) para"
            " separar treino de teste — mesma lógica de 00_gerar_dataset_final.py."
        )

    # Identificar exemplos de treino (todos que não estão no conjunto de teste)
    chaves_teste = extrair_chaves(teste)
    treino = [r for r in todos if _chave_registro(r) not in chaves_teste]
    print(f"\n✂️  Partição de treino: {len(treino)} exemplos")
    print(f"✂️  Partição de teste:  {len(teste)} exemplos")

    if not treino or not teste:
        print("❌ Partições vazias. Verifique os arquivos de entrada.")
        return

    # Extrair textos de código (campo 'input')
    textos_treino = [r.get("input", "") for r in treino]
    textos_teste = [r.get("input", "") for r in teste]

    print("\n⚙️  Vetorizando com TF-IDF...")
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=50000,
        sublinear_tf=True,
    )
    # Ajustar no treino, transformar treino e teste
    todos_textos = textos_treino + textos_teste
    vectorizer.fit(todos_textos)
    X_treino = vectorizer.transform(textos_treino)
    X_teste = vectorizer.transform(textos_teste)

    print(f"   → Vocabulário TF-IDF: {len(vectorizer.vocabulary_)} tokens")
    print(f"   → Calculando similaridade coseno ({len(textos_teste)} × {len(textos_treino)})...")

    # Calcular similaridade em lotes para economizar memória
    LOTE = 50
    sim_max = np.zeros(len(textos_teste))
    sim_argmax = np.zeros(len(textos_teste), dtype=int)

    for i in range(0, len(textos_teste), LOTE):
        lote = X_teste[i:i + LOTE]
        sim_lote = cosine_similarity(lote, X_treino)
        sim_max[i:i + LOTE] = sim_lote.max(axis=1)
        sim_argmax[i:i + LOTE] = sim_lote.argmax(axis=1)
        if (i // LOTE) % 10 == 0:
            print(f"   → Processando lote {i // LOTE + 1}/{(len(textos_teste) + LOTE - 1) // LOTE}...", end="\r")

    print()

    # Estatísticas gerais
    limiar = args.threshold
    acima_limiar = int((sim_max >= limiar).sum())
    media = float(sim_max.mean())
    mediana = float(np.median(sim_max))
    p95 = float(np.percentile(sim_max, 95))
    p99 = float(np.percentile(sim_max, 99))

    # Distribuição por faixas
    faixas = {
        "0.00-0.50": int(((sim_max >= 0.00) & (sim_max < 0.50)).sum()),
        "0.50-0.70": int(((sim_max >= 0.50) & (sim_max < 0.70)).sum()),
        "0.70-0.85": int(((sim_max >= 0.70) & (sim_max < 0.85)).sum()),
        "0.85-0.95": int(((sim_max >= 0.85) & (sim_max < 0.95)).sum()),
        "0.95-1.00": int(((sim_max >= 0.95) & (sim_max <= 1.00)).sum()),
    }

    # Top pares de alta similaridade
    indices_ordenados = np.argsort(sim_max)[::-1][:args.top]
    top_pares = []
    for idx_teste in indices_ordenados:
        idx_treino = int(sim_argmax[idx_teste])
        top_pares.append({
            "similaridade": round(float(sim_max[idx_teste]), 4),
            "id_teste": teste[idx_teste].get("id", f"teste_{idx_teste}"),
            "id_treino_mais_similar": treino[idx_treino].get("id", f"treino_{idx_treino}"),
        })

    # Resultado
    print("\n" + "=" * 80)
    print("📊 RESULTADOS")
    print("=" * 80)
    print(f"Média de similaridade máxima por exemplo de teste : {media:.4f}")
    print(f"Mediana de similaridade máxima                   : {mediana:.4f}")
    print(f"Percentil 95 de similaridade máxima              : {p95:.4f}")
    print(f"Percentil 99 de similaridade máxima              : {p99:.4f}")
    print(f"Exemplos de teste com sim ≥ {limiar}              : {acima_limiar} / {len(textos_teste)}")
    print(f"\nDistribuição por faixa de similaridade máxima:")
    for faixa, count in faixas.items():
        barra = "█" * (count * 30 // len(textos_teste)) if len(textos_teste) > 0 else ""
        print(f"  [{faixa}]: {count:4d} ({count / len(textos_teste) * 100:.1f}%) {barra}")
    print(f"\nTop {args.top} pares com maior similaridade:")
    print(f"  {'Sim':<8} {'ID Teste':<30} {'ID Treino mais similar'}")
    print("  " + "-" * 75)
    for par in top_pares:
        print(f"  {par['similaridade']:<8.4f} {str(par['id_teste']):<30} {par['id_treino_mais_similar']}")

    relatorio = {
        "configuracao": {
            "arquivo_completo": args.completo,
            "arquivo_teste": args.teste,
            "limiar_alta_similaridade": limiar,
            "metodo": "TF-IDF (char_wb, ngrams 3-5) + Coseno",
        },
        "particoes": {
            "total_completo": len(todos),
            "total_treino": len(treino),
            "total_teste": len(teste),
        },
        "estatisticas": {
            "media_sim_max": round(media, 4),
            "mediana_sim_max": round(mediana, 4),
            "percentil_95": round(p95, 4),
            "percentil_99": round(p99, 4),
            "exemplos_acima_limiar": acima_limiar,
            "percentual_acima_limiar": round(acima_limiar / len(textos_teste) * 100, 2) if textos_teste else 0,
        },
        "distribuicao_faixas": faixas,
        f"top_{args.top}_pares_maior_similaridade": top_pares,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(relatorio, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Relatório salvo em: {args.output}")

    if acima_limiar == 0:
        print(f"\n✅ Nenhum exemplo de teste apresenta similaridade ≥ {limiar} com o treino.")
        print("   Isso indica que o ganho RAG não decorre de exemplos quase idênticos entre partições.")
    else:
        print(f"\n⚠️  {acima_limiar} exemplo(s) de teste com similaridade ≥ {limiar}.")
        print("   Revise os pares listados acima para avaliar possível sobreposição.")


if __name__ == "__main__":
    main()
