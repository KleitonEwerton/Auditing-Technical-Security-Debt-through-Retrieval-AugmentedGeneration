"""
Script para análise completa dos resultados após melhoria STRIDE.
Gera métricas detalhadas: CWE Detection + STRIDE Classification.
"""
import argparse
import json
from collections import defaultdict

ARQUIVO_RESULTADOS_PADRAO = "resultados_rag.json"
ARQUIVO_SAIDA_PADRAO = "analise_resultados_melhorados.json"

# Mapeamento CWE → STRIDE (baseado em análise acadêmica)
# Usado para validar classificações STRIDE
CWE_TO_STRIDE_CORRETO = {
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

def extrair_stride_esperado_do_cwe(cwe_id):
    """Extrai STRIDE esperado baseado no CWE (usando mapeamento correto)"""
    stride_list = CWE_TO_STRIDE_CORRETO.get(cwe_id, [])
    return stride_list if stride_list else ['Unknown']

def extrair_stride_do_llm(resultado_llm):
    """Extrai STRIDE da resposta do LLM (com tratamento de erros)"""
    if isinstance(resultado_llm, dict):
        # Tratar caso de erro com raw_response
        if 'error' in resultado_llm and 'raw_response' in resultado_llm:
            try:
                resposta_texto = resultado_llm['raw_response'].strip()
                
                # Remover markdown
                if resposta_texto.startswith("```json"):
                    resposta_texto = resposta_texto.split("```json")[1].split("```")[0]
                elif resposta_texto.startswith("```"):
                    resposta_texto = resposta_texto.split("```")[1]
                    if resposta_texto.startswith("json"):
                        resposta_texto = resposta_texto[4:]
                    resposta_texto = resposta_texto.split("```")[0]
                
                resultado_llm = json.loads(resposta_texto.strip())
            except:
                return 'Unknown'
        
        return resultado_llm.get('stride', 'Unknown')
    return 'Unknown'

def calcular_metricas_por_cwe(resultados):
    """Calcula métricas detalhadas para cada CWE + distribuição STRIDE"""
    metricas_cwe = {}
    distribuicao_stride = defaultdict(int)  # Contagem simples de cada STRIDE
    distribuicao_stride_por_cwe = defaultdict(lambda: defaultdict(int))  # CWE → STRIDE → count
    
    total_testes = 0
    total_erros = 0
    total_com_stride = 0
    
    for item in resultados:
        resultado_llm = item.get('resultado_llm', {})
        
        # Verificar se há erro
        if 'erro' in item or 'error' in resultado_llm:
            total_erros += 1
            continue
        
        total_testes += 1
        
        # Extrair ground truth
        try:
            ground_truth = json.loads(item.get('ground_truth', '{}'))
            cwe_esperado = ground_truth.get('weakness', {}).get('id', '')
        except:
            continue
        
        # Extrair predição LLM
        cwe_predito = resultado_llm.get('cwe_id', 'None')
        
        # Inicializar métricas por CWE se não existir
        if cwe_esperado not in metricas_cwe:
            metricas_cwe[cwe_esperado] = {
                'acertos_cwe': 0, 'total': 0
            }
        
        metricas_cwe[cwe_esperado]['total'] += 1
        
        # === ANÁLISE 1: CWE DETECTION ===
        cwe_correto = (cwe_esperado == cwe_predito)
        if cwe_correto:
            metricas_cwe[cwe_esperado]['acertos_cwe'] += 1
        
        # === ANÁLISE 2: STRIDE DISTRIBUTION (não há "acerto/erro" porque CWE tem múltiplos STRIDE válidos) ===
        stride_predito = extrair_stride_do_llm(resultado_llm)
        
        if stride_predito and stride_predito != 'Unknown' and stride_predito != 'None':
            distribuicao_stride[stride_predito] += 1
            distribuicao_stride_por_cwe[cwe_esperado][stride_predito] += 1
            total_com_stride += 1
    
    return metricas_cwe, distribuicao_stride, distribuicao_stride_por_cwe, total_testes, total_erros, total_com_stride

def gerar_relatorio(resultados, arquivo_saida=ARQUIVO_SAIDA_PADRAO):
    """Gera relatório com 2 análises: CWE Detection + STRIDE Distribution"""
    print("=" * 80)
    print("📊 ANÁLISE COMPLETA - CWE DETECTION + STRIDE DISTRIBUTION")
    print("=" * 80)
    
    metricas_cwe, dist_stride, dist_stride_por_cwe, total_testes, total_erros, total_com_stride = calcular_metricas_por_cwe(resultados)
    
    relatorio = {
        "resumo_geral": {
            "total_testes": len(resultados),
            "testes_validos": total_testes,
            "erros": total_erros
        },
        "analises": {}
    }
    
    # ========================================
    # ANÁLISE 1: CWE ISOLADO
    # ========================================
    print("\n" + "=" * 80)
    print("📋 ANÁLISE 1: RECONHECIMENTO DE CWE (Isolado)")
    print("=" * 80)
    print("Métrica: Capacidade de identificar o tipo correto de vulnerabilidade")
    print("(Ignora se o veredito VULNERABLE/SAFE está correto)\n")
    
    analise_cwe = {}
    acertos_cwe_total = 0
    
    for cwe, metricas in sorted(metricas_cwe.items()):
        total_cwe = metricas['total']
        acertos_cwe = metricas['acertos_cwe']
        acertos_cwe_total += acertos_cwe
        
        acuracia = (acertos_cwe / total_cwe * 100) if total_cwe > 0 else 0
        
        analise_cwe[cwe] = {
            "acertos": acertos_cwe,
            "total": total_cwe,
            "acuracia": round(acuracia, 2)
        }
        
        print(f"{cwe:<10} {acertos_cwe:>3}/{total_cwe:<3} = {acuracia:>6.2f}%")
    
    acuracia_cwe_geral = (acertos_cwe_total / total_testes * 100) if total_testes > 0 else 0
    print(f"\n{'GERAL':<10} {acertos_cwe_total:>3}/{total_testes:<3} = {acuracia_cwe_geral:>6.2f}%")
    
    relatorio["analises"]["1_cwe_isolado"] = {
        "descricao": "Reconhecimento do tipo de CWE",
        "metricas_por_cwe": analise_cwe,
        "acuracia_geral": round(acuracia_cwe_geral, 2),
        "total_acertos": acertos_cwe_total,
        "total_testes": total_testes
    }
    
    # ========================================
    # ANÁLISE 2: STRIDE DISTRIBUTION
    # ========================================
    print("\n" + "=" * 80)
    print("🛡️  ANÁLISE 2: DISTRIBUIÇÃO STRIDE")
    print("=" * 80)
    print("Métrica: Cobertura e distribuição das categorias STRIDE")
    print("NOTA: Não há 'acerto/erro' pois cada CWE pode ter múltiplos STRIDE válidos\n")
    
    cobertura_stride = (total_com_stride / total_testes * 100) if total_testes > 0 else 0
    print(f"Cobertura: {total_com_stride}/{total_testes} = {cobertura_stride:.2f}%")
    print(f"(Percentual de casos que receberam classificação STRIDE)\n")
    
    print("--- Distribuição por Categoria STRIDE ---")
    stride_ordenado = sorted(dist_stride.items(), key=lambda x: x[1], reverse=True)
    
    for categoria, quantidade in stride_ordenado:
        percentual = (quantidade / total_com_stride * 100) if total_com_stride > 0 else 0
        print(f"  {categoria:<30} {quantidade:>3} ({percentual:>5.2f}%)")
    
    print("\n--- Distribuição STRIDE por CWE ---")
    print("(Mostra quais STRIDE o LLM escolheu para cada tipo de CWE)\n")
    for cwe in sorted(dist_stride_por_cwe.keys()):
        print(f"{cwe}:")
        for stride_cat, count in sorted(dist_stride_por_cwe[cwe].items(), key=lambda x: x[1], reverse=True):
            print(f"  {stride_cat:<30} {count:>3}")
    
    relatorio["analises"]["2_stride_distribution"] = {
        "descricao": "Distribuição de classificações STRIDE",
        "cobertura_percentual": round(cobertura_stride, 2),
        "total_classificados": total_com_stride,
        "total_testes": total_testes,
        "distribuicao_geral": {k: v for k, v in stride_ordenado},
        "distribuicao_por_cwe": {k: dict(v) for k, v in dist_stride_por_cwe.items()}
    }
    
    # Salvar relatório
    with open(arquivo_saida, 'w', encoding='utf-8') as f:
        json.dump(relatorio, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 80)
    print(f"✅ ANÁLISE CONCLUÍDA!")
    print("=" * 80)
    print(f"\n📁 Relatório salvo em: {arquivo_saida}")
    
    return relatorio

def main():
    parser = argparse.ArgumentParser(description="Analisa resultados LLM/RAG e gera métricas de CWE/STRIDE.")
    parser.add_argument("--input", default=ARQUIVO_RESULTADOS_PADRAO, help="Arquivo JSON de resultados de entrada")
    parser.add_argument("--output", default=ARQUIVO_SAIDA_PADRAO, help="Arquivo JSON de saída do relatório")
    args = parser.parse_args()

    # Carregar resultados
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            resultados = json.load(f)
        print(f"✓ Arquivo carregado: {len(resultados)} testes\n")
    except FileNotFoundError:
        print(f"❌ Arquivo {args.input} não encontrado")
        return
    
    # Gerar relatório
    gerar_relatorio(resultados, arquivo_saida=args.output)

if __name__ == "__main__":
    main()
