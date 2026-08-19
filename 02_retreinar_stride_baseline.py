import os
import json
import time
import logging
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv

load_dotenv()


def ler_env_int(nome_var: str, valor_padrao: int) -> int:
    valor_bruto = os.getenv(nome_var)
    if valor_bruto is None or valor_bruto.strip() == "":
        return valor_padrao
    try:
        return int(valor_bruto)
    except ValueError:
        logging.warning(
            "Valor inválido para %s=%s. Usando padrão %s.",
            nome_var,
            valor_bruto,
            valor_padrao,
        )
        return valor_padrao

# --- CONFIGURAÇÕES ---
ARQUIVO_TESTE = "dataset_teste_reservado.jsonl"
ARQUIVO_RESULTADOS_NOVO = "resultados_llm.json"

# Modelo LLM: lido de GROQ_LLM_MODEL no .env para facilitar troca em caso de depreciação.
# O modelo utilizado nos experimentos originais foi llama-3.3-70b-versatile, depreciado
# pela Groq em 16/ago/2026. Substitutos recomendados: openai/gpt-oss-120b ou qwen/qwen3.6-27b.
# Ref: https://console.groq.com/docs/deprecations#august-16-2026-llama318binstant-and-llama3370bversatile
MODELO_LLM_ORIGINAL = "llama-3.3-70b-versatile"  # usado nos experimentos do artigo (depreciado)
MODELO_LLM = os.getenv("GROQ_LLM_MODEL", MODELO_LLM_ORIGINAL)
if MODELO_LLM == MODELO_LLM_ORIGINAL:
    logging.warning(
        "AVISO: O modelo '%s' foi depreciado pela Groq em 16/ago/2026. "
        "Defina GROQ_LLM_MODEL no .env com um substituto (ex.: openai/gpt-oss-120b).",
        MODELO_LLM_ORIGINAL,
    )

# Rate Limiting
PAUSA_ENTRE_REQUISICOES = ler_env_int("RATE_LIMIT_PAUSA_ENTRE_REQUISICOES", 1)  # segundos
REQUISICOES_POR_LOTE = ler_env_int("RATE_LIMIT_REQUISICOES_POR_LOTE", 5)
PAUSA_LOTE = ler_env_int("RATE_LIMIT_PAUSA_LOTE", 5)

logging.basicConfig(filename='retreino_stride_baseline_log.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Prompt para baseline LLM-only.
# NOTA IMPORTANTE: Este prompt difere do prompt RAG (02_retreinar_stride.py) não apenas pela
# ausência do contexto recuperado ({base_conhecimento}), mas também no CONTEÚDO DAS REGRAS.
# O prompt RAG contém regras adicionais de desambiguação:
#   - CWE-328 vs CWE-327: critérios explícitos para MD5/SHA1 vs DES/RC4
#   - CWE-501: gatilho específico para session.setAttribute com input do usuário
#   - CWE-614: regras detalhadas sobre cookies (setSecure, setHttpOnly)
#   - STRIDE Rule A: análise do verbo da operação (INSERT/SELECT/EXECUTE)
# Portanto, a comparação entre as configurações não isola apenas o efeito do retrieval,
# mas também o efeito do enriquecimento de regras no prompt — conforme declarado nas
# Seções 5.2 e 6 do artigo.
prompt_template_security = """
You are a Software Security Expert. Analyze the Java code for CWE patterns and STRIDE threats.

---
TARGET CODE:
{codigo_alvo}
---

===== 1. CWE PATTERN DEFINITIONS (Strict Syntax Matching) =====

PRIORITY RULES:

   - CWE-22: File access with input.
   - CWE-78: `Runtime.exec` or `ProcessBuilder`.
   - CWE-79: Outputting input to JSP/HTML.
   - CWE-89: SQL construction with concatenation (`+`).
   - CWE-90: LDAP filter construction.
   - CWE-328 (Weak Hash) vs CWE-327 (Broken Crypto)**:
   - CWE-330: security context.
   - CWE-501 (Trust Boundary Violation)**:
   - CWE-614 (Insecure Cookie)**:
   - CWE-643: XPath expression construction.

If NO pattern matches, return CWE: "None".

===== 2. STRIDE LOGIC RULES (Secondary Goal) =====
Once a CWE is found, determine the specific threat based on the OPERATION:

Rule: Map to STRIDE
- IF Write Context (e.g., SQL INSERT) -> **Tampering**
- IF Read Context (e.g., SQL SELECT) -> **Information Disclosure**
- IF Execute Context as Root/Admin -> **Elevation of Privilege**
- IF Authentication Context (Passwords/Hashes/Cookies) -> **Spoofing**

===== RESPONSE FORMAT =====
Respond strictly in JSON format:
{{
    "cwe_id": "CWE-XXX" | "None",
    "explanation": "1. Pattern: Detected [CWE Name] in variable 'x'. 2. Context: The code performs a [INSERT/SELECT/EXEC] operation. 3. Threat: Since it is a [Write/Read] operation, the STRIDE is [Category].",
    "stride": "Tampering" | "Spoofing" | "Repudiation" | "Information Disclosure" | "Denial of Service" | "Elevation of Privilege" | "None"
}}
"""


def retreinar_stride_baseline():
    print("=" * 80)
    print("🔄 BASELINE LLM-ONLY (SEM RAG)")
    print("=" * 80)
    print(
        f"⚙️  Rate limit ativo: pausa={PAUSA_ENTRE_REQUISICOES}s | "
        f"lote={REQUISICOES_POR_LOTE} req | pausa_lote={PAUSA_LOTE}s"
    )

    # 1. Carregar dados de teste
    if not os.path.exists(ARQUIVO_TESTE):
        print(f"❌ Erro: Arquivo {ARQUIVO_TESTE} não encontrado.")
        return

    dados_teste = []
    with open(ARQUIVO_TESTE, 'r', encoding='utf-8') as f:
        for linha in f:
            if linha.strip():
                try:
                    dados_teste.append(json.loads(linha))
                except json.JSONDecodeError:
                    logging.warning(f"Erro ao parsear linha: {linha[:100]}...")

    total_testes = len(dados_teste)
    print(f"\n📊 Total de testes: {total_testes}")

    # Suporte a --limit N: permite execução reduzida para validação do pipeline
    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--limit", type=int, default=None,
                        help="Limita o número de casos processados (ex.: --limit 20 para teste rápido)")
    cli_args, _ = parser.parse_known_args()
    if cli_args.limit is not None and cli_args.limit > 0:
        dados_teste = dados_teste[:cli_args.limit]
        total_testes = len(dados_teste)
        print(f"⚡ Modo reduzido: processando apenas os primeiros {total_testes} casos (--limit {cli_args.limit})")

    # 2. Verificar se há resultados anteriores para continuar
    resultados = []
    teste_inicial = 0
    if os.path.exists(ARQUIVO_RESULTADOS_NOVO):
        print(f"\n⚠️  Arquivo {ARQUIVO_RESULTADOS_NOVO} já existe.")
        resposta = input("Deseja continuar de onde parou? (s/n): ")
        if resposta.lower() == 's':
            with open(ARQUIVO_RESULTADOS_NOVO, 'r', encoding='utf-8') as f:
                resultados = json.load(f)
                if resultados:
                    teste_inicial = max(item['teste_idx'] for item in resultados) + 1
                print(f"✓ Continuando do teste {teste_inicial} (total de {len(resultados)} resultados salvos)")

    # 3. Inicializar LLM (sem RAG)
    print(f"\n🤖 Modelo LLM: {MODELO_LLM}")
    if MODELO_LLM == MODELO_LLM_ORIGINAL:
        print("⚠️  AVISO: este modelo foi depreciado pela Groq em 16/ago/2026.")
        print("   Defina GROQ_LLM_MODEL no .env (ex.: openai/gpt-oss-120b).")
    prompt = ChatPromptTemplate.from_template(prompt_template_security)
    llm = ChatGroq(temperature=0, model=MODELO_LLM)
    chain = prompt | llm

    # 4. Executar testes
    print(f"\n🚀 Iniciando testes ({teste_inicial} até {total_testes})...\n")
    print("💾 Salvamento automático após cada resposta\n")

    for idx in range(teste_inicial, total_testes):
        item = dados_teste[idx]
        codigo = item.get('input', '')
        ground_truth = item.get('output', '{}')

        print(f"🔍 Teste {idx+1}/{total_testes}... ", end='', flush=True)

        try:
            # Consultar LLM diretamente (sem base_conhecimento)
            resposta = chain.invoke({
                "codigo_alvo": codigo
            })

            # Tentar parsear resposta JSON
            resposta_texto = resposta.content.strip()

            # Remover markdown se presente
            if resposta_texto.startswith("```json"):
                resposta_texto = resposta_texto.split("```json")[1]
                resposta_texto = resposta_texto.split("```")[0]
            elif resposta_texto.startswith("```"):
                resposta_texto = resposta_texto.split("```")[1]
                if resposta_texto.startswith("json"):
                    resposta_texto = resposta_texto[4:]
                resposta_texto = resposta_texto.split("```")[0]

            resposta_texto = resposta_texto.strip()

            try:
                resultado_llm = json.loads(resposta_texto)
            except json.JSONDecodeError:
                resultado_llm = {
                    "error": "Resposta não é JSON válido",
                    "raw_response": resposta_texto
                }

            resultados.append({
                "teste_idx": idx,
                "id_original": item.get('id', f'teste_{idx}'),
                "codigo_input": codigo,
                "ground_truth": ground_truth,
                "resultado_llm": resultado_llm
            })

            # Salvar IMEDIATAMENTE após cada resposta
            with open(ARQUIVO_RESULTADOS_NOVO, 'w', encoding='utf-8') as f:
                json.dump(resultados, f, indent=2, ensure_ascii=False)

            logging.info(f"Teste {idx} concluído com sucesso")
            print(f"✅ (💾 {len(resultados)} salvos)")

        except Exception as e:
            logging.error(f"Erro no teste {idx}: {str(e)}")
            resultados.append({
                "teste_idx": idx,
                "id_original": item.get('id', f'teste_{idx}'),
                "codigo_input": codigo,
                "ground_truth": ground_truth,
                "erro": str(e)
            })

            # Salvar também em caso de erro
            with open(ARQUIVO_RESULTADOS_NOVO, 'w', encoding='utf-8') as f:
                json.dump(resultados, f, indent=2, ensure_ascii=False)

            print(f"❌ Erro: {str(e)[:50]}")

        # Rate limiting
        time.sleep(PAUSA_ENTRE_REQUISICOES)

        if (idx + 1) % REQUISICOES_POR_LOTE == 0:
            print(f"⏸️  Pausa de {PAUSA_LOTE}s (limite de taxa)...")
            time.sleep(PAUSA_LOTE)

    print("\n\n" + "=" * 80)
    print("✅ BASELINE LLM-ONLY CONCLUÍDA!")
    print("=" * 80)
    print(f"\n📁 Resultados salvos em: {ARQUIVO_RESULTADOS_NOVO}")
    print(f"📊 Total de testes executados: {len(resultados)}")

if __name__ == "__main__":
    retreinar_stride_baseline()
