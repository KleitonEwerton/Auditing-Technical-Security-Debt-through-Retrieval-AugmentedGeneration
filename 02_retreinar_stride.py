import os
import json
import time
import logging
from langchain_chroma.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
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
CAMINHO_DB = "vectorstore_db"
# Modelo de embeddings utilizado nos experimentos e declarado no artigo (Tabela 1, Seção 4.2).
# IMPORTANTE: os resultados_rag.json foram gerados com este modelo.
MODELO_EMBEDDING = "nomic-ai/nomic-embed-text-v1.5"
ARQUIVO_TESTE = "dataset_teste_reservado.jsonl"
ARQUIVO_RESULTADOS_NOVO = "resultados_rag.json"

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
# Quota backoff: tempo de espera (s) e máximo de tentativas ao atingir limite de cota da API.
# Configurável via RATE_LIMIT_QUOTA_WAIT e RATE_LIMIT_QUOTA_MAX_RETRIES no .env.
QUOTA_WAIT = ler_env_int("RATE_LIMIT_QUOTA_WAIT", 60)
QUOTA_MAX_RETRIES = ler_env_int("RATE_LIMIT_QUOTA_MAX_RETRIES", 3)

logging.basicConfig(filename='retreino_stride_log.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Prompt melhorado com Foco em CWE + Contexto STRIDE
prompt_template_security = """
You are a Software Security Expert. Analyze the Java code for CWE patterns and STRIDE threats.

Reference Context (Use carefully, but prioritize the Explicit Patterns below):
{base_conhecimento}

---
TARGET CODE:
{codigo_alvo}
---

===== 1. CWE PATTERN DEFINITIONS (Strict Syntax Matching) =====

PRIORITY RULES (Apply in order):

1. **CWE-328 (Weak Hash) vs CWE-327 (Broken Crypto)**:
   - IF code uses `MD5`, `MD4`, `SHA1`, or `MessageDigest` -> Classify as **CWE-328**.
   - IF code uses `DES`, `RC2`, `RC4`, `Blowfish`, or `Cipher.getInstance` with weak mode -> Classify as **CWE-327**.

2. **CWE-501 (Trust Boundary Violation)**:
   - LOOK FOR: `session.setAttribute(key, value)` where `value` comes from `request.getParameter()` or user input.
   - TRIGGER: Mixing untrusted input directly into HTTP Session.

3. **CWE-614 (Insecure Cookie)**:
   - LOOK FOR: `new Cookie(...)` followed by `response.addCookie(...)`.
   - TRIGGER: If `setSecure(true)` or `setHttpOnly(true)` is MISSING.

4. **Standard Injections (Maintain current logic)**:
   - CWE-89: SQL construction with concatenation (`+`).
   - CWE-79: Outputting input to JSP/HTML.
   - CWE-78: `Runtime.exec` or `ProcessBuilder`.
   - CWE-22: File access with input.
   - CWE-90: LDAP filter construction.
   - CWE-643: XPath expression construction.
   - CWE-330: `Math.random()` or `java.util.Random` in security context.

If NO pattern matches, return CWE: "None".

===== 2. STRIDE LOGIC RULES (Secondary Goal) =====
Once a CWE is found, determine the specific threat based on the OPERATION:

Rule A: Analyze the Operation Verb
- INSERT, UPDATE, DELETE, MODIFY file -> Write Context
- SELECT, READ file, GET data -> Read Context
- EXECUTE process, RUN system command -> Execute Context

Rule B: Map to STRIDE
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

def retreinar_stride():
    print("=" * 80)
    print("🔄 RE-EXECUÇÃO COM PROMPT STRIDE MELHORADO")
    print("=" * 80)
    print(
        f"⚙️  Rate limit ativo: pausa={PAUSA_ENTRE_REQUISICOES}s | "
        f"lote={REQUISICOES_POR_LOTE} req | pausa_lote={PAUSA_LOTE}s"
    )

    # 1. Carregar Vector Store
    # trust_remote_code=True é necessário para o modelo nomic-embed-text-v1.5
    embedding_function = HuggingFaceEmbeddings(
        model_name=MODELO_EMBEDDING,
        model_kwargs={"trust_remote_code": True}
    )
    if not os.path.exists(CAMINHO_DB):
        print("❌ Erro: Banco de vetores não encontrado.")
        return

    db = Chroma(persist_directory=CAMINHO_DB, embedding_function=embedding_function)

    # 2. Carregar dados de teste
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

    # 3. Verificar se há resultados anteriores para continuar
    resultados = []
    # indices_retry: lista ordenada (crescente) dos teste_idx que falharam e precisam ser reprocessados.
    # Vazia quando não há arquivo anterior ou o usuário optou por não continuar.
    indices_retry: list[int] = []
    modo_retry = False

    if os.path.exists(ARQUIVO_RESULTADOS_NOVO):
        print(f"\n⚠️  Arquivo {ARQUIVO_RESULTADOS_NOVO} já existe.")
        resposta = input("Deseja continuar / reprocessar casos com erro? (s/n): ")
        if resposta.lower() == 's':
            with open(ARQUIVO_RESULTADOS_NOVO, 'r', encoding='utf-8') as f:
                resultados = json.load(f)

            # Separar casos com sucesso dos que falharam
            erros = sorted(
                [item['teste_idx'] for item in resultados if 'erro' in item]
            )
            sucessos = len(resultados) - len(erros)

            if erros:
                # Retry seletivo: reprocessar apenas os casos com erro, do primeiro ao último
                indices_retry = erros
                modo_retry = True
                print(f"✓ {sucessos} casos concluídos com sucesso preservados.")
                print(f"🔁 Retry seletivo: {len(erros)} caso(s) com erro serão reprocessados")
                print(f"   Primeiro erro: teste_idx={erros[0]} | Último: teste_idx={erros[-1]}")
                # Remover entradas de erro para reprocessamento limpo
                resultados = [item for item in resultados if 'erro' not in item]
            else:
                print(f"✓ Todos os {len(resultados)} casos anteriores concluíram com sucesso.")
                print("   Nada a reprocessar. Encerrando.")
                return

    # 4. Inicializar LLM
    print(f"\n🤖 Modelo LLM: {MODELO_LLM}")
    if MODELO_LLM == MODELO_LLM_ORIGINAL:
        print("⚠️  AVISO: este modelo foi depreciado pela Groq em 16/ago/2026.")
        print("   Defina GROQ_LLM_MODEL no .env (ex.: openai/gpt-oss-120b).")
    prompt = ChatPromptTemplate.from_template(prompt_template_security)
    llm = ChatGroq(temperature=0, model=MODELO_LLM)
    chain = prompt | llm

    # 5. Executar testes
    if modo_retry:
        print(f"\n🚀 Reprocessando {len(indices_retry)} caso(s) com erro (ordem crescente de teste_idx)...\n")
    else:
        print(f"\n🚀 Iniciando testes (0 até {total_testes})...\n")
    print("💾 Salvamento automático após cada resposta\n")
    
    # Determinar quais índices processar
    indices_a_processar = indices_retry if modo_retry else list(range(total_testes))
    total_a_processar = len(indices_a_processar)
    contagem_sucesso = 0
    contagem_erro = 0

    for posicao, idx in enumerate(indices_a_processar):
        item = dados_teste[idx]
        codigo = item.get('input', '')
        ground_truth = item.get('output', '{}')
        
        print(f"🔍 [{posicao+1}/{total_a_processar}] Teste idx={idx}... ", end='', flush=True)
        
        tentativas = 0
        while True:
            try:
                # Buscar contexto RAG
                resultados_busca = db.similarity_search(codigo, k=3)
                contexto_str = ""
                for doc in resultados_busca:
                    contexto_str += f"\n---\nExemplo Similar:\n{doc.page_content[:500]}...\n"
                
                # Consultar LLM
                resposta = chain.invoke({
                    "codigo_alvo": codigo,
                    "base_conhecimento": contexto_str
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
                
                # Salvar IMEDIATAMENTE após cada resposta (proteção contra rate limit)
                with open(ARQUIVO_RESULTADOS_NOVO, 'w', encoding='utf-8') as f:
                    json.dump(sorted(resultados, key=lambda x: x['teste_idx']),
                              f, indent=2, ensure_ascii=False)
                
                logging.info(f"Teste {idx} concluído com sucesso")
                contagem_sucesso += 1
                print(f"✅ (✓ {contagem_sucesso} ok / ✗ {contagem_erro} erros)")
                break  # sair do loop de tentativas
                
            except Exception as e:
                erro_str = str(e)
                # Detectar erro de quota/rate-limit para aplicar backoff automático
                eh_quota = (
                    "rate_limit_exceeded" in erro_str.lower()
                    or "429" in erro_str
                    or "quota" in erro_str.lower()
                )
                tentativas += 1
                if eh_quota and tentativas <= QUOTA_MAX_RETRIES:
                    print(
                        f"\n⏳ Quota atingida (tentativa {tentativas}/{QUOTA_MAX_RETRIES}). "
                        f"Aguardando {QUOTA_WAIT}s antes de tentar novamente..."
                    )
                    logging.warning(
                        f"Quota atingida no teste {idx} (tentativa {tentativas}). "
                        f"Aguardando {QUOTA_WAIT}s."
                    )
                    time.sleep(QUOTA_WAIT)
                    continue  # tentar novamente

                # Falha definitiva: registrar erro
                logging.error(f"Erro no teste {idx}: {erro_str}")
                resultados.append({
                    "teste_idx": idx,
                    "id_original": item.get('id', f'teste_{idx}'),
                    "codigo_input": codigo,
                    "ground_truth": ground_truth,
                    "erro": erro_str
                })
                
                # Salvar também em caso de erro
                with open(ARQUIVO_RESULTADOS_NOVO, 'w', encoding='utf-8') as f:
                    json.dump(sorted(resultados, key=lambda x: x['teste_idx']),
                              f, indent=2, ensure_ascii=False)
                
                contagem_erro += 1
                aviso_quota = " (quota esgotada após retries)" if eh_quota else ""
                print(f"❌ Erro{aviso_quota}: {erro_str[:60]}")
                break  # sair do loop de tentativas
        
        # Rate limiting
        time.sleep(PAUSA_ENTRE_REQUISICOES)
        
        if (posicao + 1) % REQUISICOES_POR_LOTE == 0:
            print(f"⏸️  Pausa de {PAUSA_LOTE}s (limite de taxa)...")
            time.sleep(PAUSA_LOTE)

    print("\n\n" + "=" * 80)
    total_processados = contagem_sucesso + contagem_erro
    if contagem_erro == 0:
        print("✅ RE-EXECUÇÃO CONCLUÍDA COM SUCESSO!")
    else:
        print("⚠️  RE-EXECUÇÃO CONCLUÍDA PARCIALMENTE")
    print("=" * 80)
    print(f"\n📁 Resultados salvos em: {ARQUIVO_RESULTADOS_NOVO}")
    print(f"✅ Concluídos com sucesso : {contagem_sucesso:4d} / {total_processados}")
    print(f"❌ Falhas (erros de API)  : {contagem_erro:4d} / {total_processados}")
    if contagem_erro > 0:
        indices_com_erro = sorted(
            [item['teste_idx'] for item in resultados if 'erro' in item]
        )
        print(f"\n⚠️  ATENÇÃO: {contagem_erro} caso(s) com erro. Execute novamente e escolha 's'")
        print(f"   para reprocessar automaticamente do primeiro erro (idx={indices_com_erro[0]}).")
        logging.warning(
            "Execução concluída parcialmente: %d sucesso(s), %d erro(s). "
            "Índices com erro: %s",
            contagem_sucesso, contagem_erro, indices_com_erro
        )
    
if __name__ == "__main__":
    retreinar_stride()
