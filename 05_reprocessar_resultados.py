import json
import os
import logging
import time
from dotenv import load_dotenv
from langchain_chroma.vectorstores import Chroma
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
from langchain_huggingface import HuggingFaceEmbeddings

load_dotenv()

CAMINHO_DB = "vectorstore_db"
MODELO_EMBEDDING = "sentence-transformers/all-MiniLM-L6-v2"

ARQUIVO_RESULTADOS_ENTRADA = "resultados_rag.json"
ARQUIVO_RESULTADOS_SAIDA = "resultados_rag_reprocessado.json"

PAUSA_ENTRE_REQUISICOES = 2

logging.basicConfig(
    filename='reprocessamento_invalidos.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

PROMPT_PRINCIPAL = """
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

PROMPT_REPARO_JSON = """
You must return only valid JSON, with no markdown, no explanation outside JSON, and no code fences.

Use the same schema:
{{
  "cwe_id": "CWE-XXX" | "None",
  "explanation": "string",
  "stride": "Tampering" | "Spoofing" | "Repudiation" | "Information Disclosure" | "Denial of Service" | "Elevation of Privilege" | "None"
}}

Java code:
{codigo_alvo}

Reference context:
{base_conhecimento}

Previous invalid response:
{resposta_invalida}
"""


def normalizar_texto_resposta(resposta_texto: str) -> str:
    resposta_texto = resposta_texto.strip()

    if resposta_texto.startswith("```json"):
        resposta_texto = resposta_texto.split("```json", 1)[1]
        resposta_texto = resposta_texto.split("```", 1)[0]
    elif resposta_texto.startswith("```"):
        resposta_texto = resposta_texto.split("```", 1)[1]
        if resposta_texto.startswith("json"):
            resposta_texto = resposta_texto[4:]
        resposta_texto = resposta_texto.split("```", 1)[0]

    return resposta_texto.strip()


def tentar_parsear_json(resposta_texto: str):
    try:
        return json.loads(normalizar_texto_resposta(resposta_texto))
    except json.JSONDecodeError:
        return None


def extrair_casos_invalidos(resultados):
    invalidos = []
    for item in resultados:
        resultado_llm = item.get("resultado_llm", {})
        if item.get("erro"):
            invalidos.append(item)
            continue
        if isinstance(resultado_llm, dict) and (
            resultado_llm.get("error") == "Resposta não é JSON válido" or "raw_response" in resultado_llm
        ):
            invalidos.append(item)
    return invalidos


def carregar_contexto_rag(db, codigo: str) -> str:
    resultados_busca = db.similarity_search(codigo, k=3)
    contexto_str = ""
    for doc in resultados_busca:
        contexto_str += f"\n---\nExemplo Similar:\n{doc.page_content[:500]}...\n"
    return contexto_str


def reprocessar_item(item, chain_principal, chain_reparo, db):
    codigo = item.get("codigo_input", "")
    contexto_str = carregar_contexto_rag(db, codigo)

    resposta = chain_principal.invoke({
        "codigo_alvo": codigo,
        "base_conhecimento": contexto_str
    })

    resposta_texto = getattr(resposta, "content", str(resposta))
    resultado_llm = tentar_parsear_json(resposta_texto)

    if resultado_llm is None:
        resposta_reparo = chain_reparo.invoke({
            "codigo_alvo": codigo,
            "base_conhecimento": contexto_str,
            "resposta_invalida": normalizar_texto_resposta(resposta_texto)
        })
        resposta_reparo_texto = getattr(resposta_reparo, "content", str(resposta_reparo))
        resultado_llm = tentar_parsear_json(resposta_reparo_texto)

        if resultado_llm is None:
            resultado_llm = {
                "error": "Ainda não foi possível gerar JSON válido",
                "raw_response": normalizar_texto_resposta(resposta_reparo_texto)
            }

    item_reprocessado = dict(item)
    item_reprocessado["resultado_llm"] = resultado_llm
    item_reprocessado["reprocessado"] = True
    return item_reprocessado


def main():
    print("=" * 80)
    print("🔄 REPROCESSAMENTO DE RESULTADOS INVÁLIDOS")
    print("=" * 80)

    if not os.path.exists(ARQUIVO_RESULTADOS_ENTRADA):
        print(f"❌ Arquivo {ARQUIVO_RESULTADOS_ENTRADA} não encontrado.")
        return

    if not os.path.exists(CAMINHO_DB):
        print("❌ Banco de vetores não encontrado.")
        return

    with open(ARQUIVO_RESULTADOS_ENTRADA, 'r', encoding='utf-8') as f:
        resultados = json.load(f)

    invalidos = extrair_casos_invalidos(resultados)
    print(f"📊 Total de resultados: {len(resultados)}")
    print(f"⚠️  Casos inválidos encontrados: {len(invalidos)}")

    if not invalidos:
        print("✅ Nenhum caso inválido para reprocessar.")
        return

    embedding_function = HuggingFaceEmbeddings(model_name=MODELO_EMBEDDING)
    db = Chroma(persist_directory=CAMINHO_DB, embedding_function=embedding_function)

    prompt_principal = ChatPromptTemplate.from_template(PROMPT_PRINCIPAL)
    prompt_reparo = ChatPromptTemplate.from_template(PROMPT_REPARO_JSON)
    llm = ChatGroq(temperature=0, model="llama-3.3-70b-versatile")
    chain_principal = prompt_principal | llm
    chain_reparo = prompt_reparo | llm

    indice_invalidos = {item.get("teste_idx"): item for item in invalidos}
    resultados_atualizados = []

    for item in resultados:
        teste_idx = item.get("teste_idx")
        if teste_idx in indice_invalidos:
            print(f"🔍 Reprocessando teste {teste_idx + 1}...", end=" ", flush=True)
            try:
                item = reprocessar_item(item, chain_principal, chain_reparo, db)
                print("✅")
                logging.info(f"Teste {teste_idx} reprocessado com sucesso")
            except Exception as e:
                print(f"❌ {str(e)[:80]}")
                item = dict(item)
                item["erro_reprocessamento"] = str(e)
                logging.error(f"Erro ao reprocessar teste {teste_idx}: {str(e)}")

            time.sleep(PAUSA_ENTRE_REQUISICOES)

        resultados_atualizados.append(item)

    with open(ARQUIVO_RESULTADOS_SAIDA, 'w', encoding='utf-8') as f:
        json.dump(resultados_atualizados, f, indent=2, ensure_ascii=False)

    print("\n" + "=" * 80)
    print("✅ REPROCESSAMENTO CONCLUÍDO")
    print("=" * 80)
    print(f"📁 Arquivo salvo em: {ARQUIVO_RESULTADOS_SAIDA}")


if __name__ == "__main__":
    main()
