# Agente de Análise de Dívida de Segurança Técnica (Security Debt)

## Autores

- Kleiton Ewerton de Oliveira - kleitonewertonoliveira@gmail.com
- Gleiph Ghiotto Lima de Menezes - gleiph.ghiotto@ufjf.br
- André Luiz de Oliveira - andre.oliveira@ufjf.br

## Abstract

Technical Security Debt (TSD) refers to latent vulnerabilities that may not immediately compromise software functionality but progressively weaken its defenses. Conventional Static Application Security Testing (SAST) tools provide the basis for vulnerability detection and remain essential in secure development workflows. However, complementary semantic layers can support
contextualizing the findings in terms of data flows, attack patterns, and architectural impact. In this paper, we propose a neuro-symbolic approach for auditing TSD by integrating Large Language Models (LLMs), Retrieval-Augmented Generation (RAG), and security ontologies. Our approach uses the CWE → CAPEC → STRIDE chain as the supporting structure to link implementation-level weaknesses to attack patterns and preliminary architectural threat hypotheses. We use the Open Worldwide Application Security Project (OWASP) Benchmark v1.2, we built a pipeline that enriches code fragments with ontological metadata and retrieves semantically similar examples during inference. The RAG-assisted configuration achieved 90.88% accuracy and a weighted F1-score of 0.9142 in CWE classification, outperforming an LLM-only baseline by 20.44% points in accuracy. A paired McNemar test confirmed that this improvement was statistically significant (p = 3.85 × 10−34). The results indicate that retrieval and ontological grounding can reduce semantic drift in vulnerability auditing, while STRIDE-based threat mapping should be interpreted as a preliminary contextualization layer rather than as a definitive threat-modeling oracle.

## 📋 Descrição

**agente-debt-sec** é um sistema inteligente baseado em **RAG (Retrieval-Augmented Generation)** e **LLM** que analisa código Java em busca de **Dívida de Segurança Técnica (Security Debt)** e vulnerabilidades. 

O projeto utiliza:
- **ChromaDB** para indexação vetorial de exemplos de código
- **Sentence Transformers** para embeddings semânticos
- **Groq LLM** (Llama-3.3-70b) para análise e reasoning
- **Dataset OWASP Benchmark** para treinamento e validação

Os selos considerados são:

- Artefatos Disponíveis (SeloD)
- Artefatos Funcionais (SeloF)
- Artefatos Sustentáveis (SeloS)
- Experimentos Reprodutíveis (SeloR)

---

## 🎯 Objetivo

Desenvolver um auditor automatizado de segurança que:
1. Classifique código como **VULNERABLE** ou **SAFE**
2. Identifique o **CWE (Common Weakness Enumeration)** aplicável
3. Categorize ameaças usando **OWASP**
4. Forneça explicações técnicas baseadas em contexto semelhante (Few-Shot Learning via RAG)

---

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────┐
│  Dataset OWASP Benchmark (.jsonl)           │
│  (treino + teste reservado)                 │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  01_construir_base_conhecimento.py          │
│  - Parse JSON                               │
│  - Chunking (2000 chars)                    │
│  - Embedding (Sentence Transformers)        │
│  - Indexação ChromaDB                       │
└──────────────┬──────────────────────────────┘
               │
               ▼
         vectorstore_db/
      (índice vetorial persistido)
               │
               ▼
┌─────────────────────────────────────────────┐
│  02_auditor_seguranca_rag.py                │
│  - RAG: Busca 3 casos similares              │
│  - Prompt com Few-Shot Learning             │
│  - Consulta Groq LLM                        │
│  - Retorna JSON estruturado                 │
└─────────────────────────────────────────────┘
```

---

## 📦 Dependências

```
langchain>=1.2.0
langchain-chroma>=1.1.0
langchain-huggingface>=1.2.0
langchain-groq>=1.1.1
chromadb>=1.4.0
sentence-transformers>=5.2.0
python-dotenv>=1.2.1
tqdm>=4.67.1
```

Instale via:
```bash
pip install -r requirements.txt
```

---

## 🚀 Como Usar

### ✅ Pré-requisitos Antes de Começar

Você precisará de:
1. **Python 3.8+** instalado
2. **Git** instalado
3. **Chave de API Groq** (obtida em https://console.groq.com/)
4. **225 arquivos Java** do OWASP Benchmark (clonados automaticamente)
5. **2 arquivos XML do MITRE** (manual):
   - `cwec_v4.18.xml` (Common Weakness Enumeration)
   - `capec_v3.9.xml` (Common Attack Pattern Enumeration)

> **Nota:** Você só precisa baixar os XMLs uma única vez, durante a geração do dataset.

---

### Passo 0: Gerar Dataset (Primeira Execução)

O dataset de treinamento e teste são **gerados automaticamente** a partir do repositório OWASP Benchmark Java. Siga os passos abaixo:

#### 0.1 Clonar OWASP Benchmark Java

```bash
# Na pasta pai de agente-debt-sec, clone o repositório
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git
```

**Estrutura esperada:**
```
agente-debt-sec/
  ├── 00_gerar_dataset_final.py
  ├── 01_construir_base_conhecimento.py
  └── ...
BenchmarkJava/
  ├── src/main/java/org/owasp/benchmark/testcode/
  ├── expectedresults-1.2.csv
  └── cwec_v4.18.xml
```

#### 0.2 Baixar Definições CWE e CAPEC ⚠️ OBRIGATÓRIO

Este é um **passo fundamental**. Os arquivos XML do MITRE são essenciais para enriquecer o dataset com informações de ameaça.

Dentro da pasta `BenchmarkJava/`, obtenha os arquivos XML:

```bash
cd BenchmarkJava

# Baixar CWE (Common Weakness Enumeration)
wget https://cwe.mitre.org/data/downloads/cwec_v4.18.xml

# Baixar CAPEC (Common Attack Pattern Enumeration)
wget https://capec.mitre.org/data/downloads/capec_v3.9.xml
```

**Ou baixe manualmente:**
- [CWE XML](https://cwe.mitre.org/data/downloads/cwec_v4.18.xml)
- [CAPEC XML](https://capec.mitre.org/data/downloads/capec_v3.9.xml)

E coloque ambos os arquivos na **raiz de `BenchmarkJava/`**.

**Estrutura esperada após download:**
```
BenchmarkJava/
├── cwec_v4.18.xml          ← Arquivo obrigatório
├── capec_v3.9.xml          ← Arquivo obrigatório
├── src/main/java/...
├── expectedresults-1.2.csv
└── ...
```

> 🚨 **Aviso:** Se esses arquivos não existirem, o script `00_gerar_dataset_final.py` falhará com mensagens de erro na leitura dos XMLs.


#### 0.3 Executar Gerador de Dataset

```bash
# De dentro da pasta BenchmarkJava
python ../agente-debt-sec/00_gerar_dataset_final.py
```

**O que faz:**
- Lê todos os arquivos `.java` do diretório `src/main/java/org/owasp/benchmark/testcode/`
- Mapeia cada teste com seu `CWE` e `CAPEC` usando os XMLs do MITRE
- Determina se é **VULNERABLE** ou **SAFE** baseado no `expectedresults-1.2.csv`
- Gera **2 arquivos JSONL**:
  - `dataset_completo_mestrado.jsonl` - onde temos os dados completos

**Saída esperada:**
```
📖 Carregando definições CWE e CAPEC...
🚀 Iniciando processamento do Benchmark em: src/main/java/org/owasp/benchmark/testcode
✅ Concluído! 225 exemplos salvos em dataset_completo_mestrado.jsonl
```

#### 0.4 Mover Datasets para agente-debt-sec

```bash
# Copiar os datasets gerados para a pasta do projeto
cp dataset_completo_mestrado.jsonl ../agente-debt-sec/
```

---

### 📂 Entendendo os Datasets e a Divisão 80/20

Após a execução do `00_gerar_dataset_final.py`, você terá:

#### 1️⃣ `dataset_completo_mestrado.jsonl` (100% dos dados)
- Contém **todos os 225 exemplos** do OWASP Benchmark
- Este é o arquivo de **entrada** usado pelo script `01_construir_base_conhecimento.py`
- **Não é o dataset de treino**, é o dataset completo antes do split

#### 2️⃣ Split Automático 80/20 (feito pelo script 01)

Quando você executa `01_construir_base_conhecimento.py`:

```python
PERCENTUAL_TESTE = 0.20  # 20% para teste

# O script faz automaticamente:
# - 80% (180 exemplos) → Vetorizados e armazenados em vectorstore_db/
# - 20% (45 exemplos)  → Salvos em dataset_teste_reservado.jsonl
```

**Resultado:**

| Arquivo/Pasta | Quantidade | Propósito |
|---------------|-----------|-----------|
| `dataset_completo_mestrado.jsonl` | 225 (100%) | Dados brutos completos |
| `vectorstore_db/` | 180 (80%) | **Base de conhecimento RAG** (embeddings) |
| `dataset_teste_reservado.jsonl` | 45 (20%) | **Dados de teste** (não vistos pelo RAG) |

> ⚠️ **Importante:** Os **80% de treino NÃO ficam em um arquivo `.jsonl` separado**. Eles são transformados em vetores (embeddings) e armazenados na pasta `vectorstore_db/` como um índice ChromaDB. Isso permite busca semântica rápida durante a auditoria.

#### 3️⃣ Como os dados são usados:

```
dataset_completo_mestrado.jsonl (225 exemplos)
            │
            ▼
   01_construir_base_conhecimento.py
            │
            ├─────────────┬──────────────┐
            ▼             ▼              ▼
    vectorstore_db/   (80% treino)   dataset_teste_reservado.jsonl
     (índice RAG)     (embeddings)    (20% teste - não vetorizado)
            │                               │
            ▼                               ▼
  02_auditor_seguranca_rag.py     02_retreinar_stride.py
   (usa RAG para buscar           (valida contra ground truth)
    exemplos similares)
```

---

### Passo 1: Configurar API Key

Crie um arquivo `.env` na raiz do projeto:
```
GROQ_API_KEY=sua_chave_aqui
```

Obtenha a chave em: https://console.groq.com/

### Passo 2: Construir a Base de Conhecimento

```bash
python 01_construir_base_conhecimento.py
```

**O que faz:**
- Carrega `dataset_completo_mestrado.jsonl` (80% dos dados)
- Cria `dataset_teste_reservado.jsonl` (20% separado)
- Vetoriza com embeddings semânticos
- Persiste índice em `vectorstore_db/`

**Saída esperada:**
```
--- 📂 Carregando Dataset: dataset_completo_mestrado.jsonl ---
📊 Total de registros encontrados: 225
✂️  Split realizado: 180 para Base de Conhecimento (RAG) | 45 reservados para Teste.
📦 Total de chunks para vetorização: 185
🧠 Inicializando Embeddings (sentence-transformers/all-MiniLM-L6-v2)...
⚡ Vetorizando e persistindo no ChromaDB...
Processando Lotes: 100%|████| 2/2
✅ Base de Conhecimento criada em 'vectorstore_db'!
```

### Passo 3: Executar Auditor Interativo

```bash
python 02_auditor_seguranca_rag.py
```

**Interação:**
1. Cole o código Java para analisar
2. Digite `FIM` em uma nova linha para processar
3. Receba análise estruturada em JSON
4. Repita ou digite `sair` para encerrar

**Exemplo de Input:**
```java
String fileName = "/tmp/" + userInput;
FileInputStream fis = new FileInputStream(new File(fileName));
```

**Exemplo de Output:**
```json
{
  "verdict": "VULNERABLE",
  "cwe_id": "CWE-22",
  "explanation": "Path Traversal: O código concatena diretamente entrada de usuário sem validação...",
  "stride": "Tampering"
}
```

---

## 📊 Estrutura dos Dados

### Dataset Training/Test (.jsonl)

```json
{
  "instruction": "Analyze the provided Java code snippet...",
  "input": "package org.owasp.benchmark.testcode; ...",
  "output": {
    "verdict": "VULNERABLE",
    "weakness": {
      "id": "CWE-22",
      "name": "Path Traversal",
      "description": "..."
    },
    "threat_model": {
      "related_capecs": ["CAPEC-126", "CAPEC-64"],
      "stride_categories": ["Repudiation"]
    }
  }
}
```

### Arquivo Benchmark (CSV)

```csv
BenchmarkTest00001, pathtraver, true, 22
BenchmarkTest00002, pathtraver, true, 22
...
```

Permite validar predições contra labels OWASP Benchmark 1.2

---

## 🔍 Vulnerabilidades Cobertas

Baseado em OWASP Benchmark v1.2:

| CWE | Nome | Exemplos |
|-----|------|----------|
| **CWE-22** | Path Traversal | `../../../etc/passwd` |
| **CWE-78** | OS Command Injection | `Runtime.exec(userInput)` |
| **CWE-79** | Cross-Site Scripting (XSS) | Sem escape HTML |
| **CWE-89** | SQL Injection | Concatenação de query |
| **CWE-90** | LDAP Injection | Sem sanitização LDAP |
| **CWE-327** | Weak Cryptography | MD5, DES, Random() |
| **CWE-328** | Weak Hash | MD5 para senhas |
| **CWE-330** | Weak Random | `java.util.Random` |
| **CWE-501** | Trust Boundary Violation | Dados não validados |
| **CWE-614** | Insecure Cookie | Sem HttpOnly/Secure |

---

## 📁 Estrutura do Projeto

```
agente-debt-sec/
├── 00_gerar_dataset_final.py            # Gerador de dataset (rodar em BenchmarkJava/)
├── 01_construir_base_conhecimento.py    # Script de indexação
├── 02_auditor_seguranca_rag.py          # Auditoria interativa
├── dataset_completo_mestrado.jsonl        # Dados de treino (80%) - GERADO
├── dataset_teste_reservado.jsonl        # Dados de teste (20%) - GERADO
├── expectedresults-1.2.csv              # Benchmark labels
├── vectorstore_db/                      # ChromaDB persistido
│   ├── chroma.sqlite3
│   └── ...
├── requirements.txt                     # Dependências Python
├── .env                                 # Variáveis de ambiente
└── README.md                            # Este arquivo
```

---

## 🔧 Configurações Avançadas

### Como Funciona 00_gerar_dataset_final.py

Este script é o **pipeline ETL (Extract-Transform-Load)** que:

1. **Extract**: Lê arquivos Java do OWASP Benchmark
2. **Transform**: 
   - Mapeia cada teste com CWE, CAPEC e STRIDE usando XMLs do MITRE
   - Limpa código (remove comentários de licença e imports)
   - Enriquece metadados com informações de ameaça
3. **Load**: Gera 2 arquivos JSONL estruturados

**Configurações personalizáveis:**

```python
PATH_CODE_DIR = os.path.join("src", "main", "java", "org", "owasp", "benchmark", "testcode")
PATH_CSV = "expectedresults-1.2.csv"
PATH_CWE_XML = "cwec_v4.18.xml"
PATH_CAPEC_XML = "capec_v3.9.xml"
OUTPUT_FILE = "dataset_completo_mestrado.jsonl"
```

**Exemplo de saída (estrutura JSONL):**
```json
{
  "instruction": "Analyze the provided Java code snippet...",
  "input": "package org.owasp.benchmark.testcode; ...",
  "output": {
    "verdict": "VULNERABLE",
    "weakness": {
      "id": "CWE-22",
      "name": "Path Traversal",
      "description": "The product uses external input to construct a pathname..."
    },
    "threat_model": {
      "related_capecs": ["CAPEC-126", "CAPEC-64", "CAPEC-76"],
      "stride_categories": ["Tampering", "Denial of Service"]
    }
  }
}
```

---

### Modificar Modelo de Embeddings

Em `01_construir_base_conhecimento.py`:
```python
MODELO_EMBEDDING = "sentence-transformers/all-mpnet-base-v2"  # Mais preciso, mais lento
```

### Ajustar Tamanho de Chunks

```python
text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=1500,  # Reduzir para contexto mais focado
    chunk_overlap=150
)
```

### Trocar LLM

Em `02_auditor_seguranca_rag.py`:
```python
llm = ChatGroq(
    temperature=0.2,  # Mais criativo (0-1)
    model="llama-3-70b-8192"  # Outras opções disponíveis
)
```

---

## ✅ Validação e Métricas

Para avaliar performance contra OWASP Benchmark:

```python
# Pseudocódigo
from sklearn.metrics import precision_recall_fscore_support

predictions = []
ground_truth = []

for test_case in dataset_teste:
    pred = auditor.analyze(test_case['code'])
    predictions.append(pred['verdict'])
    ground_truth.append(test_case['expected_verdict'])

precision, recall, f1, _ = precision_recall_fscore_support(
    ground_truth, predictions, average='binary'
)
```

---

## 🛠️ Troubleshooting

### Erro: "Banco de vetores não encontrado"
```
❌ Rode o script 01 primeiro!
```
**Solução:** Execute `01_construir_base_conhecimento.py` antes de usar o auditor.

### Erro: "Invalid GROQ_API_KEY"
```
❌ Erro na API Groq
```
**Solução:** Verifique `.env` e teste a chave em https://console.groq.com/

### ChromaDB com espaço em disco limitado
```python
# Usar lotes menores
tamanho_lote = 50  # em vez de 100
```

---

## 📚 Referências

- [OWASP Benchmark](https://owasp.org/www-project-benchmark/)
- [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/)
- [Common Attack Pattern Enumeration (CAPEC)](https://capec.mitre.org/)
- [STRIDE Threat Modeling](https://en.wikipedia.org/wiki/STRIDE_(security))
- [ChromaDB Docs](https://docs.trychroma.com/)
- [LangChain Docs](https://python.langchain.com/)
- [Groq API Docs](https://console.groq.com/docs)

---

## 👨‍🎓 Projeto Acadêmico

Este projeto foi desenvolvido como trabalho de **Mestrado** em análise de Dívida Técnica de Segurança usando técnicas de **RAG + LLM**.

---

## 📝 Licença

MIT License - Veja LICENSE para detalhes.

---

## ❓ Suporte

Para questões ou contribuições, abra uma *issue* ou *pull request*.

**Última atualização:** Janeiro 2026
