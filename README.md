# Auditoria de Dívida de Segurança Técnica via Recuperação Aumentada por Geração (RAG)

**Autores:**
- Kleiton Ewerton de Oliveira — kleitonewertonoliveira@gmail.com
- Gleiph Ghiotto Lima de Menezes — gleiph.ghiotto@ufjf.br
- André Luiz de Oliveira — andre.oliveira@ufjf.br

## Abstract

Technical Security Debt (TSD) refers to latent vulnerabilities that may not immediately compromise software functionality but progressively weaken its defenses. Conventional Static Application Security Testing (SAST) tools provide the basis for vulnerability detection and remain essential in secure development workflows. However, complementary semantic layers can support contextualizing the findings in terms of data flows, attack patterns, and architectural impact. In this paper, we propose a neuro-symbolic approach for auditing TSD by integrating Large Language Models (LLMs), Retrieval-Augmented Generation (RAG), and security ontologies. Our approach uses the CWE → CAPEC → STRIDE chain as the supporting structure to link implementation-level weaknesses to attack patterns and preliminary architectural threat hypotheses. We use the Open Worldwide Application Security Project (OWASP) Benchmark v1.2 — a dataset with 2,740 Java code samples — and built a pipeline that enriches code fragments with ontological metadata and retrieves semantically similar examples during inference. The RAG-assisted configuration achieved **90.88% accuracy** and a weighted F1-score of **0.9142** in CWE classification, outperforming an LLM-only baseline by **20.44 percentage points** in accuracy. A paired McNemar test confirmed that this improvement was statistically significant (p = 3.85 × 10⁻³⁴). The results indicate that retrieval and ontological grounding can reduce semantic drift in vulnerability auditing, while STRIDE-based threat mapping should be interpreted as a preliminary contextualization layer rather than as a definitive threat-modeling oracle.

---

# Estrutura do README

Este README está organizado da seguinte forma:

- [Estrutura do README](#estrutura-do-readme) — organização deste documento e do repositório
- [Selos Considerados](#selos-considerados) — selos solicitados para avaliação
- [Informações básicas](#informações-básicas) — ambiente de execução, hardware e software
- [Dependências](#dependências) — bibliotecas e versões necessárias
- [Preocupações com segurança](#preocupações-com-segurança) — riscos e cuidados durante a execução
- [Instalação](#instalação) — passo a passo para configurar o ambiente
- [Teste mínimo](#teste-mínimo) — verificação rápida de funcionamento
- [Experimentos](#experimentos) — reprodução das reivindicações do artigo
- [LICENSE](#license) — licença do projeto

### Estrutura do Repositório

```
.
├── 00_gerar_dataset_final.py          # ETL: gera dataset a partir do OWASP Benchmark Java
├── 01_construir_base_conhecimento.py  # Vetoriza dados de treino e persiste no ChromaDB
├── 02_retreinar_stride.py             # Executa o pipeline RAG + LLM (gera resultados_rag.json)
├── 02_retreinar_stride_baseline.py    # Executa o pipeline LLM-only / baseline (gera resultados_llm.json)
├── 03_analisar_resultados.py          # Análise básica de resultados individuais
├── 04_analise_avancada.py             # Métricas avançadas: F1, matriz de confusão, análise de erros
├── 05_reprocessar_resultados.py       # Reprocessa/corrige resultados já gerados
├── 06_comparar_resultados_llm_rag.py  # Compara accuracy LLM vs RAG → comparacao_llm_vs_rag.json
├── 07_mcnemar_test.py                 # Teste estatístico de McNemar → mcnemar_report.json
├── dataset_completo_mestrado.jsonl    # Dataset completo OWASP Benchmark v1.2 (2.740 exemplos)
├── dataset_teste_reservado.jsonl      # 20% reservados para teste (548 exemplos)
├── dataset_treino.jsonl               # Placeholder — dados de treino estão vetorizados em vectorstore_db/
├── expectedresults-1.2.csv            # Ground truth do OWASP Benchmark v1.2
├── cwec_v4.18.xml                     # Common Weakness Enumeration v4.18 (MITRE)
├── capec_v3.9.xml                     # Common Attack Pattern Enumeration v3.9 (MITRE)
├── resultados_llm.json                # Resultados gerados pelo baseline LLM-only (548 casos)
├── resultados_rag.json                # Resultados gerados pelo pipeline RAG (548 casos)
├── analise_llm.json                   # Análise básica dos resultados LLM
├── analise_rag.json                   # Análise básica dos resultados RAG
├── analise_llm_avancada.json          # Métricas avançadas do LLM (F1, matriz de confusão)
├── analise_rag_avancada.json          # Métricas avançadas do RAG (F1, matriz de confusão)
├── comparacao_llm_vs_rag.json         # Comparação lado a lado LLM vs RAG
├── mcnemar_report.json                # Resultado do teste de McNemar
├── example.env                        # Exemplo de arquivo de variáveis de ambiente
├── requirements.txt                   # Dependências Python com versões
├── LICENSE                            # Licença MIT
└── README.md                          # Este arquivo
```

**Tabela de scripts — entradas, saídas e finalidade:**

| Script | Entrada | Saída | Finalidade | Reivindicação |
|---|---|---|---|---|
| `00_gerar_dataset_final.py` | Arquivos `.java` do OWASP Benchmark, `expectedresults-1.2.csv`, `cwec_v4.18.xml`, `capec_v3.9.xml` | `dataset_completo_mestrado.jsonl` | ETL: extrai, enriquece e serializa o dataset | — |
| `01_construir_base_conhecimento.py` | `dataset_completo_mestrado.jsonl` | `vectorstore_db/` (ChromaDB), `dataset_teste_reservado.jsonl` | Vetoriza e indexa 80% dos dados para uso pelo RAG | — |
| `02_retreinar_stride.py` | `vectorstore_db/`, `dataset_teste_reservado.jsonl`, API Groq | `resultados_rag.json` | Executa o pipeline RAG + LLM sobre os 548 casos de teste | #1, #2 |
| `02_retreinar_stride_baseline.py` | `dataset_teste_reservado.jsonl`, API Groq | `resultados_llm.json` | Executa o baseline LLM-only sobre os 548 casos de teste | #1 |
| `03_analisar_resultados.py` | `resultados_rag.json` ou `resultados_llm.json` | Saída no terminal | Análise rápida de resultados individuais | — |
| `04_analise_avancada.py` | `resultados_rag.json` ou `resultados_llm.json` | `analise_avancada_metricas.json` (padrão) | F1-score ponderado, matriz de confusão, análise de erros | #2 |
| `05_reprocessar_resultados.py` | `resultados_rag.json` ou `resultados_llm.json` | Arquivo de resultados corrigido | Reprocessa respostas com parse falho | — |
| `06_comparar_resultados_llm_rag.py` | `resultados_llm.json`, `resultados_rag.json` | `comparacao_llm_vs_rag.json` | Compara accuracy e cobertura STRIDE lado a lado | #1 |
| `07_mcnemar_test.py` | `resultados_llm.json`, `resultados_rag.json` | `mcnemar_report.json` | Teste estatístico pareado de McNemar | #3 |

---

# Selos Considerados

Os selos considerados são:

- **Artefatos Disponíveis (SeloD)**
- **Artefatos Funcionais (SeloF)**
- **Artefatos Sustentáveis (SeloS)**
- **Experimentos Reprodutíveis (SeloR)**

---

# Informações básicas

## Hardware

Os experimentos foram executados em:

- **CPU:** Intel Core i7 (ou equivalente), mínimo 4 cores
- **RAM:** Mínimo 8 GB (recomendado 16 GB para execução completa do pipeline RAG)
- **Armazenamento:** Mínimo 15 GB livres (datasets + embeddings ChromaDB + modelos Sentence Transformers ~1.5 GB)
- **Internet:** Necessária para download do modelo de embeddings na primeira execução e para chamadas à API Groq

> **Nota para revisores:** Os scripts de análise e comparação (`06_comparar_resultados_llm_rag.py` e `07_mcnemar_test.py`) **não requerem GPU, API externa nem os modelos de embeddings** — operam apenas sobre os arquivos JSON de resultados já entregues. Para reproduzir as reivindicações do artigo, esses dois scripts são suficientes e executam em segundos em qualquer máquina.

## Software

- **Sistema Operacional:** Windows 10/11, Linux (Ubuntu 20.04+) ou macOS 12+
- **Python:** 3.10 ou superior (testado com Python 3.10 e 3.12)
- **Git:** Para clonar o repositório
- **Chave de API Groq:** Necessária **apenas** para re-executar os scripts `02_retreinar_stride.py` e `02_retreinar_stride_baseline.py` (geração de novos resultados). Para reproduzir as reivindicações a partir dos resultados já fornecidos, **não é necessária**.

### Obtendo a chave de API Groq (opcional para SeloR)

A chave Groq é gratuita e pode ser obtida em: https://console.groq.com/

O modelo utilizado nos experimentos foi: **`llama-3.3-70b-versatile`** via API Groq.

---

# Dependências

## Dependências Python

Todas as dependências estão listadas em `requirements.txt`. Instale via:

```bash
pip install -r requirements.txt
```

| Pacote | Versão mínima | Finalidade |
|---|---|---|
| `langchain` | ≥ 0.3.0 | Framework de orquestração LLM |
| `langchain-core` | ≥ 0.3.0 | Componentes base do LangChain |
| `langchain-chroma` | ≥ 0.1.4 | Integração ChromaDB com LangChain |
| `langchain-huggingface` | ≥ 0.1.2 | Integração HuggingFace Embeddings |
| `langchain-groq` | ≥ 0.2.1 | Integração com a API Groq |
| `langchain-text-splitters` | ≥ 0.3.0 | Divisão de documentos em chunks |
| `chromadb` | ≥ 0.5.0 | Banco de vetores persistente |
| `sentence-transformers` | ≥ 3.0.0 | Modelo de embeddings semânticos |
| `python-dotenv` | ≥ 1.0.0 | Carregamento de variáveis de ambiente |
| `tqdm` | ≥ 4.66.0 | Barras de progresso |
| `numpy` | ≥ 1.26.0 | Computação numérica (análise avançada) |
| `scikit-learn` | ≥ 1.5.0 | Métricas de classificação (F1, etc.) |

## Dados externos (já incluídos no repositório)

Os seguintes arquivos estão incluídos e **não precisam ser baixados**:

| Arquivo | Fonte | Descrição |
|---|---|---|
| `dataset_completo_mestrado.jsonl` | Gerado a partir do OWASP Benchmark v1.2 | 2.740 exemplos de código Java anotados |
| `dataset_teste_reservado.jsonl` | Split 20% do dataset completo | 548 exemplos usados nos experimentos |
| `expectedresults-1.2.csv` | OWASP Benchmark Java v1.2 | Ground truth oficial do benchmark |
| `cwec_v4.18.xml` | MITRE CWE v4.18 | Definições de fraquezas de segurança |
| `capec_v3.9.xml` | MITRE CAPEC v3.9 | Padrões de ataque |
| `resultados_llm.json` | Gerado pelos experimentos | 548 predições do baseline LLM-only |
| `resultados_rag.json` | Gerado pelos experimentos | 548 predições do pipeline RAG |

> **Sobre o dataset:** O `dataset_completo_mestrado.jsonl` foi gerado a partir do repositório [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) v1.2, que contém 2.740 testes unitários de vulnerabilidade Java. A divisão 80/20 (aleatória com `random.seed(42)`) resultou em 2.192 exemplos de treino (vetorizados no ChromaDB) e 548 exemplos de teste. O arquivo `dataset_treino.jsonl` não contém os dados de treino em formato JSONL porque eles são transformados em vetores e persistidos diretamente no `vectorstore_db/` pelo script `01_construir_base_conhecimento.py`.

---

# Preocupações com segurança

- **Chave de API Groq:** A chave de API deve ser armazenada exclusivamente no arquivo `.env` (nunca comitada no repositório). O `.gitignore` já exclui o arquivo `.env`. Revogue e regenere a chave após o uso em ambientes compartilhados.

- **Dados de código Java:** O dataset contém fragmentos de código propositalmente vulneráveis do OWASP Benchmark. Esses fragmentos são material de estudo e não devem ser executados em produção.

- **API externa (Groq):** Os scripts `02_retreinar_stride.py` e `02_retreinar_stride_baseline.py` enviam fragmentos de código Java para a API Groq. Certifique-se de estar ciente das [políticas de privacidade da Groq](https://groq.com/privacy-policy/) antes de executar esses scripts.

- **Sem exposição de portas:** Este artefato não expõe serviços de rede locais. Todos os componentes são processos Python locais.

---

# Instalação

## 1. Clonar o repositório

```bash
git clone https://github.com/KleitonEwerton/Auditing-Technical-Security-Debt-through-Retrieval-AugmentedGeneration.git
cd Auditing-Technical-Security-Debt-through-Retrieval-AugmentedGeneration
```

## 2. Criar e ativar ambiente virtual Python

```bash
# Criar o ambiente virtual
python -m venv venv

# Ativar no Linux/macOS
source venv/bin/activate

# Ativar no Windows (PowerShell)
.\venv\Scripts\Activate.ps1
```

## 3. Instalar dependências

```bash
pip install -r requirements.txt
```

> A primeira execução pode demorar alguns minutos pois o modelo de embeddings `sentence-transformers/all-MiniLM-L6-v2` (~90 MB) é baixado automaticamente do HuggingFace Hub.

## 4. Configurar variáveis de ambiente

> **Para reproduzir as reivindicações do artigo a partir dos resultados já entregues, este passo é opcional.** A chave de API só é necessária para re-gerar os resultados.

Copie o arquivo de exemplo e preencha com sua chave Groq:

```bash
cp example.env .env
```

Edite o arquivo `.env`:

```
GROQ_API_KEY=sua_chave_groq_aqui
```

---

# Teste mínimo

Este teste verifica que o ambiente está corretamente instalado executando os dois scripts de análise que **não dependem de API externa** e que recalculam as métricas principais a partir dos resultados já entregues.

## Passo 1 — Verificar comparação LLM vs RAG

```bash
python 06_comparar_resultados_llm_rag.py
```

**Saída esperada (em menos de 10 segundos):**

```
================================================================================
📊 COMPARAÇÃO LLM vs RAG
================================================================================
LLM  - CWE Accuracy: 70.44% | STRIDE Coverage: 100.00%
RAG  - CWE Accuracy: 90.88% | STRIDE Coverage: 100.00%
DELTA - CWE Accuracy: +20.44 pp | STRIDE Coverage: +0.00 pp
Melhor em CWE: RAG
Melhor em STRIDE: Empate

📁 Relatório salvo em: comparacao_llm_vs_rag.json
```

## Passo 2 — Verificar teste de McNemar

```bash
python 07_mcnemar_test.py
```

**Saída esperada (em menos de 60 segundos):**

```json
{
  "total_alinhados": 548,
  "both_correct": 386,
  "llm_only_correct": 0,
  "rag_only_correct": 112,
  "both_wrong": 50,
  "discordant_b": 0,
  "discordant_c": 112,
  "exact_two_sided_p": 3.85e-34,
  ...
}
```

Se ambos os scripts produzirem saídas similares às acima, o ambiente está funcionando corretamente.

---

# Experimentos

Esta seção descreve como reproduzir as três reivindicações principais do artigo. Os resultados podem ser reproduzidos de **duas formas**:

- **Forma A (rápida, sem API):** A partir dos arquivos de resultados já entregues (`resultados_rag.json` e `resultados_llm.json`). Tempo estimado: < 2 minutos no total.
- **Forma B (completa, requer API Groq):** Re-executando os pipelines RAG e LLM do zero contra os 548 casos de teste. Tempo estimado: 2–4 horas (rate limiting da API Groq gratuita).

> **Recomendação para revisores:** Use a **Forma A** para verificar as reivindicações. A Forma B é fornecida para transparência metodológica completa.

---

## Reivindicação #1 — Acurácia RAG 90.88% vs LLM 70.44% (delta +20.44 pp)

**Arquivo de configuração relevante:** nenhum — opera sobre os resultados já entregues.

**Comando (Forma A):**

```bash
python 06_comparar_resultados_llm_rag.py
```

**Arquivo de saída:** `comparacao_llm_vs_rag.json`

**Resultado esperado:**

```
LLM  - CWE Accuracy: 70.44% | STRIDE Coverage: 100.00%
RAG  - CWE Accuracy: 90.88% | STRIDE Coverage: 100.00%
DELTA - CWE Accuracy: +20.44 pp
Melhor em CWE: RAG
```

**Recursos necessários:** < 100 MB RAM, < 10 segundos de execução.

**Comando (Forma B — re-geração completa):**

```bash
# Passo B.1: Construir a base de conhecimento RAG (requer ~8 GB RAM, ~10 min)
python 01_construir_base_conhecimento.py

# Passo B.2: Executar baseline LLM-only (requer GROQ_API_KEY, ~2h)
python 02_retreinar_stride_baseline.py

# Passo B.3: Executar pipeline RAG (requer GROQ_API_KEY + vectorstore_db/, ~2h)
python 02_retreinar_stride.py

# Passo B.4: Comparar resultados
python 06_comparar_resultados_llm_rag.py
```

> Os scripts B.2 e B.3 incluem salvamento automático após cada predição e suporte a retomada (`s/n`), permitindo interromper e continuar a execução.

---

## Reivindicação #2 — F1-score ponderado de 0.9142 (configuração RAG)

**Arquivo de configuração:** nenhum — opera sobre `resultados_rag.json` já entregue.

**Comando:**

```bash
python 04_analise_avancada.py --input resultados_rag.json --output analise_rag_avancada.json
```

**Arquivo de saída:** `analise_rag_avancada.json`

**Resultado esperado (trecho do terminal e do JSON de saída):**

```
✓ Carregados 548 resultados
...
✅ ANÁLISE AVANÇADA CONCLUÍDA!
📁 Relatório salvo em: analise_rag_avancada.json
```

O campo `weighted_avg.f1-score` no JSON de saída corresponde ao F1-score ponderado de **0.9142** reportado no artigo.

**Recursos necessários:** < 500 MB RAM (numpy + scikit-learn), < 30 segundos de execução.

Para comparar com o baseline LLM:

```bash
python 04_analise_avancada.py --input resultados_llm.json --output analise_llm_avancada.json
```

---

## Reivindicação #3 — Significância estatística via McNemar (p = 3.85 × 10⁻³⁴)

**Arquivo de configuração:** nenhum — opera sobre os resultados já entregues.

**Comando:**

```bash
python 07_mcnemar_test.py --llm resultados_llm.json --rag resultados_rag.json --output mcnemar_report.json
```

**Arquivo de saída:** `mcnemar_report.json`

**Resultado esperado:**

```json
{
  "total_alinhados": 548,
  "both_correct": 386,
  "llm_only_correct": 0,
  "rag_only_correct": 112,
  "both_wrong": 50,
  "discordant_b": 0,
  "discordant_c": 112,
  "exact_two_sided_p": 3.85e-34
}
```

**Interpretação:** Com 112 casos em que RAG acertou e LLM errou (e nenhum caso inverso), o teste binomial exato bilateral confirma que a diferença é estatisticamente significativa (p ≈ 3.85 × 10⁻³⁴, muito abaixo de α = 0.05).

**Recursos necessários:** < 100 MB RAM, < 60 segundos de execução.

---

# LICENSE

Este projeto está licenciado sob a licença MIT. Consulte o arquivo [LICENSE](LICENSE) para mais detalhes.

MIT License — Copyright (c) 2026 Kleiton Ewerton de Oliveira, Gleiph Ghiotto Lima de Menezes, André Luiz de Oliveira
