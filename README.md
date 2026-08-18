# Auditoria de Dívida de Segurança Técnica via Recuperação Aumentada por Geração (RAG)

Este artefato acompanha o artigo *"Auditing Technical Security Debt through Retrieval-Augmented Generation: A CWE-, CAPEC-, and STRIDE-Based Approach"*, que propõe uma abordagem neuro-simbólica para auditoria de vulnerabilidades em código Java, integrando LLMs, RAG e ontologias de segurança (CWE → CAPEC → STRIDE). O artefato contém o dataset derivado do OWASP Benchmark v1.2 (2.740 amostras), a base de conhecimento vetorial (ChromaDB), os resultados experimentais completos (548 predições de cada configuração) e os scripts de análise estatística que reproduzem as três reivindicações principais do artigo: acurácia RAG de 90,88% vs. 70,44% do baseline LLM-only (+20,44 pp), F1-score ponderado de 0,9142, e significância estatística confirmada pelo teste de McNemar (p = 3,85 × 10⁻³⁴).

**Autores:**
- Kleiton Ewerton de Oliveira - kleitonewertonoliveira@gmail.com
- Gleiph Ghiotto Lima de Menezes - gleiph.ghiotto@ufjf.br
- André Luiz de Oliveira - andre.oliveira@ufjf.br

## Resumo

A Dívida de Segurança Técnica (TSD, do ingles *Technical Security Debt*) refere-se a vulnerabilidades latentes que podem não comprometer imediatamente a funcionalidade do software, mas que progressivamente enfraquecem suas defesas. As ferramentas convencionais de Teste Estatico de Segurança de Aplicacao (SAST) fornecem a base para a deteccao de vulnerabilidades e permanecem essenciais nos fluxos de desenvolvimento seguro. No entanto, camadas semânticas complementares podem apoiar a contextualizacao dos achados em termos de fluxos de dados, padroes de ataque e impacto arquitetural. Neste artigo, propomos uma abordagem neuro-simbolica para auditoria de TSD integrando Grandes Modelos de Linguagem (LLMs), Geração Aumentada por Recuperação (RAG) e ontologias de seguranca. Nossa abordagem utiliza a cadeia CWE -> CAPEC -> STRIDE como estrutura de suporte para vincular fraquezas no nivel de implementação a padroes de ataque e hipoteses preliminares de ameacas arquiteturais. Utilizamos o OWASP Benchmark v1.2 - um dataset com 2.740 amostras de codigo Java - e construímos um pipeline que enriquece fragmentos de codigo com metadados ontologicos e recupera exemplos semânticamente similares durante a inferência. A configuração assistida por RAG alcancou **90,88% de acuracia** e um F1-score ponderado de **0,9142** na classificacao CWE, superando um baseline LLM-only em **20,44 pontos percentuais** de acuracia. Um teste de McNemar pareado confirmou que essa melhoria foi estatísticamente significativa (p = 3,85 x 10^-34). Os resultados indicam que a recuperação e o ancoramento ontologico podem reduzir a deriva semântica na auditoria de vulnerabilidades, enquanto o mapeamento de ameacas baseado em STRIDE deve ser interpretado como uma camada de contextualizacao preliminar, e não como um oraculo definitivo de modelagem de ameacas.

---

# Estrutura do README

Este README esta organizado conforme o modelo mínimo obrigatorio do SBSeg 2026:

- [Estrutura do README](#estrutura-do-readme) - organização deste documento e do repositório
- [Selos Considerados](#selos-considerados) - selos solicitados para avaliação
- [Informações Básicas](#informações-básicas) - ambiente de execução, hardware e software
- [Dependências](#dependências) - bibliotecas e versões necessárias
- [Preocupações com Segurança](#preocupações-com-seguranca) - riscos e cuidados durante a execução
- [Instalação](#instalação) - passo a passo para configurar o ambiente
- [Teste Mínimo](#teste-mínimo) - verificação rapida de funcionamento
- [Experimentos](#experimentos) - reprodução das reivindicações do artigo
- [LICENSE](#license) - licenca do projeto

### Estrutura do Repositório

```
.
|-- 00_gerar_dataset_final.py          # ETL opcional - veja nota (*) abaixo
|-- 01_construir_base_conhecimento.py  # Vetoriza dados de treino e persiste no ChromaDB
|-- 02_retreinar_stride.py             # Executa o pipeline RAG + LLM (gera resultados_rag.json)
|-- 02_retreinar_stride_baseline.py    # Executa o pipeline LLM-only / baseline (gera resultados_llm.json)
|-- 03_analisar_resultados.py          # Analise basica de resultados individuais
|-- 04_analise_avancada.py             # Métricas avançadas: F1, matriz de confusão, analise de erros
|-- 05_reprocessar_resultados.py       # Reprocessa/corrige resultados ja gerados
|-- 06_comparar_resultados_llm_rag.py  # Compara accuracy LLM vs RAG -> comparacao_llm_vs_rag.json
|-- 07_mcnemar_test.py                 # Teste estatístico de McNemar -> mcnemar_report.json
|-- 08_analise_similaridade_treino_teste.py  # Analise TF-IDF de similaridade entre partições
|-- reproduce_forma_a.py               # Automação da Forma A (reproduz as 3 reivindicações)
|-- dataset_completo_mestrado.jsonl    # Dataset completo OWASP Benchmark v1.2 (2.740 exemplos)
|-- dataset_teste_reservado.jsonl      # 20% reservados para teste (548 exemplos)
|-- dataset_treino.jsonl               # Placeholder - dados de treino estão vetorizados em vectorstore_db/
|-- expectedresults-1.2.csv            # Ground truth do OWASP Benchmark v1.2
|-- cwec_v4.18.xml                     # Common Weakness Enumeration v4.18 (MITRE)
|-- capec_v3.9.xml                     # Common Attack Pattern Enumeration v3.9 (MITRE)
|-- resultados_llm.json                # Resultados gerados pelo baseline LLM-only (548 casos)
|-- resultados_rag.json                # Resultados gerados pelo pipeline RAG (548 casos)
|-- analise_llm.json                   # Analise basica dos resultados LLM
|-- analise_rag.json                   # Analise basica dos resultados RAG
|-- analise_llm_avancada.json          # Métricas avançadas do LLM (F1, matriz de confusao)
|-- analise_rag_avancada.json          # Métricas avançadas do RAG (F1, matriz de confusao)
|-- analise_avancada_metricas.json     # Métricas avançadas consolidadas
|-- comparacao_llm_vs_rag.json         # Comparação lado a lado LLM vs RAG
|-- mcnemar_report.json                # Resultado do teste de McNemar
|-- example.env                        # Exemplo de arquivo de variaveis de ambiente
|-- requirements.txt                   # Dependências Python com versões exatas
|-- LICENSE                            # Licenca MIT
`-- README.md                          # Este arquivo
```

> **(*) Nota sobre `00_gerar_dataset_final.py`:** Este script e **opcional** e **NÃO deve ser executado dentro deste repositório**. Ele foi utilizado para gerar o `dataset_completo_mestrado.jsonl` a partir do repositório [OWASP BenchmarkJava v1.2](https://github.com/OWASP-Benchmark/BenchmarkJava), e deve ser copiado para a **raiz daquele repositório** caso seja necessário regenerar o dataset. Veja detalhes na secao [Sobre o dataset](#sobre-o-dataset-owasp-benchmark-v12).

---

**Tabela de scripts - entradas, saídas e finalidade:**

| Script | Entrada | Saída | Finalidade | Reivindicação |
|---|---|---|---|---|
| `00_gerar_dataset_final.py` | Executar na raiz do [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava): arquivos `.java` em `src/main/java/.../testcode/`, `expectedresults-1.2.csv`, `cwec_v4.18.xml`, `capec_v3.9.xml` | `dataset_completo_mestrado.jsonl` | ETL **opcional**: extrai, enriquece e serializa o dataset. **Nao e necessario para replicação** (dataset ja incluso) | - |
| `01_construir_base_conhecimento.py` | `dataset_completo_mestrado.jsonl` | `vectorstore_db/` (ChromaDB), `dataset_teste_reservado.jsonl` | Vetoriza e indexa 80% dos dados para uso pelo RAG | - |
| `02_retreinar_stride.py` | `vectorstore_db/`, `dataset_teste_reservado.jsonl`, API Groq | `resultados_rag.json` | Executa o pipeline RAG + LLM sobre os 548 casos de teste. **Nao e necessario para replicação** (resultados ja inclusos) | #1, #2 |
| `02_retreinar_stride_baseline.py` | `dataset_teste_reservado.jsonl`, API Groq | `resultados_llm.json` | Executa o baseline LLM-only sobre os 548 casos de teste. **Nao e necessario para replicação** (resultados ja inclusos) | #1 |
| `03_analisar_resultados.py` | `resultados_rag.json` ou `resultados_llm.json` | Saída no terminal | Analise rapida de resultados individuais | - |
| `04_analise_avancada.py` | `resultados_rag.json` ou `resultados_llm.json` | `analise_avancada_metricas.json` (padrão) | F1-score ponderado, matriz de confusão, analise de erros, concordância STRIDE | #2 |
| `05_reprocessar_resultados.py` | `resultados_rag.json` ou `resultados_llm.json` | Arquivo de resultados corrigido | Reprocessa apenas itens com JSON inválido, `erro` ou `raw_response`. Suporta `--mode rag|llm|auto` | - |
| `06_comparar_resultados_llm_rag.py` | `resultados_llm.json`, `resultados_rag.json` | `comparacao_llm_vs_rag.json` | Compara accuracy e STRIDE Response Rate lado a lado | #1 |
| `07_mcnemar_test.py` | `resultados_llm.json`, `resultados_rag.json` | `mcnemar_report.json` | Teste estatístico pareado de McNemar | #3 |
| `08_analise_similaridade_treino_teste.py` | `dataset_completo_mestrado.jsonl`, `dataset_teste_reservado.jsonl` | `analise_similaridade_treino_teste.json` | Analise TF-IDF de deduplicacão/similaridade entre partições | - |
| `reproduce_forma_a.py` | `resultados_rag.json`, `resultados_llm.json` | Relatório consolidado no terminal | Automação da Forma A: executa scripts 04, 06 e 07 em sequência e verifica valores esperados | #1, #2, #3 |

### Reprocessamento obrigatório quando houver erro nos resultados (Condicional)
Esse passo é necessário apenas para avaliação completa com novos resultados,  para o testes mínimos e replicação dos resultados, não é necessário.
Se houver qualquer erro no JSON de resultados (por exemplo, `erro`, `error`, `raw_response` ou resposta fora do formato esperado), **o reprocessamento deve ser executado antes de qualquer análise**.

O script `05_reprocessar_resultados.py` **não reexecuta todo o pipeline**. Ele identifica somente os casos inválidos e reprocessa apenas estes itens usando o banco vetorial ChromaDB e uma nova chamada ao LLM.

- Ele considera como inválidos itens com:
  - `erro` preenchido;
  - `resultado_llm` com `error == "Resposta não é JSON válido"`;
  - `resultado_llm` contendo `raw_response`;
  - respostas fora do formato JSON esperado.
- Casos já válidos são preservados exatamente como estão no arquivo original.
- Para facilitar o uso, se `--output` não for informado, o script gera automaticamente `<arquivo_entrada>_reprocessado.json`.
- Se desejar substituir diretamente o arquivo original, use `--overwrite-input`.

**Modo de reprocessamento (`--mode`):** O script detecta automaticamente se o arquivo de entrada é do pipeline RAG ou do baseline LLM-only pelo nome do arquivo, e usa o prompt e a configuração corretos para cada caso. Use `--mode rag`, `--mode llm` ou `--mode auto` (padrão).

Exemplo de uso para o arquivo do baseline LLM:

```bash
python 05_reprocessar_resultados.py --input resultados_llm.json
# Detecção automática: modo 'llm' (sem contexto RAG, sem ChromaDB)
```

Exemplo equivalente para o pipeline RAG:

```bash
python 05_reprocessar_resultados.py --input resultados_rag.json
# Detecção automática: modo 'rag' (com contexto ChromaDB)
```

Exemplo para sobrescrever o arquivo original (sem etapa manual de renomear):

```bash
python 05_reprocessar_resultados.py --input resultados_llm.json --overwrite-input
```

Se não houver nenhum caso inválido, o script gera um arquivo de saída preservado e confirma que os dados válidos permaneceram inalterados. Assim, a correção fica explicita, reproduzível e auditável para avaliadores e revisores.

---

# Selos Considerados

Os selos considerados sao:

- **Artefatos Disponíveis (SeloD)**
- **Artefatos Funcionais (SeloF)**
- **Artefatos Sustentáveis (SeloS)**
- **Experimentos Reprodutíveis (SeloR)**

---

# Informações Básicas

## Hardware

Os experimentos foram executados em:

- **CPU:** Intel Core i7 (ou equivalente), mínimo 4 cores
- **RAM:** Mínimo 8 GB (recomendado 16 GB para execução completa do pipeline RAG com ChromaDB)
- **Armazenamento:** Mínimo 15 GB livres (datasets + embeddings ChromaDB + modelo Sentence Transformers ~1.3 GB)
- **Internet:** Necessaria para download do modelo de embeddings na primeira execução (`nomic-ai/nomic-embed-text-v1.5`, via HuggingFace Hub) e para chamadas a API Groq

> **Nota para revisores:** Os scripts de analise e comparação (`04_analise_avancada.py`, `06_comparar_resultados_llm_rag.py` e `07_mcnemar_test.py`) **não requerem GPU, API externa nem modelos de embeddings** - operam apenas sobre os arquivos JSON de resultados ja entregues. Para reproduzir as reivindicações do artigo, esses scripts são suficientes e executam em menos de 2 minutos em qualquer maquina com Python.

## Software

| Componente | Versão requerida | Observacao |
|---|---|---|
| Python | >= 3.10 | Testado com Python 3.10 e 3.12 |
| Sistema Operacional | Windows 10/11, Linux (Ubuntu 20.04+) ou macOS 12+ | Sem requisito especifico de OS |
| Git | Qualquer versão recente | Para clonar o repositório |
| Chave de API Groq | - | Necessária **apenas** para re-executar os scripts `02_*`. Gratuita em https://console.groq.com/ |

**Modelo LLM utilizado nos experimentos:** `llama-3.3-70b-versatile` via API Groq, com `temperature=0`.

**Modelo de embeddings utilizado nos experimentos:** `nomic-ai/nomic-embed-text-v1.5` (suporte a contextos de até 8k tokens), carregado via `langchain-huggingface` com `trust_remote_code=True`. Este modelo é declarado na Tabela 1 e na Seção 4.2 do artigo. Os arquivos `resultados_rag.json` foram gerados com este modelo. Os scripts `01_construir_base_conhecimento.py`, `02_retreinar_stride.py` e `05_reprocessar_resultados.py` estão alinhados com este modelo.

### Obtendo a chave de API Groq (opcional)

A chave Groq e gratuita e pode ser obtida em: https://console.groq.com/

> A chave e necessária **apenas** se voce deseja re-gerar os resultados experimentais executando `02_retreinar_stride.py` e/ou `02_retreinar_stride_baseline.py`. Para reproduzir as tres reivindicações do artigo a partir dos artefatos ja entregues, **a chave não e necessária**.

---

# Dependências

## Dependências Python

Todas as dependências estão listadas em [`requirements.txt`](requirements.txt). Instale via:

```bash
pip install -r requirements.txt
```

| Pacote | Versão exata | Finalidade |
|---|---|---|
| `langchain` | 1.3.15 | Framework de orquestracao LLM |
| `langchain-core` | 1.5.4 | Componentes base do LangChain |
| `langchain-chroma` | 1.1.0 | Integracao ChromaDB com LangChain |
| `langchain-huggingface` | 1.2.2 | Integracao HuggingFace Embeddings |
| `langchain-groq` | 1.1.3 | Integracao com a API Groq |
| `langchain-text-splitters` | 1.1.2 | Divisão de documentos em chunks |
| `chromadb` | 1.5.9 | Banco de vetores persistente |
| `sentence-transformers` | 5.7.0 | Biblioteca para carregar o modelo `nomic-ai/nomic-embed-text-v1.5` |
| `python-dotenv` | 1.2.2 | Carregamento de variaveis de ambiente |
| `tqdm` | 4.70.0 | Barras de progresso |
| `numpy` | 2.5.2 | Computacao numerica (`04_analise_avancada.py`) |
| `scikit-learn` | 1.9.0 | Métricas de classificacao: F1, matriz de confusão (`04_analise_avancada.py`, `08_analise_similaridade_treino_teste.py`) |

> **Nota:** As versões acima foram fixadas com `==` para garantir reprodutibilidade futura. O modelo de embeddings `nomic-ai/nomic-embed-text-v1.5` é carregado via `sentence-transformers` com `trust_remote_code=True` e requer ~270 MB de download na primeira execução. Os scripts `06_comparar_resultados_llm_rag.py` e `07_mcnemar_test.py` (teste mínimo) usam exclusivamente a biblioteca padrão do Python e **não requerem instalação de dependências externas**.

## Dados externos (ja incluidos no repositório)

Os seguintes arquivos estão incluidos e **não precisam ser baixados ou gerados**:

| Arquivo | Fonte | Descricao |
|---|---|---|
| `dataset_completo_mestrado.jsonl` | Gerado a partir do OWASP Benchmark v1.2 | 2.740 exemplos de codigo Java anotados com CWE, CAPEC e metadados ontologicos |
| `dataset_teste_reservado.jsonl` | Split 20% do dataset completo (seed=42) | 548 exemplos usados nos experimentos de avaliação |
| `expectedresults-1.2.csv` | [OWASP Benchmark Java v1.2](https://github.com/OWASP-Benchmark/BenchmarkJava) | Ground truth oficial do benchmark |
| `cwec_v4.18.xml` | [MITRE CWE v4.18](https://cwe.mitre.org/data/downloads.html) | Definicoes de fraquezas de seguranca |
| `capec_v3.9.xml` | [MITRE CAPEC v3.9](https://capec.mitre.org/data/downloads.html) | Padroes de ataque |
| `resultados_llm.json` | Gerado pelos experimentos | 548 predições do baseline LLM-only |
| `resultados_rag.json` | Gerado pelos experimentos | 548 predições do pipeline RAG |
| `vectorstore_db/` | Gerado por `01_construir_base_conhecimento.py` | Base de conhecimento vetorial (ChromaDB) com os 2.192 exemplos de treino,  Split 80% do dataset completo |

## Sobre o dataset OWASP Benchmark v1.2

O **OWASP Benchmark Java v1.2** contem 2.740 testes unitarios de vulnerabilidade Java, cobrindo 11 categorias de CWE. O dataset completo (`dataset_completo_mestrado.jsonl`) foi gerado a partir dos arquivos `.java` desse benchmark usando o script `00_gerar_dataset_final.py`.

**Divisão dos dados:**
- **Total:** 2.740 exemplos (corresponde ao OWASP Benchmark v1.2 completo)
- **Treino (80%):** 2.192 exemplos - vetorizados e persistidos no `vectorstore_db/` pelo script `01_construir_base_conhecimento.py`
- **Teste (20%):** 548 exemplos - armazenados em `dataset_teste_reservado.jsonl` e utilizados nos experimentos

> A divisão foi feita com `random.seed(42)` para garantir reprodutibilidade. O arquivo `dataset_treino.jsonl` e um *placeholder* (arquivo de referencia vazio): os dados de treino **não são armazenados em formato JSONL**, pois são transformados diretamente em vetores e persistidos no `vectorstore_db/` pelo script `01_construir_base_conhecimento.py`.

### Como o dataset foi gerado (opcional - para regeneracao)

O script `00_gerar_dataset_final.py` e responsavel pelo ETL de geração do dataset. Ele **NÃO deve ser executado dentro deste repositório**. Para regenerar o dataset do zero:

1. Clone o repositório [OWASP BenchmarkJava v1.2](https://github.com/OWASP-Benchmark/BenchmarkJava).
2. Copie para a raiz do BenchmarkJava os arquivos: `00_gerar_dataset_final.py`, `expectedresults-1.2.csv`, `cwec_v4.18.xml` e `capec_v3.9.xml`.
3. Execute `python 00_gerar_dataset_final.py` a partir da raiz do BenchmarkJava.
4. Copie o `dataset_completo_mestrado.jsonl` gerado de volta para a raiz deste repositório.

> Este script usa apenas a biblioteca padrão do Python (sem dependências externas) e pode ser executado com Python 3.10+.

---

# Preocupações com Segurança

- **Chave de API Groq:** A chave de API deve ser armazenada exclusivamente no arquivo `.env` (nunca comitada no repositório). O `.gitignore` ja exclui o arquivo `.env`. Revogue e regenere a chave apos o uso em ambientes compartilhados.

- **Dados de codigo Java:** O dataset contem fragmentos de codigo **propositalmente vulneraveis** do OWASP Benchmark. Esses fragmentos são material de estudo e **não devem ser executados em produção**.

- **API externa (Groq):** Os scripts `02_retreinar_stride.py` e `02_retreinar_stride_baseline.py` enviam fragmentos de codigo Java para a API Groq. Certifique-se de estar ciente das [politicas de privacidade da Groq](https://groq.com/privacy-policy/) antes de executar esses scripts.

- **Sem exposicao de portas:** Este artefato não expoe servicos de rede locais. Todos os componentes são processos Python locais.

- **ChromaDB local:** O banco de vetores `vectorstore_db/` e armazenado localmente e não requer autenticacao.

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

> A primeira execução pode demorar alguns minutos pois o modelo de embeddings `nomic-ai/nomic-embed-text-v1.5` (~270 MB) é baixado automaticamente do HuggingFace Hub na primeira vez que `01_construir_base_conhecimento.py` e executado. Os scripts de analise (`04`, `06`, `07`) não realizam esse download.

## 4. Configurar variaveis de ambiente (opcional)

> **Para reproduzir as reivindicações do artigo a partir dos resultados ja entregues, este passo e opcional.** A chave de API so e necessária para re-gerar os resultados com os scripts `02_*`.

Copie o arquivo de exemplo e preencha com sua chave Groq:

```bash
# Linux/macOS
cp example.env .env

# Windows (PowerShell)
Copy-Item example.env .env
```

Edite o arquivo `.env`, adicionando sua chave ATIVA do groq:

```
GROQ_API_KEY=sua_chave_groq_aqui # https://console.groq.com/keys

# Ajuste conforme o rate limit da sua chave/plano Groq
RATE_LIMIT_PAUSA_ENTRE_REQUISICOES=2
RATE_LIMIT_REQUISICOES_POR_LOTE=10
RATE_LIMIT_PAUSA_LOTE=10

# Opcional: pausa específica do script 05_reprocessar_resultados.py
RATE_LIMIT_REPROCESSAR_PAUSA_ENTRE_REQUISICOES=2
```

### Rate limit da chave Groq (importante)

Cada chave/plano da Groq pode ter limites diferentes (requisições por minuto, tokens por minuto, rajadas e tokens maximos por requisição). **Antes de executar os scripts `02_*` e `05_*`, verifique os limites da sua chave no painel da Groq** e ajuste os parâmetros de rate limit no `.env`.

- `RATE_LIMIT_PAUSA_ENTRE_REQUISICOES`: pausa (em segundos) entre chamadas.
- `RATE_LIMIT_REQUISICOES_POR_LOTE`: quantidade de requisições antes de aplicar pausa maior.
- `RATE_LIMIT_PAUSA_LOTE`: pausa (em segundos) aplicada após cada lote.
- `RATE_LIMIT_REPROCESSAR_PAUSA_ENTRE_REQUISICOES`: pausa específica do reprocessamento (`05_reprocessar_resultados.py`).

Se sua chave estiver sofrendo `429`, `timeout` ou instabilidade, aumente as pausas e/ou reduza o tamanho do lote.

> Observação: no `05_reprocessar_resultados.py`, a flag `--pause` tem prioridade sobre o valor do `.env`.

---

# Teste Mínimo

Este teste verifica que o ambiente esta corretamente instalado executando dois scripts de analise que **não dependem de API externa, GPU ou modelos de embeddings** e que recalculam as métricas principais a partir dos resultados ja entregues.

> **Pre-requisito:** Apenas Python instalado. Nao e necessário sequer o `pip install -r requirements.txt` para este teste mínimo - `python 06_comparar_resultados_llm_rag.py` e `python 07_mcnemar_test.py` usam exclusivamente a biblioteca padrão do Python.

## Passo 1 - Verificar comparação LLM vs RAG

```bash
python 06_comparar_resultados_llm_rag.py
```

**Saída esperada (em menos de 10 segundos):**

```
================================================================================
📊 COMPARAÇÃO LLM vs RAG
================================================================================
LLM  - CWE Accuracy: 70.44% | STRIDE Response Rate: 100.00%
RAG  - CWE Accuracy: 90.88% | STRIDE Response Rate: 100.00%
DELTA - CWE Accuracy: +20.44 pp | STRIDE Response Rate: +0.00 pp
Melhor em CWE: RAG
Melhor em STRIDE: Empate

📁 Relatório salvo em: comparacao_llm_vs_rag.json
```

> **Nota:** A métrica "STRIDE Response Rate" mede a proporção de respostas com classificação STRIDE não-vazia (distinta de "STRIDE Coverage" ou concordância STRIDE). A concordância STRIDE de 75% reportada na Tabela 6 do artigo é calculada pelo script `04_analise_avancada.py`.

## Passo 2 - Verificar teste de McNemar

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
  "exact_two_sided_p": 3.851859888774472e-34,
  "chi2_continuity_corrected_stat": 110.00892857142857,
  "chi2_p_value": 0.0
}
```

Se ambos os scripts produzirem saídas similares as acima, o ambiente esta funcionando corretamente.

---

# Experimentos

Esta secao descreve como reproduzir as tres reivindicações principais do artigo. Os resultados podem ser reproduzidos de **duas formas**:

- **Forma A (rapida, sem API - recomendada para revisores):** A partir dos arquivos de resultados ja entregues (`resultados_rag.json` e `resultados_llm.json`). Tempo estimado: **< 2 minutos** no total. **Nao requer chave de API, GPU ou modelos de embeddings.**
- **Forma B (completa, requer API Groq):** Re-executando os pipelines RAG e LLM do zero contra os 548 casos de teste. Tempo estimado: **2-4 horas** (sujeito ao rate limiting da API Groq gratuita). Inclui suporte a `--limit N` para execução reduzida.

> **Recomendacao para revisores:** Use a **Forma A** para verificar as reivindicações. A Forma B e fornecida para transparência metodologica completa, mas **não e necessaria** para confirmar os resultados do artigo - todos os artefatos intermediarios ja estão disponíveis no repositório.

## Automação da Forma A (script único)

Para reproduzir as três reivindicações em um único comando, execute:

```bash
python reproduce_forma_a.py
```

O script encadeia automaticamente os passos 04, 06 e 07, verifica os valores obtidos contra os esperados e gera um sumário consolidado. Compatível com Windows, Linux e macOS.

---

> **Nota sobre diferenças entre os prompts das configurações LLM-only e RAG:** Os prompts das duas configurações diferem não apenas pela presença do contexto recuperado (`{base_conhecimento}`), mas também no **conteúdo das regras de classificação**. O prompt da configuração RAG (`02_retreinar_stride.py`) contém regras adicionais de desambiguação — incluindo critérios explícitos para CWE-328 vs CWE-327 (MD5/SHA1 vs DES/RC4), gatilhos específicos para `session.setAttribute` (CWE-501), regras detalhadas sobre cookies (CWE-614) e análise do verbo da operação para STRIDE — que não estão presentes de forma equivalente no prompt do baseline (`02_retreinar_stride_baseline.py`). Portanto, a comparação entre as configurações não isola individualmente os efeitos de retrieval, enriquecimento ontológico e restrições de prompt — conforme declarado nas Seções 5.2 e 6 do artigo.

---

## Reivindicação #1 - Acuracia RAG 90,88% vs LLM 70,44% (delta +20,44 pp)

**Arquivo de configuração relevante:** nenhum - opera sobre os resultados ja entregues.

**Comando (Forma A):**

```bash
python 06_comparar_resultados_llm_rag.py
```

**Arquivo de saída:** `comparacao_llm_vs_rag.json`

**Resultado esperado:**

```
LLM  - CWE Accuracy: 70.44% | STRIDE Response Rate: 100.00%
RAG  - CWE Accuracy: 90.88% | STRIDE Response Rate: 100.00%
DELTA - CWE Accuracy: +20.44 pp
Melhor em CWE: RAG
```

**Recursos necessários:** < 100 MB RAM, < 10 segundos de execução, sem dependências externas.

**Comando (Forma B - re-geração completa):**

```bash
# Passo B.1: Construir a base de conhecimento RAG (requer ~8 GB RAM, ~10 min)
python 01_construir_base_conhecimento.py

# Passo B.2: Executar baseline LLM-only (requer GROQ_API_KEY, ~2h)
# Para testar o pipeline fim a fim com poucos casos, use --limit N:
python 02_retreinar_stride_baseline.py --limit 20
# Execução completa:
python 02_retreinar_stride_baseline.py

# Passo B.3: Executar pipeline RAG (requer GROQ_API_KEY + vectorstore_db/, ~2h)
# Para testar o pipeline fim a fim com poucos casos, use --limit N:
python 02_retreinar_stride.py --limit 20
# Execução completa:
python 02_retreinar_stride.py

# Passo B.4: Comparar resultados
python 06_comparar_resultados_llm_rag.py
```

> **IMPORTANTE - Scripts 02 não são necessários para replicação:** Os scripts `02_retreinar_stride.py` e `02_retreinar_stride_baseline.py` **não precisam ser executados** para reproduzir as reivindicações do artigo. Os arquivos `resultados_rag.json` e `resultados_llm.json` ja estão inclusos no repositório e contem os 548 resultados completos dos experimentos originais. Execute esses scripts apenas se quiser re-gerar os resultados do zero por razoes de transparencia metodologica.

> **Variacoes esperadas em novas execuções (Forma B):** LLMs são sistemas **não-deterministicos** - mesmo com o mesmo modelo e prompt, pequenas variacoes nas respostas são esperadas entre execuções distintas. Alem disso, modelos com capacidades superiores ou inferiores ao `llama-3.3-70b-versatile` produzirao resultados diferentes. Portanto, ao re-executar os scripts `02_*`, os valores exatos de acuracia e F1 podem diferir ligeiramente dos reportados no artigo. Isso e esperado e não invalida as conclusoes gerais.

> **Inconsistencias e falhas durante a execução dos scripts 02 (Forma B):** Durante a execução dos pipelines RAG e LLM, podem ocorrer falhas pontuais, incluindo:
>
> - Respostas da LLM **fora do formato JSON esperado** ou **incompletas**
> - **Timeout** na chamada a API (por instabilidade da LLM, da rede ou limites de rate da sua chave de API)
> - Erros de parse que resultam em instâncias marcadas como falhas
>
> **Como proceder em caso de falha:** Os scripts incluem salvamento automatico apos cada predição e suporte a retomada interativa (s/n). Instancias com falha de parse devem ser reprocessadas com `05_reprocessar_resultados.py` usando o arquivo afetado, por exemplo:
>
> ```bash
> python 05_reprocessar_resultados.py --input resultados_llm.json
> ```
>
> O script identifica apenas os itens inválidos, reprocessa somente esses casos com o contexto RAG e salva automaticamente `<arquivo>_reprocessado.json` (ou sobrescreve com `--overwrite-input`, se desejado). Casos já válidos permanecem inalterados, o que torna a correção reproduzível, auditável e compatível com uma revisão por avaliadores.
>
> Para reduzir trabalho manual, os scripts de análise `03`, `04`, `06` e `07` agora interrompem quando detectam erro e orientam o reprocessamento, ou podem automatizar esse passo com a flag `--auto-reprocess`.

---

## Reivindicação #2 - F1-score ponderado de 0,9142 (configuração RAG)

**Arquivo de configuração:** nenhum - opera sobre `resultados_rag.json` ja entregue.

**Comando:**

```bash
python 04_analise_avancada.py --input resultados_rag.json --output analise_rag_avancada.json
```

**Arquivo de saída:** `analise_rag_avancada.json`

**Resultado esperado (trecho do terminal e do JSON de saída):**

```
Carregados 548 resultados
...
ANALISE AVANCADA CONCLUIDA!
Relatorio salvo em: analise_rag_avancada.json
```

O campo `weighted_avg.f1-score` no JSON de saída corresponde ao F1-score ponderado de **0,9142** reportado no artigo.

**Recursos necessários:** < 500 MB RAM (numpy + scikit-learn), < 30 segundos de execução.

Para comparar com o baseline LLM:

```bash
python 04_analise_avancada.py --input resultados_llm.json --output analise_llm_avancada.json
```

---

## Reivindicação #3 - Significancia estatística via McNemar (p = 3,85 x 10^-34)

**Arquivo de configuração:** nenhum - opera sobre os resultados ja entregues.

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

**Interpretacao:** Com 112 casos em que RAG acertou e LLM errou (e nenhum caso inverso), o teste binomial exato bilateral confirma que a diferenca e estatísticamente significativa (p = 3,85 x 10^-34, muito abaixo de alfa = 0,05).

**Recursos necessários:** < 100 MB RAM, < 60 segundos de execução, sem dependências externas.

---

# LICENSE

Este projeto esta licenciado sob a licenca MIT. Consulte o arquivo [LICENSE](LICENSE) para mais detalhes.

MIT License - Copyright (c) 2026 Kleiton Ewerton de Oliveira, Gleiph Ghiotto Lima de Menezes, André Luiz de Oliveira
