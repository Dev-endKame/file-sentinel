## Sobre

O **File Sentinel** é uma ferramenta de linha de comando (CLI) desenvolvida em Python para análise forense de arquivos. Ela permite:

- **Varredura recursiva** de diretórios com metadados
- **Cálculo de hashes SHA-256** com leitura em streaming (suporta arquivos de qualquer tamanho)
- **Detecção de duplicatas** com heurística de dois estágios (performance O(n))
- **Monitoramento de integridade** (File Integrity Monitoring) com baseline JSON
- **Relatórios exportáveis** em JSON (SIEM) e CSV (Excel/Auditoria)

&gt; Projeto de portfólio demonstrando arquitetura limpa, boas práticas Python, e fundamentos de cibersegurança aplicados.

---

## Instalação 

```bash
# 1. Clone o repositório
git clone https://github.com/Dev-endKame/file-sentinel.git
cd file-sentinel

# 2. Crie e ative o ambiente virtual
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# 3. Instale as dependências
pip install -r requirements.txt

---

```
## Como Usar:

1. Varredura de diretório
Lista todos os arquivos com metadados:

```bash
python main.py scan --path "C:\Users\SeuUsuario\Documents"
Saída esperada:
plain
[1] relatorio.pdf | 245760 bytes | .pdf | 2026-08-13 14:30
[2] foto.jpg | 1048576 bytes | .jpg | 2026-08-12 09:15

Total de arquivos encontrados: 42
Exportar para CSV:
bash
python main.py scan --path "C:\Users\..." --format csv --output relatorio

```

## Cálculo de hash SHA-256:

2. Calcula o hash criptográfico de um arquivo:
```bash
python main.py hash --file "documento_confidencial.pdf"
Saída esperada:
plain
Arquivo: documento_confidencial.pdf
Algoritmo: SHA-256
Hash: a3f5c8d2e1b4... (64 caracteres)

```

## Detecção de duplicatas:

Encontra arquivos idênticos por conteúdo, mesmo com nomes diferentes:
```bash
python main.py duplicates --path "C:\Users\SeuUsuario\Downloads"
Saída esperada:
plain
============================================================
DUPLICATAS ENCONTRADAS: 3 grupos
============================================================

Hash: 7b27bf22958834a0...
Arquivos (4):
  → C:\...\Downloads\relatorio_final.pdf
  → C:\...\Downloads\copia_relatorio.pdf
  → C:\...\Desktop\backup\relatorio_final.pdf

``` 
## Exportar para JSON:
```bash
python main.py duplicates --path "C:\..." --format json --output relatorio
Caso de uso em segurança: Um atacante renomeia malware.exe para notepad.exe e esconde em outra pasta. O SafeScan detecta pelo hash.

```

## Gerar baseline de integridade:

Cria um "retrato" dos arquivos para monitoramento futuro:
```bash
python main.py baseline --path "C:\Windows\System32" --output "baseline_system32.json"
Saída esperada:
plain
Baseline gerado com sucesso: reports\baseline_system32.json

```
## Verificar integridade:
Compara o estado atual contra o baseline:
```bash
python main.py verify --path "C:\Windows\System32" --baseline "baseline_system32.json"

## Saída esperada (sistema limpo):
plain
============================================================
Integridade: 150 intactos, 0 modificados, 0 novos, 0 removidos
============================================================
Sistema limpo. Nenhuma anomalia detectada.
Saída esperada (após ataque):
plain
ARQUIVOS MODIFICADOS (1):
  → C:\Windows\System32\drivers\etc\hosts
    Esperado: 7b27bf22958834a0...
    Atual:    076e9d05c41b1e23...
Exportar relatório:

python main.py verify --path "C:\..." --baseline "baseline.json" --format csv --output auditoria

```
## File Sentinel/
```
├── src/
│   ├── core/               # Regras de negócio (domínio)
│   │   ├── scanner.py       # Varredura de diretórios
│   │   ├── hasher.py        # Cálculo de hashes SHA-256
│   │   ├── duplicate_detector.py  # Detecção de duplicatas
│   │   └── integrity.py     # File Integrity Monitoring (FIM)
│   ├── utils/              # Infraestrutura transversal
│   │   ├── logger.py        # Logging profissional
│   │   └── report_generator.py  # Exportação JSON/CSV
│   └── cli/
│       └── menu.py          # Interface de linha de comando
├── tests/                   # Testes automatizados (pytest)
├── reports/                 # Relatórios gerados
├── docs/                    # Documentação
└── main.py                  # Entry point
```
- Princípios aplicados:
 - SOLID — Single Responsibility (scanner ≠ hasher ≠ detector)
 - Clean Code — Nomes descritivos, funções pequenas, docstrings
 - Fail Fast — Erros são levantados e logados imediatamente
 - Audit Trail — Toda operação é registrada em logs/safescan.log

## Executando os Testes
```bash
python -m pytest tests/ -v
Saída esperada:
plain
tests/test_hasher.py::TestFileHasher::test_hash_file_empty PASSED
tests/test_hasher.py::TestFileHasher::test_hash_file_known_content PASSED
tests/test_hasher.py::TestFileHasher::test_hash_file_nonexistent PASSED
tests/test_hasher.py::TestFileHasher::test_hash_bytes PASSED
4 passed in 0.03s

```
## Casos de Uso em Cibersegurança
```
Planilhas
Cenário	Comando	Objetivo
Investigação forense	duplicates	Encontrar malware replicado em múltiplas pastas
Auditoria de compliance	baseline + verify	Provar que arquivos críticos não foram alterados
Data exfiltration	duplicates	Detectar cópias não-autorizadas de dados sensíveis
Chain of Custody	hash	Gerar hash de evidência digital para tribunal
Monitoramento SOC	verify --format json	Integrar com SIEM via relatório automatizado
```