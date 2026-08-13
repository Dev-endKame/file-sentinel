# Changelog

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/lang/pt-BR/).

## [Unreleased]

## [0.1.4] - 2026-08-13

### Adicionado
- Estrutura modular do projeto (`src/core`, `src/utils`, `src/cli`)
- Sistema de logging profissional com dual handlers (console + arquivo)
- Documentação inicial (`README.md`, `LICENSE`, `CHANGELOG.md`)
- `.gitignore` com exclusões focadas em segurança

- Módulo `src/core/scanner.py` para varredura recursiva de diretórios
- Classe `FileInfo` com metadados (path, size, modified_at, extension)
- Filtro de exclusão de diretórios (pycache, .git, venv, etc.)
- Logging de auditoria para cada arquivo acessado

Módulo `src/core/hasher.py` para cálculo de hashes SHA-256
- Leitura em streaming (chunks de 64KB) para arquivos grandes
- Integração scanner + hasher no entry point

- Módulo `src/core/duplicate_detector.py` para detecção de duplicatas
- Heurística de dois estágios (tamanho → hash) para performance
- Proteção contra DoS por grupos suspeitos de arquivos
- Integração completa scanner → hasher → detector

- Módulo `src/core/integrity.py` para File Integrity Monitoring (FIM)
- Geração de baseline JSON persistente com metadados de auditoria
- Verificação de integridade detectando: intactos, modificados, novos, removidos
- Simulação de ataque no entry point para demonstração forense

- Interface de linha de comando (CLI) profissional com 5 subcomandos
- `scan`, `hash`, `duplicates`, `baseline`, `verify`
- Códigos de saída Unix para integração com scripts e automação