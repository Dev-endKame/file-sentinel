# Changelog

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/lang/pt-BR/).

## [Unreleased]

## [0.1.1] - 2026-08-13

### Adicionado
- Estrutura modular do projeto (`src/core`, `src/utils`, `src/cli`)
- Sistema de logging profissional com dual handlers (console + arquivo)
- Documentação inicial (`README.md`, `LICENSE`, `CHANGELOG.md`)
- `.gitignore` com exclusões focadas em segurança

- Módulo `src/core/scanner.py` para varredura recursiva de diretórios
- Classe `FileInfo` com metadados (path, size, modified_at, extension)
- Filtro de exclusão de diretórios (pycache, .git, venv, etc.)
- Logging de auditoria para cada arquivo acessado