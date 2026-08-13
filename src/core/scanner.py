"""
Módulo de varredura de diretórios do SafeScan.

Responsável por navegar recursivamente pelo filesystem,
coletar metadados de arquivos e retornar uma estrutura
tipada para processamento pelos módulos core.

Em cibersegurança, a varredura precisa ser:
- Não-intrusiva (apenas leitura, nunca escrita)
- Auditável (cada arquivo acessado é logado)
- Resiliente (erros de permissão não quebram o scan inteiro)
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator

from src.utils.logger import setup_logger


logger = setup_logger()


@dataclass(frozen=True)
class FileInfo:
    """
    Representação imutável de um arquivo encontrado durante a varredura.

    Attributes:
        path: Caminho absoluto do arquivo.
        size: Tamanho em bytes.
        modified_at: Data da última modificação.
        extension: Extensão do arquivo (ex: '.py', '.txt').
    """
    path: Path
    size: int
    modified_at: datetime
    extension: str


class DirectoryScanner:
    """
    Scanner profissional de diretórios.

    Implementa o padrão Iterator para permitir processamento
    lazy de grandes volumes de arquivos sem carregar tudo em memória.
    """

    # Diretórios comuns que devem ser ignorados em análise forense
    DEFAULT_EXCLUDES: set[str] = {
        "__pycache__",
        ".git",
        ".venv",
        "venv",
        "node_modules",
        ".pytest_cache",
        ".idea",
        ".vscode",
    }

    def __init__(
        self,
        root_path: str | Path,
        exclude_dirs: set[str] | None = None,
    ) -> None:
        """
        Inicializa o scanner com o diretório raiz.

        Args:
            root_path: Caminho do diretório a ser varrido.
            exclude_dirs: Conjunto de nomes de diretórios a ignorar.
                          Se None, usa DEFAULT_EXCLUDES.
        """
        self.root = Path(root_path).resolve()
        self.exclude_dirs = exclude_dirs or self.DEFAULT_EXCLUDES
        logger.info(
            "DirectoryScanner inicializado para: %s (excluindo: %s)",
            self.root,
            sorted(self.exclude_dirs),
        )

    def _should_skip(self, path: Path) -> bool:
        """
        Verifica se um caminho deve ser ignorado.

        Em cibersegurança, isso evita processar artefatos de sistema
        ou diretórios de ambientes de desenvolvimento.
        """
        # Verifica se algum componente do caminho está na lista de exclusão
        for part in path.parts:
            if part in self.exclude_dirs:
                logger.debug("Ignorando caminho excluído: %s", path)
                return True
        return False

    def scan(self) -> Iterator[FileInfo]:
        """
        Executa a varredura recursiva do diretório raiz.

        Yields:
            FileInfo: Metadados de cada arquivo encontrado.

        Raises:
            ValueError: Se o root_path não for um diretório válido.
        """
        if not self.root.exists():
            raise ValueError(f"Diretório não encontrado: {self.root}")
        if not self.root.is_dir():
            raise ValueError(f"Caminho não é um diretório: {self.root}")

        logger.info("Iniciando varredura em: %s", self.root)

        try:
            for file_path in self.root.rglob("*"):
                if self._should_skip(file_path):
                    continue

                if not file_path.is_file():
                    continue

                try:
                    stat = file_path.stat()
                    info = FileInfo(
                        path=file_path,
                        size=stat.st_size,
                        modified_at=datetime.fromtimestamp(stat.st_mtime),
                        extension=file_path.suffix.lower(),
                    )
                    logger.debug("Arquivo encontrado: %s (%d bytes)", info.path, info.size)
                    yield info

                except (OSError, PermissionError) as exc:
                    logger.warning("Acesso negado ou erro ao ler %s: %s", file_path, exc)
                    continue

        except Exception as exc:
            logger.error("Erro fatal durante varredura: %s", exc)
            raise

        logger.info("Varredura concluída em: %s", self.root)