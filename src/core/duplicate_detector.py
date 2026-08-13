"""
Módulo de detecção de arquivos duplicados do SafeScan.

Implementa heurística de dois estágios para encontrar arquivos
idênticos por conteúdo, mesmo que tenham nomes ou localizações
diferentes.

Estágio 1: Agrupa por tamanho (filtro determinístico de custo zero)
Estágio 2: Calcula hash SHA-256 apenas nos grupos com 2+ arquivos

Em cibersegurança forense, esta técnica é usada para:
- Identificar malware replicado em múltiplas pastas
- Detectar exfiltração de dados (cópias não autorizadas)
- Reduzir volume de evidências (deduplicação)
"""

import logging
from collections import defaultdict
from pathlib import Path
from typing import Final

from src.core.hasher import FileHasher
from src.core.scanner import FileInfo
from src.utils.logger import setup_logger


logger = setup_logger()

# Limite de segurança: grupos com mais de este número de arquivos
# geram warning (possível ataque de DoS por milhões de arquivos de 1 byte)
MAX_GROUP_SIZE_WARNING: Final[int] = 10_000


class DuplicateDetector:
    """
    Detector de duplicatas com heurística de dois estágios.

    Otimizado para performance em volumes grandes de dados
    sem comprometer a precisão forense.
    """

    def __init__(self, hasher: FileHasher | None = None) -> None:
        """
        Inicializa o detector com um hasher opcional.

        Args:
            hasher: Instância de FileHasher. Se None, cria um padrão.
        """
        self.hasher = hasher or FileHasher()
        logger.info("DuplicateDetector inicializado")

    def find_duplicates(
        self,
        files: list[FileInfo],
    ) -> dict[str, list[Path]]:
        """
        Encontra arquivos duplicados por conteúdo.

        Heurística de dois estágios:
        1. Agrupa por tamanho (O(n), custo zero)
        2. Hash SHA-256 apenas nos grupos com 2+ arquivos (O(k), k << n)

        Args:
            files: Lista de FileInfo retornada pelo scanner.

        Returns:
            Dict onde a chave é o hash SHA-256 e o valor é uma lista
            de caminhos de arquivos com aquele conteúdo.
            Apenas hashes com 2+ arquivos são incluídos.

        Raises:
            ValueError: Se a lista de arquivos estiver vazia.
        """
        if not files:
            raise ValueError("Lista de arquivos não pode estar vazia")

        logger.info("Iniciando detecção de duplicatas em %d arquivos", len(files))

        # ─── ESTÁGIO 1: Agrupamento por tamanho ───
        size_groups: defaultdict[int, list[FileInfo]] = defaultdict(list)

        for file_info in files:
            size_groups[file_info.size].append(file_info)

        logger.debug("Grupos por tamanho formados: %d grupos únicos", len(size_groups))

        # ─── ESTÁGIO 2: Hash apenas nos candidatos ───
        hash_groups: defaultdict[str, list[Path]] = defaultdict(list)

        candidates_found = 0
        for size, group in size_groups.items():
            if len(group) < 2:
                continue  # Arquivo único em tamanho = nunca duplicata

            if len(group) > MAX_GROUP_SIZE_WARNING:
                logger.warning(
                    "Grupo suspeito: %d arquivos de %d bytes. Possível ataque DoS?",
                    len(group),
                    size,
                )

            candidates_found += len(group)
            logger.debug(
                "Grupo de tamanho %d bytes: %d candidatos a duplicata",
                size,
                len(group),
            )

            for file_info in group:
                try:
                    file_hash = self.hasher.hash_file(file_info.path)
                    hash_groups[file_hash].append(file_info.path)
                except Exception as exc:
                    logger.error(
                        "Falha ao calcular hash de %s: %s",
                        file_info.path,
                        exc,
                    )
                    continue

        logger.info(
            "Candidatos analisados: %d | Grupos de hash formados: %d",
            candidates_found,
            len(hash_groups),
        )

        # ─── Filtra apenas hashes com 2+ arquivos ───
        duplicates = {
            h: paths for h, paths in hash_groups.items() if len(paths) >= 2
        }

        total_dupes = sum(len(paths) for paths in duplicates.values())
        unique_hashes = len(duplicates)

        logger.info(
            "Duplicatas encontradas: %d arquivos em %d grupos únicos",
            total_dupes,
            unique_hashes,
        )

        return duplicates