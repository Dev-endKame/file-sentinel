"""
Módulo de cálculo de hashes do SafeScan.

Responsável por gerar hashes criptográficos (SHA-256) de arquivos
de forma segura e eficiente, mesmo para arquivos de grande volume.

Em cibersegurança, hashes são usados para:
- Integridade de evidências (chain of custody)
- Detecção de malware (comparação com bancos de dados de hashes)
- Verificação de duplicatas (arquivos iguais = hashes iguais)
"""

import hashlib
import logging
from pathlib import Path
from typing import Final

from src.utils.logger import setup_logger


logger = setup_logger()

# Tamanho do buffer de leitura: 64KB é o "sweet spot" para I/O de disco
# Menor que isso = muitas chamadas ao SO (lento)
# Maior que isso = desperdício de memória sem ganho de performance
CHUNK_SIZE: Final[int] = 64 * 1024  # 65.536 bytes


class FileHasher:
    """
    Calculador de hashes criptográficos para arquivos.

    Implementa leitura em streaming para suportar arquivos
    de qualquer tamanho sem estourar a memória RAM.
    """

    def __init__(self, algorithm: str = "sha256") -> None:
        """
        Inicializa o hasher com o algoritmo desejado.

        Args:
            algorithm: Algoritmo de hash (padrão: 'sha256').
                       Suporta todos os algoritmos do hashlib.
        """
        self.algorithm = algorithm
        logger.info("FileHasher inicializado com algoritmo: %s", algorithm)

    def hash_file(self, file_path: str | Path) -> str:
        """
        Calcula o hash criptográfico de um arquivo.

        Lê o arquivo em chunks de 64KB para garantir eficiência
        de memória em arquivos de grande volume.

        Args:
            file_path: Caminho do arquivo a ser hasheado.

        Returns:
            String hexadecimal do hash (64 caracteres para SHA-256).

        Raises:
            ValueError: Se o caminho não for um arquivo válido.
            OSError: Se houver erro de leitura no arquivo.
        """
        path = Path(file_path)

        if not path.exists():
            raise ValueError(f"Arquivo não encontrado: {path}")
        if not path.is_file():
            raise ValueError(f"Caminho não é um arquivo: {path}")

        hasher = hashlib.new(self.algorithm)
        bytes_read = 0

        logger.debug("Iniciando hash de: %s", path.name)

        try:
            with path.open("rb") as file:
                while chunk := file.read(CHUNK_SIZE):
                    hasher.update(chunk)
                    bytes_read += len(chunk)

            digest = hasher.hexdigest()
            logger.info(
                "Hash calculado | arquivo: %s | algoritmo: %s | hash: %s... | bytes lidos: %d",
                path.name,
                self.algorithm,
                digest[:16],  # mostra só os primeiros 16 chars no log (segurança)
                bytes_read,
            )
            return digest

        except OSError as exc:
            logger.error("Erro ao ler arquivo para hash: %s | %s", path, exc)
            raise

    def hash_bytes(self, data: bytes) -> str:
        """
        Calcula o hash de dados em memória (bytes).

        Útil para hash de strings, chaves ou dados já carregados.

        Args:
            data: Dados em formato bytes.

        Returns:
            String hexadecimal do hash.
        """
        hasher = hashlib.new(self.algorithm)
        hasher.update(data)
        return hasher.hexdigest()