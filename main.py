"""
Entry point do SafeScan.
"""

from src.core.scanner import DirectoryScanner
from src.core.hasher import FileHasher
from src.utils.logger import setup_logger


def main() -> None:
    """Função principal de execução do SafeScan."""
    logger = setup_logger()
    logger.info("SafeScan iniciado com sucesso.")

    # 1. Varre a pasta src/
    scanner = DirectoryScanner("src")
    hasher = FileHasher()

    # 2. Calcula hash de cada arquivo encontrado
    for file_info in scanner.scan():
        try:
            file_hash = hasher.hash_file(file_info.path)
            logger.info(
                "[%s] %s | %d bytes | hash: %s",
                file_info.extension or "no-ext",
                file_info.path.name,
                file_info.size,
                file_hash,
            )
        except Exception as exc:
            logger.error("Falha ao processar %s: %s", file_info.path, exc)

    logger.info("Varredura e hashing concluídos.")


if __name__ == "__main__":
    main()