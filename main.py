"""
Entry point do SafeScan.
"""

from src.core.scanner import DirectoryScanner
from src.utils.logger import setup_logger


def main() -> None:
    """Função principal de execução do SafeScan."""
    logger = setup_logger()
    logger.info("SafeScan iniciado com sucesso.")

    # Varre a pasta src/ do próprio projeto como teste
    scanner = DirectoryScanner("src")
    
    count = 0
    for file_info in scanner.scan():
        count += 1
        logger.info(
            "[%d] %s | %d bytes | %s | %s",
            count,
            file_info.path.name,
            file_info.size,
            file_info.extension,
            file_info.modified_at.strftime("%Y-%m-%d %H:%M"),
        )

    logger.info("Total de arquivos encontrados: %d", count)


if __name__ == "__main__":
    main()