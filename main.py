"""
Entry point do SafeScan.
"""

from src.core.scanner import DirectoryScanner
from src.core.duplicate_detector import DuplicateDetector
from src.utils.logger import setup_logger


def main() -> None:
    """Função principal de execução do SafeScan."""
    logger = setup_logger()
    logger.info("=" * 50)
    logger.info("SafeScan - Modo Detecção de Duplicatas")
    logger.info("=" * 50)

    # Varre a pasta de teste
    scanner = DirectoryScanner("test_files")
    files = list(scanner.scan())

    if not files:
        logger.warning("Nenhum arquivo encontrado na pasta de teste")
        return

    # Detecta duplicatas
    detector = DuplicateDetector()
    duplicates = detector.find_duplicates(files)

    # Exibe resultados
    if not duplicates:
        logger.info("Nenhuma duplicata encontrada.")
        return

    logger.info("-" * 50)
    logger.info("RESULTADO: %d grupos de duplicatas encontrados", len(duplicates))

    for file_hash, paths in duplicates.items():
        logger.info("\nHash: %s... (%d arquivos)", file_hash[:16], len(paths))
        for path in paths:
            logger.info("  → %s", path)


if __name__ == "__main__":
    main()