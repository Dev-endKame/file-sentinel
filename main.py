"""
Entry point do SafeScan.

Responsável por inicializar o sistema e orquestrar a execução
da ferramenta via interface de linha de comando.
"""

from src.utils.logger import setup_logger


def main() -> None:
    """Função principal de execução do SafeScan."""
    logger = setup_logger()
    logger.info("SafeScan iniciado com sucesso.")
    logger.debug("Modo de depuração ativo.")
    logger.info("Aguardando implementação dos módulos core...")


if __name__ == "__main__":
    main()