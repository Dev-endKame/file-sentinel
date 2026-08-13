"""
Módulo de logging do SafeScan.

Centraliza a configuração de logs para garantir rastreabilidade
de todas as operações do sistema — essencial para auditoria em
cenários de cibersegurança.
"""

import logging
import sys
from pathlib import Path


def setup_logger(name: str = "safescan") -> logging.Logger:
    """
    Configura e retorna um logger profissional.

    O logger escreve em dois destinos:
    1. Console (stdout) - nível INFO, formato enxuto
    2. Arquivo (logs/safescan.log) - nível DEBUG, formato completo

    Args:
        name: Nome do logger (padrão: 'safescan').

    Returns:
        Instância configurada de logging.Logger.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Evita handlers duplicados se a função for chamada múltiplas vezes
    if logger.handlers:
        return logger

    # Formato detalhado para arquivo (auditoria)
    file_formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Formato enxuto para console (usuário)
    console_formatter = logging.Formatter(
        fmt="[%(levelname)s] %(message)s"
    )

    # Handler de arquivo
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    file_handler = logging.FileHandler(log_dir / "safescan.log", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)

    # Handler de console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger