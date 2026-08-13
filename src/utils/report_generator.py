"""
Módulo de geração de relatórios do SafeScan.

Responsável por exportar resultados de análises em formatos
padrão de mercado (JSON e CSV) para auditoria e integração.

Em cibersegurança, relatórios são evidências:
- Devem ser imutáveis após geração
- Devem conter timestamp e metadados
- Devem ser legíveis por humanos e máquinas
"""

import csv
import json
import logging
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from src.utils.logger import setup_logger


logger = setup_logger()


class ReportGenerator:
    """
    Gerador de relatórios forenses em JSON e CSV.

    Segue princípios de cadeia de custódia digital:
    - Timestamp de geração
    - Metadados da ferramenta
    - Formato consistente e validável
    """

    def __init__(self, output_dir: str | Path = "reports") -> None:
        """
        Inicializa o gerador com diretório de saída.

        Args:
            output_dir: Pasta onde os relatórios serão salvos.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info("ReportGenerator inicializado | diretório: %s", self.output_dir)

    def _generate_filename(self, prefix: str, extension: str) -> Path:
        """
        Gera nome de arquivo com timestamp para unicidade.

        Args:
            prefix: Prefixo descritivo (ex: 'scan', 'duplicates').
            extension: Extensão do arquivo (ex: 'json', 'csv').

        Returns:
            Path completo do arquivo.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"safescan_{prefix}_{timestamp}.{extension}"
        return self.output_dir / filename

    def to_json(self, data: dict[str, Any], prefix: str = "report") -> Path:
        """
        Exporta dados para JSON formatado.

        Args:
            data: Dicionário com os dados do relatório.
            prefix: Prefixo do nome do arquivo.

        Returns:
            Caminho do arquivo JSON gerado.
        """
        filepath = self._generate_filename(prefix, "json")

        report = {
            "generated_at": datetime.now().isoformat(),
            "tool": "SafeScan",
            "version": "0.1.0",
            "data": data,
        }

        with filepath.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info("Relatório JSON gerado: %s (%d registros)", filepath, len(data))
        return filepath

    def to_csv(self, rows: list[dict[str, Any]], prefix: str = "report") -> Path:
        """
        Exporta dados para CSV.

        Args:
            rows: Lista de dicionários (cada dict = uma linha).
            prefix: Prefixo do nome do arquivo.

        Returns:
            Caminho do arquivo CSV gerado.

        Raises:
            ValueError: Se a lista estiver vazia.
        """
        if not rows:
            raise ValueError("Lista de registros vazia — não é possível gerar CSV")

        filepath = self._generate_filename(prefix, "csv")

        # Determina colunas a partir das chaves do primeiro registro
        fieldnames = list(rows[0].keys())

        with filepath.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        logger.info("Relatório CSV gerado: %s (%d linhas)", filepath, len(rows))
        return filepath