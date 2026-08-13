"""
Módulo de verificação de integridade de arquivos do SafeScan.

Implementa File Integrity Monitoring (FIM) — técnica essencial
em cibersegurança para detectar alterações não-autorizadas
em arquivos críticos do sistema.

Funcionamento:
1. Gera um baseline JSON com hashes de referência
2. Periodicamente verifica o estado atual contra o baseline
3. Reporta: intactos, modificados, novos e removidos

Em empresas, o baseline deve ser armazenado em mídia
append-only (WORM) ou offline para evitar tampering.
"""

import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Final

from src.core.hasher import FileHasher
from src.core.scanner import DirectoryScanner, FileInfo
from src.utils.logger import setup_logger


logger = setup_logger()

# Nome padrão do arquivo de baseline
DEFAULT_BASELINE_NAME: Final[str] = "safescan_baseline.json"


class IntegrityStatus:
    """Constantes de status para relatórios de integridade."""
    INTACT = "intact"
    MODIFIED = "modified"
    NEW = "new"
    REMOVED = "removed"


@dataclass
class IntegrityResult:
    """
    Resultado consolidado de uma verificação de integridade.

    Attributes:
        scanned_at: Timestamp da verificação.
        root_path: Diretório que foi verificado.
        intact: Arquivos que não mudaram (hash igual).
        modified: Arquivos que existem mas o hash mudou.
        new: Arquivos que não estavam no baseline.
        removed: Arquivos que estavam no baseline mas sumiram.
    """
    scanned_at: str
    root_path: str
    intact: list[dict]
    modified: list[dict]
    new: list[dict]
    removed: list[dict]

    @property
    def is_clean(self) -> bool:
        """Retorna True se nenhuma anomalia foi detectada."""
        return not (self.modified or self.new or self.removed)

    def summary(self) -> str:
        """Retorna um resumo legível do resultado."""
        return (
            f"Integridade: {len(self.intact)} intactos, "
            f"{len(self.modified)} modificados, "
            f"{len(self.new)} novos, "
            f"{len(self.removed)} removidos"
        )


class IntegrityChecker:
    """
    Verificador de integridade de arquivos com baseline persistente.

    Segue o princípio de File Integrity Monitoring (FIM)
    usado em ferramentas como Tripwire e AIDE.
    """

    def __init__(self, hasher: FileHasher | None = None) -> None:
        """
        Inicializa o checker com um hasher opcional.

        Args:
            hasher: Instância de FileHasher. Se None, cria um padrão.
        """
        self.hasher = hasher or FileHasher()
        logger.info("IntegrityChecker inicializado")

    def generate_baseline(
        self,
        root_path: str | Path,
        output_path: str | Path | None = None,
    ) -> Path:
        """
        Gera um baseline JSON com hashes de referência.

        Args:
            root_path: Diretório a ser monitorado.
            output_path: Caminho do arquivo JSON de saída.
                         Se None, salva na pasta reports/.

        Returns:
            Caminho do arquivo baseline gerado.
        """
        root = Path(root_path).resolve()
        output = Path(output_path) if output_path else Path("reports") / DEFAULT_BASELINE_NAME

        logger.info("Gerando baseline para: %s", root)
        logger.info("Destino do baseline: %s", output)

        scanner = DirectoryScanner(root)
        baseline: dict[str, dict] = {}

        for file_info in scanner.scan():
            try:
                file_hash = self.hasher.hash_file(file_info.path)
                baseline[str(file_info.path)] = {
                    "hash": file_hash,
                    "size": file_info.size,
                    "modified_at": file_info.modified_at.isoformat(),
                }
                logger.debug("Baseline | %s | %s", file_info.path.name, file_hash[:16])
            except Exception as exc:
                logger.error("Falha ao adicionar %s ao baseline: %s", file_info.path, exc)
                continue

        # Adiciona metadados do baseline
        baseline_data = {
            "generated_at": datetime.now().isoformat(),
            "root_path": str(root),
            "algorithm": self.hasher.algorithm,
            "total_files": len(baseline),
            "files": baseline,
        }

        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as f:
            json.dump(baseline_data, f, indent=2, ensure_ascii=False)

        logger.info("Baseline gerado: %d arquivos em %s", len(baseline), output)
        return output

    def verify_integrity(
        self,
        root_path: str | Path,
        baseline_path: str | Path,
    ) -> IntegrityResult:
        """
        Verifica o estado atual dos arquivos contra um baseline.

        Args:
            root_path: Diretório a ser verificado.
            baseline_path: Caminho do arquivo baseline JSON.

        Returns:
            IntegrityResult com a análise completa.
        """
        root = Path(root_path).resolve()
        baseline_file = Path(baseline_path)

        logger.info("Verificando integridade de: %s", root)
        logger.info("Usando baseline: %s", baseline_file)

        if not baseline_file.exists():
            raise ValueError(f"Baseline não encontrado: {baseline_file}")

        with baseline_file.open("r", encoding="utf-8") as f:
            baseline_data = json.load(f)

        baseline_files: dict[str, dict] = baseline_data.get("files", {})
        logger.info("Baseline contém %d arquivos de referência", len(baseline_files))

        # Varre o diretório atual
        scanner = DirectoryScanner(root)
        current_files: dict[str, FileInfo] = {
            str(f.path): f for f in scanner.scan()
        }

        # Containers para o resultado
        intact: list[dict] = []
        modified: list[dict] = []
        new_files: list[dict] = []
        removed: list[dict] = []

        # Verifica arquivos do baseline (intactos, modificados ou removidos)
        for path_str, baseline_info in baseline_files.items():
            path = Path(path_str)

            if path_str not in current_files:
                # Arquivo sumiu
                removed.append({
                    "path": path_str,
                    "expected_hash": baseline_info["hash"],
                    "status": IntegrityStatus.REMOVED,
                })
                logger.warning("ARQUIVO REMOVIDO: %s", path_str)
                continue

            current_info = current_files[path_str]

            try:
                current_hash = self.hasher.hash_file(path)
            except Exception as exc:
                logger.error("Erro ao calcular hash de %s: %s", path, exc)
                continue

            if current_hash == baseline_info["hash"]:
                intact.append({
                    "path": path_str,
                    "hash": current_hash,
                    "status": IntegrityStatus.INTACT,
                })
                logger.debug("INTACTO: %s", path.name)
            else:
                modified.append({
                    "path": path_str,
                    "expected_hash": baseline_info["hash"],
                    "current_hash": current_hash,
                    "status": IntegrityStatus.MODIFIED,
                })
                logger.warning(
                    "ARQUIVO MODIFICADO: %s | esperado: %s... | atual: %s...",
                    path.name,
                    baseline_info["hash"][:16],
                    current_hash[:16],
                )

        # Verifica arquivos novos (estão no disco mas não no baseline)
        for path_str, file_info in current_files.items():
            if path_str not in baseline_files:
                try:
                    file_hash = self.hasher.hash_file(file_info.path)
                    new_files.append({
                        "path": path_str,
                        "hash": file_hash,
                        "size": file_info.size,
                        "status": IntegrityStatus.NEW,
                    })
                    logger.warning("ARQUIVO NOVO: %s (%d bytes)", path.name, file_info.size)
                except Exception as exc:
                    logger.error("Erro ao hash de novo arquivo %s: %s", path_str, exc)

        result = IntegrityResult(
            scanned_at=datetime.now().isoformat(),
            root_path=str(root),
            intact=intact,
            modified=modified,
            new=new_files,
            removed=removed,
        )

        logger.info(result.summary())
        return result