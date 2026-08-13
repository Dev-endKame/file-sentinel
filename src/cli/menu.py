"""
Interface de linha de comando (CLI) do SafeScan.

Orquestra os módulos core através de subcomandos intuitivos,
seguindo o padrão de ferramentas profissionais como git, docker e aws.
"""

import argparse
import logging
import sys
from pathlib import Path

from src.core.scanner import DirectoryScanner
from src.core.hasher import FileHasher
from src.core.duplicate_detector import DuplicateDetector
from src.core.integrity import IntegrityChecker
from src.utils.logger import setup_logger


logger = setup_logger()


def _build_parser() -> argparse.ArgumentParser:
    """
    Constrói o parser de argumentos com subcomandos.

    Returns:
        Parser configurado com todos os subcomandos do SafeScan.
    """
    parser = argparse.ArgumentParser(
        prog="safescan",
        description="SafeScan - Ferramenta de análise de arquivos e integridade forense",
        epilog="Exemplo: python main.py scan --path C:\\Users",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Comandos disponíveis")

    # ─── scan ───
    scan_parser = subparsers.add_parser(
        "scan",
        help="Varre um diretório e lista todos os arquivos encontrados",
    )
    scan_parser.add_argument(
        "--path",
        required=True,
        help="Caminho do diretório a ser varrido",
    )

    # ─── hash ───
    hash_parser = subparsers.add_parser(
        "hash",
        help="Calcula o hash SHA-256 de um arquivo",
    )
    hash_parser.add_argument(
        "--file",
        required=True,
        help="Caminho do arquivo a ser hasheado",
    )

    # ─── duplicates ───
    dup_parser = subparsers.add_parser(
        "duplicates",
        help="Detecta arquivos duplicados em um diretório",
    )
    dup_parser.add_argument(
        "--path",
        required=True,
        help="Caminho do diretório a ser analisado",
    )

    # ─── baseline ───
    base_parser = subparsers.add_parser(
        "baseline",
        help="Gera um baseline de integridade em JSON",
    )
    base_parser.add_argument(
        "--path",
        required=True,
        help="Caminho do diretório a ser monitorado",
    )
    base_parser.add_argument(
        "--output",
        default="reports/safescan_baseline.json",
        help="Caminho do arquivo baseline de saída (padrão: reports/safescan_baseline.json)",
    )

    # ─── verify ───
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verifica integridade de arquivos contra um baseline",
    )
    verify_parser.add_argument(
        "--path",
        required=True,
        help="Caminho do diretório a ser verificado",
    )
    verify_parser.add_argument(
        "--baseline",
        required=True,
        help="Caminho do arquivo baseline JSON",
    )

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    """Executa o comando scan."""
    scanner = DirectoryScanner(args.path)
    count = 0

    for file_info in scanner.scan():
        count += 1
        print(
            f"[{count}] {file_info.path.name} | "
            f"{file_info.size} bytes | {file_info.extension} | "
            f"{file_info.modified_at.strftime('%Y-%m-%d %H:%M')}"
        )

    print(f"\nTotal de arquivos encontrados: {count}")
    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    """Executa o comando hash."""
    hasher = FileHasher()
    file_path = Path(args.file)

    if not file_path.exists():
        print(f"Erro: arquivo não encontrado: {file_path}", file=sys.stderr)
        return 1

    digest = hasher.hash_file(file_path)
    print(f"Arquivo: {file_path}")
    print(f"Algoritmo: SHA-256")
    print(f"Hash: {digest}")
    return 0


def cmd_duplicates(args: argparse.Namespace) -> int:
    """Executa o comando duplicates."""
    scanner = DirectoryScanner(args.path)
    files = list(scanner.scan())

    if not files:
        print("Nenhum arquivo encontrado.")
        return 0

    detector = DuplicateDetector()
    duplicates = detector.find_duplicates(files)

    if not duplicates:
        print("Nenhuma duplicata encontrada.")
        return 0

    print(f"\n{'='*60}")
    print(f"DUPLICATAS ENCONTRADAS: {len(duplicates)} grupos")
    print(f"{'='*60}")

    for file_hash, paths in duplicates.items():
        print(f"\nHash: {file_hash}")
        print(f"Arquivos ({len(paths)}):")
        for p in paths:
            print(f"  → {p}")

    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    """Executa o comando baseline."""
    checker = IntegrityChecker()
    baseline_path = checker.generate_baseline(args.path, args.output)
    print(f"Baseline gerado com sucesso: {baseline_path}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Executa o comando verify."""
    checker = IntegrityChecker()
    result = checker.verify_integrity(args.path, args.baseline)

    print(f"\n{'='*60}")
    print(result.summary())
    print(f"{'='*60}")

    if result.is_clean:
        print("✅ Sistema limpo. Nenhuma anomalia detectada.")
        return 0

    if result.modified:
        print(f"\n🚨 ARQUIVOS MODIFICADOS ({len(result.modified)}):")
        for item in result.modified:
            print(f"  → {item['path']}")
            print(f"    Esperado: {item['expected_hash'][:16]}...")
            print(f"    Atual:    {item['current_hash'][:16]}...")

    if result.new:
        print(f"\n🆕 ARQUIVOS NOVOS ({len(result.new)}):")
        for item in result.new:
            print(f"  → {item['path']}")

    if result.removed:
        print(f"\n❌ ARQUIVOS REMOVIDOS ({len(result.removed)}):")
        for item in result.removed:
            print(f"  → {item['path']}")

    return 1


def main(argv: list[str] | None = None) -> int:
    """
    Entry point da CLI do SafeScan.

    Args:
        argv: Lista de argumentos (padrão: sys.argv).

    Returns:
        Código de saída (0 = sucesso, 1 = erro/anomalia).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    logger.info("Comando executado: %s", args.command)

    commands = {
        "scan": cmd_scan,
        "hash": cmd_hash,
        "duplicates": cmd_duplicates,
        "baseline": cmd_baseline,
        "verify": cmd_verify,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)

    return 1


if __name__ == "__main__":
    sys.exit(main())