"""
Entry point do SafeScan — Modo Integridade.
"""

from src.core.integrity import IntegrityChecker
from src.utils.logger import setup_logger


def main() -> None:
    """Demonstração do módulo de integridade do SafeScan."""
    logger = setup_logger()
    logger.info("=" * 60)
    logger.info("SafeScan - Modo Verificação de Integridade")
    logger.info("=" * 60)

    checker = IntegrityChecker()

    # PASSO 1: Gera o baseline da pasta test_files
    logger.info("\n>> PASSO 1: Gerando baseline...")
    baseline_path = checker.generate_baseline("test_files")
    logger.info("Baseline salvo em: %s", baseline_path)

    # PASSO 2: Verifica integridade (ainda nada mudou → deve estar limpo)
    logger.info("\n>> PASSO 2: Verificando integridade imediata...")
    result = checker.verify_integrity("test_files", baseline_path)

    logger.info("Resultado: %s", result.summary())
    logger.info("Sistema limpo? %s", result.is_clean)

    # PASSO 3: Simula uma "invasão" — modifica um arquivo
    logger.info("\n>> PASSO 3: Simulando alteração não-autorizada...")
    target = "test_files/original.txt"
    with open(target, "w") as f:
        f.write("CONTEUDO MALICIOSO ALTERADO PELO ATACANTE\n")

    # PASSO 4: Verifica novamente → deve detectar modificação
    logger.info("\n>> PASSO 4: Verificando integridade após alteração...")
    result = checker.verify_integrity("test_files", baseline_path)

    logger.info("Resultado: %s", result.summary())
    logger.info("Sistema limpo? %s", result.is_clean)

    if result.modified:
        logger.error("🚨 ALERTA DE INTEGRIDADE:")
        for item in result.modified:
            logger.error("   MODIFICADO: %s", item["path"])
            logger.error("   Hash esperado: %s...", item["expected_hash"][:16])
            logger.error("   Hash atual:    %s...", item["current_hash"][:16])

    if result.new:
        logger.error("🆕 ARQUIVOS NOVOS DETECTADOS: %d", len(result.new))

    if result.removed:
        logger.error("❌ ARQUIVOS REMOVIDOS: %d", len(result.removed))


if __name__ == "__main__":
    main()