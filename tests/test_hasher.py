"""
Testes unitários para o módulo FileHasher.

Segue o padrão Arrange-Act-Assert (AAA):
1. Arrange: prepara o cenário
2. Act: executa a ação
3. Assert: verifica o resultado

Em cibersegurança, testes de hash são críticos porque:
- Um bug no hasher invalida toda a cadeia de custódia
- Hashes devem ser determinísticos (mesmo input = mesmo output, sempre)
"""

import hashlib
import tempfile
from pathlib import Path

import pytest

from src.core.hasher import FileHasher


class TestFileHasher:
    """Suite de testes para FileHasher."""

    def test_hash_file_empty(self) -> None:
        """
        Testa hash de arquivo vazio.

        O SHA-256 de uma entrada vazia é um valor fixo e conhecido.
        Se isso mudar, o algoritmo está quebrado.
        """
        # Arrange
        hasher = FileHasher()
        expected = hashlib.sha256(b"").hexdigest()

        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as tmp:
            tmp.write(b"")
            tmp_path = Path(tmp.name)

        # Act
        result = hasher.hash_file(tmp_path)

        # Assert
        assert result == expected
        assert len(result) == 64  # SHA-256 sempre tem 64 caracteres hex

        # Cleanup
        tmp_path.unlink()

    def test_hash_file_known_content(self) -> None:
        """
        Testa hash de arquivo com conteúdo conhecido.

        Verifica determinismo: rodar 2x deve dar o mesmo resultado.
        """
        # Arrange
        hasher = FileHasher()
        content = b"SafeScan test content 12345!@#$%"

        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        # Act
        result1 = hasher.hash_file(tmp_path)
        result2 = hasher.hash_file(tmp_path)

        # Assert
        expected = hashlib.sha256(content).hexdigest()
        assert result1 == expected
        assert result1 == result2  # Determinismo

        # Cleanup
        tmp_path.unlink()

    def test_hash_file_nonexistent(self) -> None:
        """
        Testa comportamento com arquivo inexistente.

        Deve levantar ValueError, não quebrar silenciosamente.
        """
        # Arrange
        hasher = FileHasher()
        fake_path = Path("C:/arquivo_que_nao_existe_12345.txt")

        # Act & Assert
        with pytest.raises(ValueError, match="não encontrado"):
            hasher.hash_file(fake_path)

    def test_hash_bytes(self) -> None:
        """
        Testa hash de dados em memória (bytes).

        Útil para hash de chaves, senhas ou dados já carregados.
        """
        # Arrange
        hasher = FileHasher()
        data = b"test data"

        # Act
        result = hasher.hash_bytes(data)

        # Assert
        expected = hashlib.sha256(data).hexdigest()
        assert result == expected