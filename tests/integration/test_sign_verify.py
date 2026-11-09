import hashlib
import subprocess
import tempfile
import os

import pytest
from bdfparser import Font

from glyph_sig.core import (
    render_crypto_signature,
    verify_crypto_signature,
    generate_keypair,
    hash_document,
    load_raw_pubkey,
    _build_glyph_grids,
    _count_fill_pixels,
    _payload_palette_len,
    CRYPTO_PAYLOAD_SIZE,
    PALETTES,
)


class TestCryptoSignVerify:
    def test_sign_and_verify(self, font, keypair, document_hash):
        private_pem, _ = keypair
        art = render_crypto_signature("Fred Bloggs", document_hash, private_pem, font, 'alnum')
        valid, pubkey, timestamp = verify_crypto_signature(art, "Fred Bloggs", document_hash, font, 'alnum')
        assert valid
        assert pubkey is not None
        assert timestamp > 0

    def test_wrong_document_fails(self, font, keypair, document_hash):
        private_pem, _ = keypair
        art = render_crypto_signature("Fred Bloggs", document_hash, private_pem, font, 'alnum')
        wrong_hash = hashlib.sha256(b"wrong content").hexdigest()
        valid, _, _ = verify_crypto_signature(art, "Fred Bloggs", wrong_hash, font, 'alnum')
        assert not valid

    def test_wrong_name_fails(self, font, keypair, document_hash):
        private_pem, _ = keypair
        art = render_crypto_signature("Fred Bloggs", document_hash, private_pem, font, 'alnum')
        valid, _, _ = verify_crypto_signature(art, "Jane Smith", document_hash, font, 'alnum')
        assert not valid

    def test_expected_pubkey_match(self, font, keypair, document_hash):
        private_pem, public_pem = keypair
        expected_raw = load_raw_pubkey(public_pem)
        art = render_crypto_signature("Fred Bloggs", document_hash, private_pem, font, 'alnum')
        valid, pubkey, _ = verify_crypto_signature(
            art, "Fred Bloggs", document_hash, font, 'alnum', expected_raw,
        )
        assert valid
        assert pubkey == expected_raw

    def test_expected_pubkey_mismatch(self, font, keypair, document_hash):
        private_pem, _ = keypair
        other_priv, other_pub = generate_keypair()
        other_raw = load_raw_pubkey(other_pub)
        art = render_crypto_signature("Fred Bloggs", document_hash, private_pem, font, 'alnum')
        valid, _, _ = verify_crypto_signature(
            art, "Fred Bloggs", document_hash, font, 'alnum', other_raw,
        )
        assert not valid

    def test_insufficient_pixels_raises(self, font, keypair, document_hash):
        private_pem, _ = keypair
        with pytest.raises(ValueError, match="Not enough fill pixels"):
            render_crypto_signature("A", document_hash, private_pem, font, 'symbols')

    @pytest.mark.parametrize("palette", ['alpha', 'alnum'])
    def test_all_suitable_palettes(self, font, keypair, document_hash, palette):
        private_pem, _ = keypair
        art = render_crypto_signature("Fred Bloggs", document_hash, private_pem, font, palette)
        valid, _, _ = verify_crypto_signature(art, "Fred Bloggs", document_hash, font, palette)
        assert valid

    def test_leading_blank_lines_stripped(self, font, keypair, document_hash):
        private_pem, _ = keypair
        art = render_crypto_signature("Fred Bloggs", document_hash, private_pem, font, 'alnum')
        stripped = '\n'.join(line for line in art.split('\n') if line.strip())
        valid, _, _ = verify_crypto_signature(stripped, "Fred Bloggs", document_hash, font, 'alnum')
        assert valid

    def test_spacing_changes_tolerated(self, font, keypair, document_hash):
        private_pem, _ = keypair
        art = render_crypto_signature("Fred Bloggs", document_hash, private_pem, font, 'alnum')
        import re
        compressed = re.sub(r' {2,}', ' ', art)
        valid, _, _ = verify_crypto_signature(compressed, "Fred Bloggs", document_hash, font, 'alnum')
        assert valid

    def test_timestamp_is_recent(self, font, keypair, document_hash):
        import time
        private_pem, _ = keypair
        before = int(time.time())
        art = render_crypto_signature("Fred Bloggs", document_hash, private_pem, font, 'alnum')
        after = int(time.time())
        valid, _, timestamp = verify_crypto_signature(art, "Fred Bloggs", document_hash, font, 'alnum')
        assert valid
        assert before <= timestamp <= after

    def test_different_keys_produce_different_art(self, font, document_hash):
        priv1, _ = generate_keypair()
        priv2, _ = generate_keypair()
        art1 = render_crypto_signature("Fred Bloggs", document_hash, priv1, font, 'alnum')
        art2 = render_crypto_signature("Fred Bloggs", document_hash, priv2, font, 'alnum')
        assert art1 != art2

    def test_different_documents_produce_different_art(self, font, keypair):
        private_pem, _ = keypair
        hash1 = hashlib.sha256(b"doc one").hexdigest()
        hash2 = hashlib.sha256(b"doc two").hexdigest()
        art1 = render_crypto_signature("Fred Bloggs", hash1, private_pem, font, 'alnum')
        art2 = render_crypto_signature("Fred Bloggs", hash2, private_pem, font, 'alnum')
        assert art1 != art2


class TestCLISignVerify:
    @pytest.fixture
    def cli_env(self, tmp_path):
        priv, pub = generate_keypair()
        key_path = tmp_path / "testkey"
        pub_path = tmp_path / "testkey.pub"
        key_path.write_bytes(priv)
        pub_path.write_bytes(pub)
        doc_path = tmp_path / "doc.txt"
        doc_path.write_text("test document\n")
        return tmp_path, str(key_path), str(pub_path), str(doc_path)

    def _run(self, args):
        result = subprocess.run(
            ['glyph-sig'] + args,
            capture_output=True, text=True,
        )
        return result

    def test_sign_and_verify(self, cli_env):
        tmp_path, key, pub, doc = cli_env
        sig_path = str(tmp_path / "sig.txt")

        result = self._run(['sign', doc, '-n', 'Fred Bloggs', '-k', key, '-p', 'alnum'])
        assert result.returncode == 0
        with open(sig_path, 'w') as f:
            f.write(result.stdout)

        result = self._run(['verify', doc, sig_path, '-n', 'Fred Bloggs', '-p', 'alnum'])
        assert result.returncode == 0
        assert 'VALID' in result.stdout
        assert 'Signed at:' in result.stdout

    def test_verify_wrong_doc(self, cli_env, tmp_path):
        tmp_path, key, pub, doc = cli_env
        wrong_doc = str(tmp_path / "wrong.txt")
        with open(wrong_doc, 'w') as f:
            f.write("different content\n")
        sig_path = str(tmp_path / "sig.txt")

        result = self._run(['sign', doc, '-n', 'Fred Bloggs', '-k', key, '-p', 'alnum'])
        with open(sig_path, 'w') as f:
            f.write(result.stdout)

        result = self._run(['verify', wrong_doc, sig_path, '-n', 'Fred Bloggs', '-p', 'alnum'])
        assert result.returncode != 0
        assert 'INVALID' in result.stdout

    def test_verify_with_pubkey(self, cli_env):
        tmp_path, key, pub, doc = cli_env
        sig_path = str(tmp_path / "sig.txt")

        result = self._run(['sign', doc, '-n', 'Fred Bloggs', '-k', key, '-p', 'alnum'])
        with open(sig_path, 'w') as f:
            f.write(result.stdout)

        result = self._run(['verify', doc, sig_path, '-n', 'Fred Bloggs', '-p', 'alnum', '-k', pub])
        assert result.returncode == 0
        assert 'VALID' in result.stdout

    def test_keygen(self, tmp_path):
        out = str(tmp_path / "newkey")
        result = self._run(['keygen', '-o', out])
        assert result.returncode == 0
        assert os.path.exists(out)
        assert os.path.exists(out + '.pub')
        assert oct(os.stat(out).st_mode)[-3:] == '600'

    def test_keyid(self, cli_env):
        _, key, pub, _ = cli_env
        r1 = self._run(['keyid', key])
        r2 = self._run(['keyid', pub])
        assert r1.returncode == 0
        assert r2.returncode == 0
        assert r1.stdout.strip() == r2.stdout.strip()

    def test_sign_requires_key(self):
        result = self._run(['sign', '/dev/null', '-n', 'Test'])
        assert result.returncode != 0

    def test_sign_requires_name(self, cli_env):
        _, key, _, doc = cli_env
        result = self._run(['sign', doc, '-k', key])
        assert result.returncode != 0
