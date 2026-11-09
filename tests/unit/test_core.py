import math

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from glyph_sig.core import (
    _int_to_digits,
    _digits_to_int,
    _pubkey_palette_len,
    _payload_palette_len,
    _chirographum_template,
    _build_glyph_grids,
    _count_fill_pixels,
    extract_fill_chars,
    generate_keypair,
    encode_pubkey_block,
    decode_pubkey_block,
    load_raw_pubkey,
    raw_to_pem_pubkey,
    signature_bits,
    hash_document,
    PALETTES,
    BLOCK_WIDTH,
    CHIROGRAPHUM_LABEL,
    CRYPTO_PAYLOAD_SIZE,
)


class TestBaseConversion:
    def test_round_trip_small(self):
        n = 12345
        digits = _int_to_digits(n, 17, 10)
        assert _digits_to_int(digits, 17) == n

    def test_round_trip_large(self):
        n = 2**256 - 1
        digits = _int_to_digits(n, 17, 63)
        assert _digits_to_int(digits, 17) == n

    def test_zero(self):
        digits = _int_to_digits(0, 17, 5)
        assert digits == [0, 0, 0, 0, 0]
        assert _digits_to_int(digits, 17) == 0

    def test_digits_length(self):
        digits = _int_to_digits(42, 10, 8)
        assert len(digits) == 8

    @pytest.mark.parametrize("base", [6, 17, 50, 54])
    def test_round_trip_all_palette_bases(self, base):
        n = 2**255
        length = math.ceil(256 * math.log(2) / math.log(base))
        digits = _int_to_digits(n, base, length)
        assert _digits_to_int(digits, base) == n


class TestPaletteLengths:
    def test_pubkey_palette_len_symbols(self):
        base = len(PALETTES['symbols'])
        length = _pubkey_palette_len('symbols')
        assert length == math.ceil(256 * math.log(2) / math.log(base))

    def test_payload_palette_len_symbols(self):
        base = len(PALETTES['symbols'])
        length = _payload_palette_len(CRYPTO_PAYLOAD_SIZE, 'symbols')
        assert length == math.ceil(CRYPTO_PAYLOAD_SIZE * 8 * math.log(2) / math.log(base))

    @pytest.mark.parametrize("palette", PALETTES.keys())
    def test_payload_fits_256_bits(self, palette):
        length = _pubkey_palette_len(palette)
        base = len(PALETTES[palette])
        assert base ** length >= 2**256


class TestChirographumTemplate:
    def test_three_lines(self):
        template = _chirographum_template()
        assert len(template) == 3

    def test_line_widths(self):
        template = _chirographum_template()
        for line in template:
            assert len(line) == BLOCK_WIDTH

    def test_label_present(self):
        template = _chirographum_template()
        assert CHIROGRAPHUM_LABEL in template[1]


class TestPubkeyBlock:
    @pytest.mark.parametrize("palette", PALETTES.keys())
    def test_round_trip(self, palette):
        key = Ed25519PrivateKey.generate().public_key()
        from cryptography.hazmat.primitives import serialization
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        block = encode_pubkey_block(raw, palette)
        recovered = decode_pubkey_block(block, palette)
        assert recovered == raw

    def test_block_format(self):
        raw = b'\x00' * 32
        block = encode_pubkey_block(raw, 'symbols')
        lines = block.split('\n')
        assert len(lines) == 3
        assert CHIROGRAPHUM_LABEL in lines[1]


class TestKeypair:
    def test_generate_returns_pem(self, keypair):
        private_pem, public_pem = keypair
        assert b'BEGIN PRIVATE KEY' in private_pem
        assert b'BEGIN PUBLIC KEY' in public_pem

    def test_private_key_loads(self, keypair):
        private_pem, _ = keypair
        key = load_pem_private_key(private_pem, password=None)
        assert isinstance(key, Ed25519PrivateKey)

    def test_public_key_loads(self, keypair):
        _, public_pem = keypair
        key = load_pem_public_key(public_pem)
        assert key is not None

    def test_keys_correspond(self, keypair):
        from cryptography.hazmat.primitives import serialization
        private_pem, public_pem = keypair
        priv = load_pem_private_key(private_pem, password=None)
        pub = load_pem_public_key(public_pem)
        priv_pub_raw = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        pub_raw = pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        assert priv_pub_raw == pub_raw


class TestLoadRawPubkey:
    def test_from_public_pem(self, keypair):
        _, public_pem = keypair
        raw = load_raw_pubkey(public_pem)
        assert len(raw) == 32

    def test_from_private_pem(self, keypair):
        private_pem, public_pem = keypair
        raw_from_priv = load_raw_pubkey(private_pem)
        raw_from_pub = load_raw_pubkey(public_pem)
        assert raw_from_priv == raw_from_pub

    def test_raw_to_pem_round_trip(self, keypair):
        _, public_pem = keypair
        raw = load_raw_pubkey(public_pem)
        pem = raw_to_pem_pubkey(raw)
        raw2 = load_raw_pubkey(pem)
        assert raw == raw2


class TestExtractFillChars:
    def test_strips_spaces_and_newlines(self):
        assert extract_fill_chars("a b\nc d") == "abcd"

    def test_empty(self):
        assert extract_fill_chars("") == ""

    def test_all_spaces(self):
        assert extract_fill_chars("   \n   ") == ""


class TestSignatureBits:
    def test_positive(self, font):
        bits = signature_bits("Fred Bloggs", font, 'symbols')
        assert bits > 0

    def test_more_chars_more_bits(self, font):
        short = signature_bits("AB", font, 'symbols')
        long = signature_bits("ABCDEF", font, 'symbols')
        assert long > short

    def test_bigger_palette_more_bits(self, font):
        sym = signature_bits("Fred", font, 'symbols')
        aln = signature_bits("Fred", font, 'alnum')
        assert aln > sym


class TestHashDocument:
    def test_deterministic(self, tmp_document):
        h1 = hash_document(tmp_document)
        h2 = hash_document(tmp_document)
        assert h1 == h2

    def test_hex_string(self, tmp_document):
        h = hash_document(tmp_document)
        assert len(h) == 64
        int(h, 16)


class TestGlyphGrids:
    def test_build_grids(self, font):
        grids = _build_glyph_grids("AB", font)
        assert len(grids) == 2
        assert all(g is not None for g in grids)

    def test_space_is_none(self, font):
        grids = _build_glyph_grids("A B", font)
        assert len(grids) == 3
        assert grids[1] is None

    def test_count_fill_pixels(self, font):
        grids = _build_glyph_grids("A", font)
        count = _count_fill_pixels(grids)
        assert count > 0
