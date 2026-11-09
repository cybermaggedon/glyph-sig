"""Core rendering logic for glyph-sig."""

import hashlib
import hmac
import math
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

from bdfparser import Font

PALETTES = {
    'simple': list('oO0DQ@'),
    'symbols': list('#@%&/=*+~:;!?$^.'),
    'alpha': list('abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'),
    'alnum': list('abcdefghijkmnopqrstuvwxyz23456789ABCDEFGHJKLMNPQRSTUVWXYZ'),
}
DEFAULT_PALETTE = 'symbols'
LETTER_SPACING = 1
WORD_SPACING = 3


def hash_document(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def hash_prng(hex_hash: str, count: int) -> list[int]:
    key = bytes.fromhex(hex_hash)
    out = []
    block = 0
    while len(out) < count:
        data = hmac.new(key, struct.pack('>I', block), hashlib.sha256).digest()
        out.extend(data)
        block += 1
    return out[:count]


def font_glyph_to_grid(font: Font, ch: str) -> list[list[bool]] | None:
    glyph = font.glyph(ch)
    if glyph is None:
        return None
    bitmap = glyph.draw()
    lines = str(bitmap).split('\n')
    grid = []
    for line in lines:
        row = [c == '#' for c in line]
        grid.append(row)
    return grid


def render_signature(name: str, hex_hash: str, font: Font, palette: str = DEFAULT_PALETTE) -> str:
    fill_palette = PALETTES[palette]
    font_h = font.headers['fbby']
    font_w = font.headers['fbbx']

    glyph_grids = []
    for ch in name:
        if ch == ' ':
            glyph_grids.append(None)
            continue
        grid = font_glyph_to_grid(font, ch)
        if grid is None:
            continue
        glyph_grids.append(grid)

    total_cells = sum(
        sum(cell for row in grid for cell in row)
        for grid in glyph_grids if grid is not None
    )
    rand_bytes = hash_prng(hex_hash, total_cells)

    output_rows = []
    byte_idx = 0
    for row_idx in range(font_h):
        line_parts = []
        for g_idx, grid in enumerate(glyph_grids):
            if grid is None:
                line_parts.append(' ' * WORD_SPACING)
                continue
            row_str = ''
            for col_idx in range(font_w):
                if row_idx < len(grid) and col_idx < len(grid[row_idx]) and grid[row_idx][col_idx]:
                    fill_char = fill_palette[rand_bytes[byte_idx] % len(fill_palette)]
                    row_str += fill_char
                    byte_idx += 1
                else:
                    row_str += ' '
            line_parts.append(row_str)

            if g_idx < len(glyph_grids) - 1 and glyph_grids[g_idx + 1] is not None:
                line_parts.append(' ' * LETTER_SPACING)
        output_rows.append(''.join(line_parts))

    return '\n'.join(output_rows)


def signature_bits(name: str, font: Font, palette: str = DEFAULT_PALETTE) -> float:
    fill_palette = PALETTES[palette]
    total_cells = 0
    for ch in name:
        if ch == ' ':
            continue
        grid = font_glyph_to_grid(font, ch)
        if grid is None:
            continue
        total_cells += sum(cell for row in grid for cell in row)
    return total_cells * math.log2(len(fill_palette))


def generate_keypair() -> tuple[bytes, bytes]:
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


CHIROGRAPHUM_LABEL = "C H I R O G R A P H U M"
BLOCK_WIDTH = 45
BLOCK_SIDE = 10


def _int_to_digits(n: int, base: int, length: int) -> list[int]:
    digits = []
    for _ in range(length):
        digits.append(n % base)
        n //= base
    return list(reversed(digits))


def _digits_to_int(digits: list[int], base: int) -> int:
    n = 0
    for d in digits:
        n = n * base + d
    return n


def _pubkey_palette_len(palette: str) -> int:
    base = len(PALETTES[palette])
    return math.ceil(256 * math.log(2) / math.log(base))


def _chirographum_template() -> list[str]:
    label = f" {CHIROGRAPHUM_LABEL} "
    return [
        '=' * BLOCK_WIDTH,
        '=' * BLOCK_SIDE + label + '=' * BLOCK_SIDE,
        '=' * BLOCK_WIDTH,
    ]


def encode_pubkey_block(raw_key: bytes, palette: str = DEFAULT_PALETTE) -> str:
    fill = PALETTES[palette]
    base = len(fill)
    num_chars = _pubkey_palette_len(palette)

    key_int = int.from_bytes(raw_key, 'big')
    digits = _int_to_digits(key_int, base, num_chars)
    chars = iter(fill[d] for d in digits)

    result = []
    for line in _chirographum_template():
        out = []
        for ch in line:
            if ch == '=':
                c = next(chars, None)
                out.append(c if c is not None else '=')
            else:
                out.append(ch)
        result.append(''.join(out))
    return '\n'.join(result)


def decode_pubkey_block(block: str, palette: str = DEFAULT_PALETTE) -> bytes:
    fill = PALETTES[palette]
    base = len(fill)
    num_chars = _pubkey_palette_len(palette)

    template = _chirographum_template()
    block_lines = block.strip().split('\n')

    chars = []
    for tline, bline in zip(template, block_lines):
        for tch, bch in zip(tline, bline):
            if tch == '=' and len(chars) < num_chars:
                chars.append(bch)

    idx = {ch: i for i, ch in enumerate(fill)}
    digits = [idx[ch] for ch in chars]
    key_int = _digits_to_int(digits, base)
    return key_int.to_bytes(32, 'big')


def load_raw_pubkey(pem_bytes: bytes) -> bytes:
    try:
        pub = load_pem_public_key(pem_bytes)
    except ValueError:
        priv = load_pem_private_key(pem_bytes, password=None)
        pub = priv.public_key()
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def raw_to_pem_pubkey(raw_key: bytes) -> bytes:
    pub = Ed25519PublicKey.from_public_bytes(raw_key)
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


CRYPTO_PAYLOAD_SIZE = 104  # 64 (signature) + 32 (public key) + 8 (timestamp)


def _payload_palette_len(num_bytes: int, palette: str) -> int:
    base = len(PALETTES[palette])
    return math.ceil(num_bytes * 8 * math.log(2) / math.log(base))


def _build_glyph_grids(name: str, font: Font):
    glyph_grids = []
    for ch in name:
        if ch == ' ':
            glyph_grids.append(None)
            continue
        grid = font_glyph_to_grid(font, ch)
        if grid is not None:
            glyph_grids.append(grid)
    return glyph_grids


def _count_fill_pixels(glyph_grids) -> int:
    return sum(
        sum(cell for row in grid for cell in row)
        for grid in glyph_grids if grid is not None
    )


def _render_from_digits(glyph_grids, digits: list[int], font: Font, palette: str) -> str:
    fill_palette = PALETTES[palette]
    font_h = font.headers['fbby']
    font_w = font.headers['fbbx']

    output_rows = []
    digit_idx = 0
    for row_idx in range(font_h):
        line_parts = []
        for g_idx, grid in enumerate(glyph_grids):
            if grid is None:
                line_parts.append(' ' * WORD_SPACING)
                continue
            row_str = ''
            for col_idx in range(font_w):
                if row_idx < len(grid) and col_idx < len(grid[row_idx]) and grid[row_idx][col_idx]:
                    row_str += fill_palette[digits[digit_idx]]
                    digit_idx += 1
                else:
                    row_str += ' '
            line_parts.append(row_str)
            if g_idx < len(glyph_grids) - 1 and glyph_grids[g_idx + 1] is not None:
                line_parts.append(' ' * LETTER_SPACING)
        output_rows.append(''.join(line_parts))
    return '\n'.join(output_rows)


def _signing_message(hex_hash: str, name: str, timestamp: int) -> bytes:
    return hashlib.sha256(
        bytes.fromhex(hex_hash) + name.encode('utf-8') + struct.pack('>Q', timestamp)
    ).digest()


def render_crypto_signature(
    name: str, hex_hash: str, private_key_pem: bytes,
    font: Font, palette: str = DEFAULT_PALETTE,
) -> str:
    import time
    fill_palette = PALETTES[palette]
    base = len(fill_palette)

    timestamp = int(time.time())
    private_key = load_pem_private_key(private_key_pem, password=None)
    sig_bytes = private_key.sign(_signing_message(hex_hash, name, timestamp))
    pubkey_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    payload = sig_bytes + pubkey_raw + struct.pack('>Q', timestamp)

    glyph_grids = _build_glyph_grids(name, font)
    total_cells = _count_fill_pixels(glyph_grids)
    num_payload_chars = _payload_palette_len(CRYPTO_PAYLOAD_SIZE, palette)

    if total_cells < num_payload_chars:
        raise ValueError(
            f"Not enough fill pixels ({total_cells}) to encode crypto payload "
            f"(need {num_payload_chars} with {palette} palette). "
            f"Use a longer name, larger font, or bigger palette."
        )

    payload_int = int.from_bytes(payload, 'big')
    payload_digits = _int_to_digits(payload_int, base, num_payload_chars)

    remaining = total_cells - num_payload_chars
    rand_bytes = hash_prng(hex_hash, remaining)
    extra_digits = [b % base for b in rand_bytes]

    return _render_from_digits(glyph_grids, payload_digits + extra_digits, font, palette)


def verify_crypto_signature(
    art: str, name: str, hex_hash: str,
    font: Font, palette: str = DEFAULT_PALETTE,
    expected_pubkey: bytes | None = None,
) -> tuple[bool, bytes | None, int | None]:
    fill_palette = PALETTES[palette]
    base = len(fill_palette)
    num_payload_chars = _payload_palette_len(CRYPTO_PAYLOAD_SIZE, palette)

    fill_chars = extract_fill_chars(art)
    if len(fill_chars) < num_payload_chars:
        return False, None, None

    char_to_idx = {ch: i for i, ch in enumerate(fill_palette)}
    try:
        digits = [char_to_idx[ch] for ch in fill_chars[:num_payload_chars]]
    except KeyError:
        return False, None, None

    payload_int = _digits_to_int(digits, base)
    payload = payload_int.to_bytes(CRYPTO_PAYLOAD_SIZE, 'big')

    sig_bytes = payload[:64]
    pubkey_raw = payload[64:96]
    timestamp = struct.unpack('>Q', payload[96:104])[0]

    if expected_pubkey is not None and pubkey_raw != expected_pubkey:
        return False, pubkey_raw, timestamp

    try:
        pub = Ed25519PublicKey.from_public_bytes(pubkey_raw)
        pub.verify(sig_bytes, _signing_message(hex_hash, name, timestamp))
        return True, pubkey_raw, timestamp
    except Exception:
        return False, pubkey_raw, timestamp


def extract_fill_chars(art: str) -> str:
    return ''.join(ch for ch in art if ch not in (' ', '\n'))


def verify_signature(art: str, name: str, hex_hash: str, font: Font, palette: str = DEFAULT_PALETTE) -> bool:
    expected = render_signature(name, hex_hash, font, palette)
    return extract_fill_chars(art) == extract_fill_chars(expected)
