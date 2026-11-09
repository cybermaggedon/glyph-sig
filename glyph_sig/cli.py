"""Command-line interface for glyph-sig."""

import argparse
import importlib.resources
import os
import sys

from bdfparser import Font

from glyph_sig.core import (
    hash_document, signature_bits,
    generate_keypair, encode_pubkey_block, decode_pubkey_block,
    load_raw_pubkey, raw_to_pem_pubkey,
    render_crypto_signature, verify_crypto_signature,
    PALETTES, DEFAULT_PALETTE,
)


def bundled_fonts_dir():
    return importlib.resources.files('glyph_sig') / 'fonts'


def resolve_font_path(name: str | None) -> str:
    if name is None:
        return str(bundled_fonts_dir() / '8x13O.bdf')
    if os.path.exists(name):
        return name
    if not name.endswith('.bdf'):
        name += '.bdf'
    bundled = bundled_fonts_dir() / name
    if bundled.is_file():
        return str(bundled)
    sys.exit(f"Font not found: {name}\nUse 'glyph-sig fonts' to list bundled fonts.")


def list_bundled_fonts() -> list[str]:
    return sorted(
        f.name for f in bundled_fonts_dir().iterdir()
        if f.name.endswith('.bdf')
    )


def main():
    parser = argparse.ArgumentParser(
        prog='glyph-sig',
        description='Generate deterministic ASCII art signatures from document hashes.',
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    sign_parser = subparsers.add_parser('sign', help='Sign a document')
    sign_parser.add_argument('document', help='Path to document to sign')
    sign_parser.add_argument('-n', '--name', required=True, help='Signer name')
    sign_parser.add_argument('-k', '--key', required=True, help='Private key file')
    sign_parser.add_argument('-f', '--font', default=None, help='Path to BDF font file')
    sign_parser.add_argument('-p', '--palette', default=DEFAULT_PALETTE,
                             choices=PALETTES.keys(), help='Fill character palette')

    verify_parser = subparsers.add_parser('verify', help='Verify a document signature')
    verify_parser.add_argument('document', help='Path to document to verify')
    verify_parser.add_argument('signature', help='Path to signature file (- for stdin)')
    verify_parser.add_argument('-n', '--name', required=True, help='Signer name')
    verify_parser.add_argument('-f', '--font', default=None, help='Path to BDF font file')
    verify_parser.add_argument('-p', '--palette', default=DEFAULT_PALETTE,
                               choices=PALETTES.keys(), help='Fill character palette')
    verify_parser.add_argument('-k', '--key', default=None,
                               help='Public key file to verify against (optional)')

    bits_parser = subparsers.add_parser('bits', help='Show effective signature entropy in bits')
    bits_parser.add_argument('-n', '--name', default='Fred Bloggs', help='Signer name')
    bits_parser.add_argument('-f', '--font', default=None, help='Path to BDF font file')
    bits_parser.add_argument('-p', '--palette', default=DEFAULT_PALETTE,
                             choices=PALETTES.keys(), help='Fill character palette')

    keyid_parser = subparsers.add_parser('keyid', help='Print the base64 key ID for a key file')
    keyid_parser.add_argument('keyfile', help='PEM public or private key file')

    keygen_parser = subparsers.add_parser('keygen', help='Generate an Ed25519 keypair')
    keygen_parser.add_argument('-o', '--output', default='glyph-sig',
                               help='Output file base name (default: glyph-sig)')

    pubkey_parser = subparsers.add_parser('pubkey', help='Encode/decode a public key as a CHIROGRAPHUM block')
    pubkey_parser.add_argument('keyfile', help='PEM public key file (or CHIROGRAPHUM block with --decode)')
    pubkey_parser.add_argument('--decode', action='store_true',
                               help='Decode a CHIROGRAPHUM block back to PEM')
    pubkey_parser.add_argument('-p', '--palette', default=DEFAULT_PALETTE,
                               choices=PALETTES.keys(), help='Fill character palette')

    fonts_parser = subparsers.add_parser('fonts', help='List bundled fonts')

    args = parser.parse_args()
    font_path = resolve_font_path(args.font if hasattr(args, 'font') else None)

    if args.command == 'fonts':
        for name in list_bundled_fonts():
            print(name)
        return

    if args.command == 'keyid':
        import base64
        with open(args.keyfile, 'rb') as f:
            raw = load_raw_pubkey(f.read())
        print(base64.b64encode(raw).decode())
        return

    if args.command == 'pubkey':
        with open(args.keyfile, 'rb') as f:
            data = f.read()
        if args.decode:
            raw_key = decode_pubkey_block(data.decode(), args.palette)
            sys.stdout.buffer.write(raw_to_pem_pubkey(raw_key))
        else:
            raw_key = load_raw_pubkey(data)
            print(encode_pubkey_block(raw_key, args.palette))
        return

    if args.command == 'keygen':
        priv_path = args.output
        pub_path = args.output + '.pub'
        if os.path.exists(priv_path) or os.path.exists(pub_path):
            sys.exit(f"Refusing to overwrite existing file(s): {priv_path}, {pub_path}")
        private_pem, public_pem = generate_keypair()
        with open(priv_path, 'wb') as f:
            f.write(private_pem)
        os.chmod(priv_path, 0o600)
        with open(pub_path, 'wb') as f:
            f.write(public_pem)
        print(f"Private key: {priv_path}")
        print(f"Public key:  {pub_path}")
        return

    font = Font(font_path)

    if args.command == 'bits':
        bits = signature_bits(args.name, font, args.palette)
        print(int(bits))
        return

    elif args.command == 'sign':
        hex_hash = hash_document(args.document)
        with open(args.key, 'rb') as f:
            private_pem = f.read()
        try:
            print(render_crypto_signature(args.name, hex_hash, private_pem, font, args.palette))
        except ValueError as e:
            sys.exit(str(e))

    elif args.command == 'verify':
        hex_hash = hash_document(args.document)
        if args.signature == '-':
            art = sys.stdin.read()
        else:
            with open(args.signature) as f:
                art = f.read()

        expected_raw = None
        if args.key:
            with open(args.key, 'rb') as f:
                expected_raw = load_raw_pubkey(f.read())

        valid, pubkey_raw, timestamp = verify_crypto_signature(
            art, args.name, hex_hash, font, args.palette, expected_raw,
        )
        if valid:
            import base64
            from datetime import datetime, timezone
            print("VALID: cryptographic signature verified.")
            print(f"Signed by key: {base64.b64encode(pubkey_raw).decode()}")
            print(f"Signed at:     {datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()}")
        else:
            if expected_raw and pubkey_raw and expected_raw != pubkey_raw:
                print("INVALID: embedded public key does not match expected key.")
            else:
                print("INVALID: signature does not match document.")
            sys.exit(1)


if __name__ == '__main__':
    main()
