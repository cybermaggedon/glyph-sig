import hashlib
import importlib.resources
import tempfile
import os

import pytest
from bdfparser import Font

from glyph_sig.core import generate_keypair


@pytest.fixture
def font():
    path = importlib.resources.files('glyph_sig') / 'fonts' / '8x13O.bdf'
    return Font(str(path))


@pytest.fixture
def keypair():
    private_pem, public_pem = generate_keypair()
    return private_pem, public_pem


@pytest.fixture
def tmp_document(tmp_path):
    doc = tmp_path / "document.txt"
    doc.write_text("hello world\n")
    return str(doc)


@pytest.fixture
def document_hash(tmp_document):
    h = hashlib.sha256()
    with open(tmp_document, 'rb') as f:
        h.update(f.read())
    return h.hexdigest()
