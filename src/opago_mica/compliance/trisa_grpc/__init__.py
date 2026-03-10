"""
TRISA gRPC stubs — compiled from trisacrypto/trisa proto definitions.

Ensures trisa and ivms101 packages are importable by adding this directory
to sys.path when the module loads.
"""

from __future__ import annotations

import sys
from pathlib import Path

_grpc_dir = Path(__file__).resolve().parent
if str(_grpc_dir) not in sys.path:
    sys.path.insert(0, str(_grpc_dir))
