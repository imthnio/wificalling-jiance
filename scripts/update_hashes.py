#!/usr/bin/env python3
"""Maintainer-only: update the launcher's expected hashes after rebuilding."""
from pathlib import Path
import hashlib
import re
root=Path(__file__).resolve().parents[1]
p=root/'check.sh'
s=p.read_text()
lines=[]
for arch in ('x86_64','aarch64'):
    name=f'check-linux-{arch}'
    digest=hashlib.sha256((root/'bin'/name).read_bytes()).hexdigest()
    s,n=re.subn(rf'(HASH_{arch}=)[a-f0-9A-Z_]+',rf'\g<1>{digest}',s)
    if n!=1: raise SystemExit(f'Missing hash placeholder for {arch}')
    lines.append(f'{digest}  bin/{name}\n')
p.write_text(s)
(root/'SHA256SUMS').write_text(''.join(lines))
