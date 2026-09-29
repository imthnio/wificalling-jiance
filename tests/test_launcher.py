#!/usr/bin/env python3
"""Exercise downloads and failures with fake tools; never execute a remote file."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.tools=self.root/'tools'; self.tools.mkdir()
        self.scratch=self.root/'scratch'; self.scratch.mkdir()
        self.payload=self.root/'payload'
        self.payload.write_text('#!/bin/sh\nprintf "ARG=<%s>\\n" "$@"\nexit "${PAYLOAD_STATUS:-0}"\n')
        for command in ('mktemp','rm','chmod','shasum','cp'):
            src=shutil.which(command)
            if src: (self.tools/command).symlink_to(src)
        digest=hashlib.sha256(self.payload.read_bytes()).hexdigest()
        s=(ROOT/'check.sh').read_text()
        s=re.sub(r'HASH_(x86_64|aarch64)=[a-f0-9]+',lambda m:m[0].split('=')[0]+'='+digest,s)
        self.launcher=self.root/'check.sh'; self.launcher.write_text(s)
        self.tool('uname','if [ "$1" = -s ]; then echo "${FAKE_OS:-Linux}"; else echo "${FAKE_ARCH:-x86_64}"; fi')
        self.tool('curl','if [ "${BAD_DOWNLOAD:-0}" = 1 ]; then exit 22; fi\nwhile [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; cp "$PAYLOAD" "$1"; exit; fi; shift; done\nexit 2')
        self.env={**os.environ,'PATH':str(self.tools),'WIFICALLING_TMPDIR':str(self.scratch),'PAYLOAD':str(self.payload)}
    def tearDown(self): self.tmp.cleanup()
    def tool(self,name,body):
        p=self.tools/name; p.write_text('#!/bin/sh\n'+body+'\n'); p.chmod(0o700)
    def run_script(self,*args,**env):
        p=subprocess.run(['/bin/sh',str(self.launcher),*args],env={**self.env,**env},capture_output=True,text=True)
        self.assertEqual(list(self.scratch.iterdir()),[], 'launcher left temporary files')
        return p
    def test_good_download_arguments_and_cleanup(self):
        p=self.run_script('--filter','英国 EE'); self.assertEqual(p.returncode,0); self.assertIn('ARG=<英国 EE>',p.stdout)
    def test_aarch64_alias(self): self.assertEqual(self.run_script('--list',FAKE_ARCH='arm64').returncode,0)
    def test_child_exit_propagates(self): self.assertEqual(self.run_script(PAYLOAD_STATUS='7').returncode,7)
    def test_download_failure(self): self.assertNotEqual(self.run_script(BAD_DOWNLOAD='1').returncode,0)
    def test_hash_mismatch_never_executes(self):
        self.payload.write_text('#!/bin/sh\necho BAD_EXECUTION\n')
        p=self.run_script(); self.assertNotEqual(p.returncode,0); self.assertNotIn('BAD_EXECUTION',p.stdout); self.assertIn('校验失败',p.stderr)
    def test_missing_hasher(self):
        (self.tools/'shasum').unlink(); self.assertIn('校验工具',self.run_script().stderr)
    def test_wget_only(self):
        (self.tools/'curl').unlink()
        self.tool('wget','while [ "$#" -gt 0 ]; do if [ "$1" = -O ]; then shift; cp "$PAYLOAD" "$1"; exit; fi; shift; done\nexit 2')
        self.assertEqual(self.run_script('--list').returncode,0)
    def test_missing_downloader(self):
        (self.tools/'curl').unlink(); self.assertNotEqual(self.run_script().returncode,0)
    def test_unsupported_platform(self):
        self.assertNotEqual(self.run_script(FAKE_OS='Darwin').returncode,0)
        self.assertNotEqual(self.run_script(FAKE_ARCH='mips').returncode,0)
    def test_http_override_refused(self): self.assertNotEqual(self.run_script(WIFICALLING_BASE_URL='http://example.com').returncode,0)
    def test_help_and_version_do_not_download(self):
        self.assertEqual(self.run_script('--help',FAKE_OS='Darwin',BAD_DOWNLOAD='1').returncode,0)
        self.assertEqual(self.run_script('--version',BAD_DOWNLOAD='1').stdout.strip(),'2.3.0')
    def test_hash_manifest_matches_binaries_and_launcher(self):
        s=(ROOT/'check.sh').read_text()
        for row in (ROOT/'SHA256SUMS').read_text().splitlines():
            expected,path=row.split(); self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),expected); self.assertIn(expected,s)

if __name__=='__main__': unittest.main(verbosity=2)
