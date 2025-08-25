#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

Author: Ferly Afriliyan [ NyctophileXNIKA (Nyctophile Schizophrenia) ]
# – Please use it, if you want to change it, no problem, as long as you don't delete my name, bro! – #

"""

# —————

"""
obfuscate_pack.py — Multi-round Python obfuscator/packer

Layer (per round):
  [plain] -> zlib.compress -> encrypt (AES-CTR / AES-GCM / XOR) -> (HMAC if needed) -> marshal(tuple)
Final:
  base64(fragmented) embedded into a loader .py

Author :
  Ferly Afriliyan – [ NyctophileXNIKA (Nyctophile Schizophrenia) ]
  Facebook : https://www.facebook.com/Nyctophile.Schizophrenia
  Instagram: V3n.ryougaa
"""

import argparse, base64, hashlib, hmac, marshal, os, random, secrets, textwrap, zlib, sys
from typing import Tuple

# ---- banner & clear ----
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    print(r"""
==========================================
 🔐 Python Multi-Round Obfuscator/Packer
 Author : Ferly Afriliyan
   [ NyctophileXNIKA ( Nyctophile Schizophrenia ) ]
 Facebook : Nyctophile.Schizophrenia
 Instagram: V3n.ryougaa
==========================================
""")

# ---- crypto helpers ----
try:
    from Crypto.Cipher import AES
    HAVE_AES = True
except Exception:
    HAVE_AES = False

def pbkdf2(key: bytes, salt: bytes, n=200_000, dklen=32):
    return hashlib.pbkdf2_hmac("sha256", key, salt, n, dklen)

def aes_encrypt_ctr(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=iv)
    return iv, cipher.encrypt(plaintext)

def aes_encrypt_gcm(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    iv = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return iv, ct, tag

def xor_keystream_enc(key: bytes, data: bytes) -> Tuple[bytes, bytes]:
    iv = secrets.token_bytes(16)
    out = bytearray(); counter = 0; i = 0
    while i < len(data):
        block = hashlib.sha256(key + iv + counter.to_bytes(8,'big')).digest()
        take = min(32, len(data) - i)
        out.extend(bytes(a ^ b for a, b in zip(data[i:i+take], block[:take])))
        i += take; counter += 1
    return iv, bytes(out)

def hmac256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

# ---- packer core ----
def compile_to_code(src_bytes: bytes, filename: str):
    src = src_bytes.decode("utf-8", "replace")
    return compile(src, filename, "exec", dont_inherit=True, optimize=2)

def machine_fingerprint() -> bytes:
    try:
        return (os.uname().sysname + os.uname().release + sys.version).encode()
    except Exception:
        return sys.version.encode()

def pack_one_round(plain: bytes, password: str, use_aes: bool, aes_gcm: bool, kdf_iter: int, machine_lock: bool) -> bytes:
    comp = zlib.compress(plain, 9)
    salt = secrets.token_bytes(16)
    pw_bytes = password.encode()
    if machine_lock:
        pw_bytes += hashlib.sha256(machine_fingerprint()).digest()

    k_enc = pbkdf2(pw_bytes, salt, n=kdf_iter, dklen=32)
    k_mac = pbkdf2(pw_bytes, salt + b"mac", n=kdf_iter, dklen=32)

    if aes_gcm:
        iv, ct, tag = aes_encrypt_gcm(k_enc, comp)
        wrap = marshal.dumps((b"O1gcm", salt, iv, tag, ct))
    elif use_aes:
        iv, enc = aes_encrypt_ctr(k_enc, comp)
        tag = hmac256(k_mac, enc)
        wrap = marshal.dumps((b"O1", salt, iv, tag, enc, b"aes-ctr"))
    else:
        iv, enc = xor_keystream_enc(k_enc, comp)
        tag = hmac256(k_mac, enc)
        wrap = marshal.dumps((b"O1", salt, iv, tag, enc, b"xor"))
    return wrap

def multilayer_pack(codeobj, password: str, use_aes: bool, aes_gcm: bool, rounds: int, kdf_iter: int, machine_lock: bool) -> bytes:
    plain = marshal.dumps(codeobj)
    blob = plain
    for _ in range(rounds):
        blob = pack_one_round(blob, password, use_aes, aes_gcm, kdf_iter, machine_lock)
    return blob

def make_fragments(b: bytes, chunks: int, var_prefix: str) -> Tuple[str, int]:
    s = base64.b64encode(b).decode()
    parts = []; i = 0
    while i < len(s):
        span = random.randint(max(32, chunks//2), int(chunks*1.3))
        parts.append(s[i:i+span]); i += span
    decl, names = [], []
    for part in parts:
        nm = f"{var_prefix}_{secrets.token_hex(3)}"
        wrapped = "\\\n".join(textwrap.wrap(part, 80))
        decl.append(f"{nm} = '''{wrapped}'''"); names.append(nm)
    code = "\n".join(decl) + f"\nparts = [{', '.join(names)}]\nencoded = ''.join(parts)\n"
    return code, len(parts)

def build_loader(b64_frag_code: str, var_prefix: str, filename_hint: str, hardcoded_pw: str | None,
                 rounds_hint: int, kdf_iter: int, aes_gcm: bool, machine_lock: bool) -> str:
    if hardcoded_pw is not None:
        pw_expr = repr(hardcoded_pw)
    else:
        pw_expr = f'_os.environ.get("{var_prefix.upper()}_PW") or (_sys.argv[1] if len(_sys.argv)>1 else "")'

    lock_expr = " + _hash.sha256(_fingerprint()).digest()" if machine_lock else ""

    return f'''# -*- coding: utf-8 -*-
# Obfuscated loader generated by obfuscate_pack.py
# rounds={rounds_hint}, kdf_iter={kdf_iter}, aes_gcm={aes_gcm}, machine_lock={machine_lock}
import base64 as _b64, marshal as _m, zlib as _z, sys as _sys, hmac as _hmac, hashlib as _hash, types as _types
import os as _os

# --- Begin fragmented payload ---
{b64_frag_code}
# --- End fragmented payload ---

def _pbkdf2(pw, salt, n={kdf_iter}, dklen=32):
    return _hash.pbkdf2_hmac("sha256", pw, salt, n, dklen)

def _xor_dec(key, iv, data):
    out = bytearray(); counter = 0; i = 0
    import hashlib as H
    while i < len(data):
        block = H.sha256(key + iv + counter.to_bytes(8,'big')).digest()
        take = min(32, len(data) - i)
        out.extend(bytes(a ^ b for a, b in zip(data[i:i+take], block[:take])))
        i += take; counter += 1
    return bytes(out)

def _fingerprint():
    try:
        return (_os.uname().sysname + _os.uname().release + _sys.version).encode()
    except Exception:
        return _sys.version.encode()

def _unwrap_all(blob: bytes, pw: str) -> _types.CodeType:
    while True:
        obj = _m.loads(blob)
        if isinstance(obj, tuple):
            if obj[0] == b"O1gcm":
                _, salt, iv, tag, ct = obj
                k_enc = _pbkdf2(pw.encode(){lock_expr}, salt, {kdf_iter}, 32)
                from Crypto.Cipher import AES as _AES
                c = _AES.new(k_enc, _AES.MODE_GCM, nonce=iv)
                raw = c.decrypt_and_verify(ct, tag)
                blob = _z.decompress(raw); continue
            elif obj[0] == b"O1":
                _, salt, iv, tag, enc, mode = obj
                k_enc = _pbkdf2(pw.encode(){lock_expr}, salt, {kdf_iter}, 32)
                k_mac = _pbkdf2(pw.encode(){lock_expr}, salt + b"mac", {kdf_iter}, 32)
                if not _hmac.compare_digest(tag, _hmac.new(k_mac, enc, _hash.sha256).digest()):
                    raise RuntimeError("Integrity check failed")
                if mode == b'aes-ctr':
                    from Crypto.Cipher import AES as _AES
                    c = _AES.new(k_enc, _AES.MODE_CTR, nonce=b"", initial_value=iv)
                    raw = c.decrypt(enc)
                else:
                    raw = _xor_dec(k_enc, iv, enc)
                blob = _z.decompress(raw); continue
        if isinstance(obj, _types.CodeType):
            return obj
        raise RuntimeError("Unexpected object type during unwrap")

def _main():
    pw = {pw_expr}
    if not pw:
        _sys.stderr.write("Password required via env {var_prefix.upper()}_PW or CLI arg\\n")
        _sys.exit(2)
    blob = _b64.b64decode(encoded)
    co = _unwrap_all(blob, pw)
    g = {{"__name__":"__main__","__file__":{filename_hint!r},"__package__":None}}
    exec(co, g, None)

if __name__ == "__main__":
    _main()
'''

# ---- interactive wrapper ----
def prompt(msg, default=None):
    val = input(f"[*] {msg} [default={default}]: ").strip()
    return val if val else default

def yn_prompt(msg, default="y"):
    val = input(f"[*] {msg} (y/n) [default={default}]: ").strip().lower()
    return (val if val in ("y","n") else default) == "y"

def main():
    clear(); banner()
    src_file = input("[*] Masukkan nama file sumber (.py): ").strip()
    if not src_file:
        print("[!] Error: File sumber wajib diisi.")
        sys.exit(1)
    if not os.path.exists(src_file):
        print(f"[!] Error: File '{src_file}' tidak ditemukan.")
        sys.exit(1)

    rounds = int(prompt("Berapa jumlah rounds/lapisan enkripsi? (Rounds adalah pengulangan/lapisan enkripsi)", 1))
    password = input("[*] Masukkan password enkripsi (kosong = auto generate): ").strip() or None
    hardcode = yn_prompt("Hardcode password di loader?", "n")
    use_gcm = yn_prompt("Gunakan AES-GCM?", "n")
    use_aes = yn_prompt("Gunakan AES-CTR (AES biasa)?", "y")
    use_xor = yn_prompt("Paksa pakai XOR fallback?", "n")
    kdf_iter = int(prompt("Jumlah iterasi PBKDF2 (semakin besar semakin aman tapi lambat)", 200000))
    chunks = int(prompt("Target panjang fragment base64", 120))
    var_prefix = prompt("Prefix nama variabel fragment", "zX")
    machine_lock = yn_prompt("Ikat password ke fingerprint mesin (machine-lock)?", "n")

    # compile & pack
    src = open(src_file,"rb").read()
    codeobj = compile_to_code(src, os.path.basename(src_file))
    password = password or base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")

    wrapped = multilayer_pack(codeobj, password, use_aes, use_gcm, rounds, kdf_iter, machine_lock)
    frag_code, n_parts = make_fragments(wrapped, chunks, var_prefix)
    hardcoded_pw = password if hardcode else None
    loader = build_loader(frag_code, var_prefix, os.path.basename(src_file), hardcoded_pw, rounds, kdf_iter, use_gcm, machine_lock)

    out = os.path.splitext(src_file)[0] + "_obf.py"
    with open(out,"w",encoding="utf-8") as f: f.write(loader)

    sys.stderr.write(f"[+] Wrote loader: {out} (rounds={rounds}, fragments={n_parts}, mode={'AES-GCM' if use_gcm else ('AES-CTR' if use_aes else 'XOR')}, kdf_iter={kdf_iter}, machine_lock={machine_lock})\n")
    print(f"[i] Password digunakan: {password}")

    if not hardcode:
        print("\n[!] Jalankan hasil obfuscate dengan salah satu cara berikut:")
        print(f"    1) Langsung dengan argumen:")
        print(f"       python {out} {password}")
        print(f"    2) Atau dengan environment variable (cukup sekali per session):")
        print(f"       export {var_prefix.upper()}_PW={password}")
        print(f"       python {out}")

if __name__ == "__main__":
    main()