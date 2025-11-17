import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import argparse

BLOCK_SIZE = AES.block_size 

def generate_key(length: int = 32) -> bytes:
    return get_random_bytes(length)

def aes_encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    # Simpan IV di depan ciphertext
    return iv + ct

def aes_decrypt_bytes(iv_ct: bytes, key: bytes) -> bytes:
    iv = iv_ct[:BLOCK_SIZE]
    ct = iv_ct[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), BLOCK_SIZE)
    return pt

def encrypt_file(infile: str, outfile: str, key: bytes):
    with open(infile, "rb") as f:
        data = f.read()
    iv_ct = aes_encrypt_bytes(data, key)
    with open(outfile, "wb") as f:
        f.write(iv_ct)

def decrypt_file(infile: str, outfile: str, key: bytes):
    with open(infile, "rb") as f:
        iv_ct = f.read()
    pt = aes_decrypt_bytes(iv_ct, key)
    with open(outfile, "wb") as f:
        f.write(pt)

def demo_console():
    key = generate_key()
    print("Generated AES-256 key (base64):", base64.b64encode(key).decode())
    plaintext = b"Pesan rahasia. Ini contoh AES-CBC."
    ct = aes_encrypt_bytes(plaintext, key)
    print("Ciphertext (base64):", base64.b64encode(ct).decode())
    recovered = aes_decrypt_bytes(ct, key)
    print("Recovered:", recovered.decode())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AES demo (CBC + PKCS7)")
    parser.add_argument("--mode", choices=["demo", "encrypt", "decrypt"], default="demo")
    parser.add_argument("--infile", help="input file for encrypt/decrypt")
    parser.add_argument("--outfile", help="output file")
    parser.add_argument("--keyfile", help="key file (if omitted, generate new key for demo)")
    args = parser.parse_args()

    if args.mode == "demo":
        demo_console()
    elif args.mode == "encrypt":
        if not args.infile or not args.outfile:
            print("encrypt requires --infile and --outfile")
            raise SystemExit(1)
        if args.keyfile and os.path.exists(args.keyfile):
            key = open(args.keyfile, "rb").read()
        else:
            key = generate_key()
            if args.keyfile:
                open(args.keyfile, "wb").write(key)
        encrypt_file(args.infile, args.outfile, key)
        print(f"Encrypted {args.infile} -> {args.outfile}. Key saved in {args.keyfile or '(not saved)'}")
    elif args.mode == "decrypt":
        if not args.infile or not args.outfile or not args.keyfile:
            print("decrypt requires --infile, --outfile, and --keyfile")
            raise SystemExit(1)
        key = open(args.keyfile, "rb").read()
        decrypt_file(args.infile, args.outfile, key)
        print(f"Decrypted {args.infile} -> {args.outfile}")
