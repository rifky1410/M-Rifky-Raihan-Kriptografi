from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import argparse
import os

def generate_rsa_keypair(bits: int = 2048):
    key = RSA.generate(bits)
    priv_pem = key.export_key()
    pub_pem = key.publickey().export_key()
    return priv_pem, pub_pem

def save_key(pem: bytes, path: str):
    with open(path, "wb") as f:
        f.write(pem)

def load_key(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def rsa_encrypt(message: bytes, public_pem: bytes) -> bytes:
    pub = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(pub)
    return cipher.encrypt(message)

def rsa_decrypt(ciphertext: bytes, private_pem: bytes) -> bytes:
    priv = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(priv)
    return cipher.decrypt(ciphertext)

def rsa_sign(message: bytes, private_pem: bytes) -> bytes:
    priv = RSA.import_key(private_pem)
    h = SHA256.new(message)
    signature = pkcs1_15.new(priv).sign(h)
    return signature

def rsa_verify(message: bytes, signature: bytes, public_pem: bytes) -> bool:
    pub = RSA.import_key(public_pem)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(pub).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RSA demo: keygen/encrypt/decrypt/sign/verify")
    parser.add_argument("--action", choices=["gen", "encrypt", "decrypt", "sign", "verify"], default="gen")
    parser.add_argument("--infile", help="input file (binary)")
    parser.add_argument("--outfile", help="output file (binary)")
    parser.add_argument("--priv", help="private key file path")
    parser.add_argument("--pub", help="public key file path")
    args = parser.parse_args()

    if args.action == "gen":
        priv, pub = generate_rsa_keypair(2048)
        save_key(priv, "rsa_private.pem")
        save_key(pub, "rsa_public.pem")
        print("Generated rsa_private.pem and rsa_public.pem")
    elif args.action == "encrypt":
        if not args.infile or not args.outfile or not args.pub:
            print("encrypt requires --infile, --outfile, --pub")
            raise SystemExit(1)
        pub = load_key(args.pub)
        with open(args.infile, "rb") as f:
            data = f.read()
        ct = rsa_encrypt(data, pub)
        with open(args.outfile, "wb") as f:
            f.write(ct)
        print(f"Encrypted {args.infile} -> {args.outfile}")
    elif args.action == "decrypt":
        if not args.infile or not args.outfile or not args.priv:
            print("decrypt requires --infile, --outfile, --priv")
            raise SystemExit(1)
        priv = load_key(args.priv)
        with open(args.infile, "rb") as f:
            ct = f.read()
        pt = rsa_decrypt(ct, priv)
        with open(args.outfile, "wb") as f:
            f.write(pt)
        print(f"Decrypted {args.infile} -> {args.outfile}")
    elif args.action == "sign":
        if not args.infile or not args.outfile or not args.priv:
            print("sign requires --infile, --outfile, --priv")
            raise SystemExit(1)
        priv = load_key(args.priv)
        with open(args.infile, "rb") as f:
            data = f.read()
        sig = rsa_sign(data, priv)
        with open(args.outfile, "wb") as f:
            f.write(sig)
        print(f"Signed {args.infile} -> signature saved {args.outfile}")
    elif args.action == "verify":
        if not args.infile or not args.outfile or not args.pub:
            print("verify requires --infile (message), --outfile (signature), --pub")
            raise SystemExit(1)
        pub = load_key(args.pub)
        with open(args.infile, "rb") as f:
            data = f.read()
        with open(args.outfile, "rb") as f:
            sig = f.read()
        ok = rsa_verify(data, sig, pub)
        print("Signature valid?" , ok)
