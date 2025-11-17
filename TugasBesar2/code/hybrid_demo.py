import os
import argparse
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

BLOCK_SIZE = AES.block_size

def generate_rsa_keypair(path_priv: str, path_pub: str, bits: int = 2048):
    key = RSA.generate(bits)
    priv_pem = key.export_key()
    pub_pem = key.publickey().export_key()
    with open(path_priv, "wb") as f:
        f.write(priv_pem)
    with open(path_pub, "wb") as f:
        f.write(pub_pem)
    return path_priv, path_pub

def load_rsa_key(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def aes_encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    return iv + ct

def aes_decrypt_bytes(iv_ct: bytes, key: bytes) -> bytes:
    iv = iv_ct[:BLOCK_SIZE]
    ct = iv_ct[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), BLOCK_SIZE)
    return pt

def rsa_encrypt_bytes(data: bytes, pub_pem: bytes) -> bytes:
    pub = RSA.import_key(pub_pem)
    cipher = PKCS1_OAEP.new(pub)
    return cipher.encrypt(data)

def rsa_decrypt_bytes(data: bytes, priv_pem: bytes) -> bytes:
    priv = RSA.import_key(priv_pem)
    cipher = PKCS1_OAEP.new(priv)
    return cipher.decrypt(data)

def sign_bytes(data: bytes, priv_pem: bytes) -> bytes:
    priv = RSA.import_key(priv_pem)
    h = SHA256.new(data)
    sig = pkcs1_15.new(priv).sign(h)
    return sig

def verify_signature(data: bytes, signature: bytes, pub_pem: bytes) -> bool:
    pub = RSA.import_key(pub_pem)
    h = SHA256.new(data)
    try:
        pkcs1_15.new(pub).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def encrypt_pipeline(infile: str, outdir: str, pub_key_path: str, sender_priv_key: str = None):
    os.makedirs(outdir, exist_ok=True)
    with open(infile, "rb") as f:
        plaintext = f.read()

    # Generate AES key
    aes_key = get_random_bytes(32)  
    iv_ct = aes_encrypt_bytes(plaintext, aes_key)

    pub_pem = load_rsa_key(pub_key_path)
    enc_key = rsa_encrypt_bytes(aes_key, pub_pem)

    signature = b""
    if sender_priv_key and os.path.exists(sender_priv_key):
        priv_pem = load_rsa_key(sender_priv_key)
        signature = sign_bytes(iv_ct, priv_pem)

    ct_path = os.path.join(outdir, "ciphertext.bin")
    enc_key_path = os.path.join(outdir, "encrypted_key.bin")
    sig_path = os.path.join(outdir, "signature.bin")

    with open(ct_path, "wb") as f:
        f.write(iv_ct)
    with open(enc_key_path, "wb") as f:
        f.write(enc_key)
    with open(sig_path, "wb") as f:
        f.write(signature)

    print("Encryption complete.")
    print(f"Ciphertext: {ct_path}")
    print(f"Encrypted AES key: {enc_key_path}")
    print(f"Signature: {sig_path} (empty if no sender private key provided)")

def decrypt_pipeline(ct_path: str, enc_key_path: str, sig_path: str, outdir: str, priv_key_path: str, sender_pub_key: str = None):
    os.makedirs(outdir, exist_ok=True)
    with open(ct_path, "rb") as f:
        iv_ct = f.read()
    with open(enc_key_path, "rb") as f:
        enc_key = f.read()
    signature = b""
    if os.path.exists(sig_path):
        with open(sig_path, "rb") as f:
            signature = f.read()

    # Decrypt AES key
    priv_pem = load_rsa_key(priv_key_path)
    aes_key = rsa_decrypt_bytes(enc_key, priv_pem)

    # Decrypt ciphertext
    plaintext = aes_decrypt_bytes(iv_ct, aes_key)

    if sender_pub_key and os.path.exists(sender_pub_key) and signature:
        pub_pem = load_rsa_key(sender_pub_key)
        ok = verify_signature(iv_ct, signature, pub_pem)
        print("Signature valid?", ok)
        if not ok:
            print("Warning: signature verification failed!")

    out_path = os.path.join(outdir, "decrypted_out")
    with open(out_path, "wb") as f:
        f.write(plaintext)
    print("Decryption complete. Plaintext saved to:", out_path)

def main():
    parser = argparse.ArgumentParser(description="Hybrid encryption demo (AES + RSA + Signature)")
    parser.add_argument("--mode", choices=["encrypt", "decrypt"], required=True)
    parser.add_argument("--infile", help="input file (for encrypt: plaintext file; for decrypt: ciphertext file)")
    parser.add_argument("--outdir", default="out", help="output directory")
    parser.add_argument("--genkeys", action="store_true", help="generate RSA keypair and save as out/rsa_private.pem & out/rsa_public.pem")
    parser.add_argument("--pub", help="receiver public key (for encrypt)")
    parser.add_argument("--priv", help="receiver private key (for decrypt)")
    parser.add_argument("--sender-priv", help="sender private key (for signing during encrypt)")
    parser.add_argument("--sender-pub", help="sender public key (for verification during decrypt)")
    args = parser.parse_args()

    if args.genkeys:
        os.makedirs(args.outdir, exist_ok=True)
        priv_path = os.path.join(args.outdir, "rsa_private.pem")
        pub_path = os.path.join(args.outdir, "rsa_public.pem")
        generate_rsa_keypair(priv_path, pub_path)
        print("Generated RSA keys in", args.outdir)

    if args.mode == "encrypt":
        if not args.infile or not args.pub:
            print("encrypt requires --infile and --pub (receiver public key). Use --genkeys to generate keys.")
            raise SystemExit(1)
        encrypt_pipeline(args.infile, args.outdir, args.pub, sender_priv_key=args.sender_priv)
    elif args.mode == "decrypt":

        ct_path = args.infile
        enc_key_path = os.path.join(args.outdir, "encrypted_key.bin")
        sig_path = os.path.join(args.outdir, "signature.bin")
        if not ct_path or not args.priv:
            print("decrypt requires --infile (ciphertext) and --priv (receiver private key)")
            raise SystemExit(1)
        decrypt_pipeline(ct_path, enc_key_path, sig_path, args.outdir, args.priv, sender_pub_key=args.sender_pub)

if __name__ == "__main__":
    main()
