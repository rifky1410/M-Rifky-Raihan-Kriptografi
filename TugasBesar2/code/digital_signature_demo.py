import argparse
from rsa_example import generate_rsa_keypair, save_key, load_key, rsa_sign, rsa_verify
from Crypto.Hash import SHA256

def demo():
    priv, pub = generate_rsa_keypair(2048)
    save_key(priv, "sig_private.pem")
    save_key(pub, "sig_public.pem")
    print("Generated keys: sig_private.pem, sig_public.pem")

    message = b"Pesan untuk ditandatangani"
    signature = rsa_sign(message, priv)
    print("Message:", message)
    print("Signature (len):", len(signature))
    ok = rsa_verify(message, signature, pub)
    print("Verify result:", ok)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Digital signature demo")
    parser.add_argument("--demo", action="store_true", help="run demo")
    args = parser.parse_args()
    if args.demo:
        demo()
    else:
        demo()
