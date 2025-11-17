from Crypto.Hash import MD5, SHA1, SHA256

def hash_md5(data: bytes) -> str:
    h = MD5.new()
    h.update(data)
    return h.hexdigest()

def hash_sha1(data: bytes) -> str:
    h = SHA1.new()
    h.update(data)
    return h.hexdigest()

def hash_sha256(data: bytes) -> str:
    h = SHA256.new()
    h.update(data)
    return h.hexdigest()

def avalanche_demo(msg: bytes, changed_msg: bytes):
    print("Original:", msg)
    print("Modified:", changed_msg)
    print("MD5   :", hash_md5(msg), " / ", hash_md5(changed_msg))
    print("SHA1  :", hash_sha1(msg), " / ", hash_sha1(changed_msg))
    print("SHA256:", hash_sha256(msg), " / ", hash_sha256(changed_msg))

if __name__ == "__main__":
    m1 = b"Hello, dunia!"
    # ubah 1 byte/karakter
    m2 = b"Hella, dunia!"
    avalanche_demo(m1, m2)
