from Crypto.Cipher import AES

BLOCK_SIZE = AES.block_size
KEY = b"OhLFDWo9f/gBw1f3KtoJdw=="

# padding scheme: 10000000...
def pad_data(data: bytes, block_size: int) -> bytes:
    data += int.to_bytes(128, 1, byteorder="big")
    remaining_bits = len(data) % block_size
    if remaining_bits != 0:
        data += int.to_bytes(0, 1, byteorder="big") * (block_size - remaining_bits)
    return data


def unpad_data(data: bytes) -> bytes:
    data = data.rstrip(int.to_bytes(0, 1, byteorder="big"))
    data = data.rstrip(int.to_bytes(128, 1, byteorder="big"))
    return data


def encrypt(data: bytes):
    cipher = AES.new(KEY, AES.MODE_CBC, iv=(0).to_bytes(BLOCK_SIZE, byteorder="big"))
    ciphertext = cipher.encrypt(
        pad_data(
            data,
            BLOCK_SIZE,
        )
    )
    print(
        "padded data: ",
        pad_data(
            data,
            BLOCK_SIZE,
        ),
    )
    return ciphertext


def decrypt(ciphertext: bytes):
    cipher = AES.new(KEY, AES.MODE_CBC, iv=(0).to_bytes(BLOCK_SIZE, byteorder="big"))
    plaintext = cipher.decrypt(ciphertext)
    return unpad_data(plaintext)


def generate_mac(data: bytes):
    return encrypt(data)[-BLOCK_SIZE:]


def verify(plaintext: bytes, mac: bytes):
    verify_cipher = AES.new(
        KEY, AES.MODE_CBC, iv=(0).to_bytes(BLOCK_SIZE, byteorder="big")
    )
    verification = verify_cipher.encrypt(pad_data(plaintext, BLOCK_SIZE))
    return verification[-BLOCK_SIZE:] == mac


def byte_xor(*args):
    if len(args) == 0:
        return 0
    res = 0
    byte_length = len(args[0])
    for b in args:
        res = res ^ int.from_bytes(b, "big")
    return res.to_bytes(byte_length, "big")
