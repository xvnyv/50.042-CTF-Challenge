import json
import datetime
import random
import base64
from util import encrypt, decrypt, verify, generate_mac


n = 20
accounts = [
    {"name": "Bob's Bank", "id": "BCD54321XY"},
    {"name": "Carl's Cash", "id": "CEB12321QY"},
    {"name": "Dora's Backpack", "id": "BEA95321QP"},
    # {"name": "Eve's Extra Income", "id": "CBA54321XZ"},
    {"name": "Freddo's Funds", "id": "AED87493MQ"},
]
date_element_ranges = {
    "year": (2015, 2021),
    "month": (1, 12),
    "day": (1, 28),
    "hour": (0, 23),
    "minute": (0, 59),
    "second": (0, 59),
}


def generate_random_date(
    year: int = None,
    month: int = None,
    day: int = None,
    hour: int = None,
    minute: int = None,
    second: int = None,
):
    date_args = locals()
    for var, val in date_args.items():
        if val is None:
            date_args[var] = random.randint(
                date_element_ranges[var][0], date_element_ranges[var][1]
            )

    return datetime.datetime(
        date_args["year"],
        date_args["month"],
        date_args["day"],
        date_args["hour"],
        date_args["minute"],
        date_args["second"],
    ).strftime("%Y-%m-%d %H:%M:%S")


def generate_ciphertexts():
    data = {
        "amount": None,
        "receiver_account_id": None,
        "receiver_account_name": None,
        "sender_account_id": "ABC12345ZQ",
        "sender_account_name": "Alice's Savings",
        "timestamp": None,
        "transaction_status": "pending",
        "transaction_type": "transfer",
    }
    ciphertexts = []
    for i in range(n):
        cur_data = data.copy()
        cur_data["amount"] = str(round(random.uniform(100.00, 999.99), 2))
        cur_data["timestamp"] = generate_random_date(year=2021)
        chosen_receiver = random.choice(accounts)
        cur_data["receiver_account_id"] = chosen_receiver["id"]
        cur_data["receiver_account_name"] = chosen_receiver["name"]
        cur_data = json.dumps(cur_data).encode()

        ciphertext = encrypt(cur_data)
        encoded_ciphertext = base64.b64encode(ciphertext).decode()
        mac = generate_mac(cur_data)
        encoded_mac = base64.b64encode(mac).decode()
        ciphertexts.append("{},{}".format(encoded_ciphertext, encoded_mac))

    with open("encrypted_transactions.txt", "w") as f:
        f.write("\n".join(ciphertexts))


def decrypt_ciphertexts():
    with open("encrypted_transactions.txt", "r") as f:
        ciphertexts_n_macs = f.read().split("\n")

    for c_and_m in ciphertexts_n_macs:
        encoded_c, encoded_m = c_and_m.split(",")
        c = base64.b64decode(encoded_c.encode())
        p = decrypt(c)
        m = base64.b64decode(encoded_m)
        authentic = verify(p, m)
        print("Ciphertext: ", encoded_c)
        print("MAC: ", encoded_m)
        print("Plaintext: ", p.decode())
        print("Authentic: ", authentic)
        print()


def create_intercepted_message():
    data = json.dumps(
        {
            "amount": "100.00",
            "receiver_account_id": "CBA54321XZ",
            "receiver_account_name": "Eve's Extra Income",
            "sender_account_id": "ABC12345ZQ",
            "sender_account_name": "Alice's Savings",
            "timestamp": "2022-01-01 00:00:00",
            "transaction_status": "pending",
            "transaction_type": "transfer",
        }
    ).encode()
    ciphertext = encrypt(data)
    mac = generate_mac(data)
    print("Ciphertext")
    print(base64.b64encode(ciphertext).decode())
    print("MAC")
    print(base64.b64encode(mac).decode())


def decrypt_intercepted_message():
    ciphertext = "zx2Zh6hRkwJE66JX5soSK3q/NXWnp9RfBxebOiktXQ/IiYTXWm+XzHosIPXfmCHso6H3ltWXjqSQG7cl9tCmzt+4mUF5Zsc2mNuQrUMA+9tzE5pbuPf0pqkLoord7JF13f0eahfsTVx/8k+jnqOSV7TLLvNuU8v9CnZhhcJUIQtSvRlw2vm5k47H+V3K7EsB9UREG2fD3t3+MNQ7NENJXT7jwU4OjCDWVve9xtOI4ACZ/3c0wKEiyxTkIO5xMWP1nnlpF/TRFYiPa3A26WeJZcIiVq95ywp7V78JU0Y/H2hM/OpVKtuSv9ObteTK4kHPQaZvAhH4kmq5giFLCodIlqdymOP7Itw4FKbQoGR164aFJBeLrQGft1VZsj92NGIl"
    mac = "hSQXi60Bn7dVWbI/djRiJQ=="
    plaintext = decrypt(base64.b64decode(ciphertext.encode()))
    authentic = verify(plaintext, base64.b64decode(mac.encode()))
    print("Plaintext:")
    print(plaintext.decode())
    print("Authentic:", authentic)


if __name__ == "__main__":
    generate_ciphertexts()
    # decrypt_ciphertexts()
    # create_intercepted_message()
    # decrypt_intercepted_message()
