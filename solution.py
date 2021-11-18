import base64
import json
import requests

if __name__ == "__main__":
    with open("encrypted_transactions.txt", "r") as f:
        ciphertexts_n_macs = f.read().split("\n")

    # identify that last the block of the ciphertext and MAC are the same
    # infer that the same key was used for both encryption and generating MAC
    ciphertexts = []
    for c_and_m in ciphertexts_n_macs:
        encoded_c, encoded_m = c_and_m.split(",")
        c = base64.b64decode(encoded_c.encode())
        m = base64.b64decode(encoded_m)

        ciphertexts.append(c)
        print(c)
        print(m)
        print()

    # now the plan will be to use one of the ciphertexts in the list to modify the given ciphertext
    # we can replace blocks of ciphertext without affecting the MAC
    # however the block after our last replaced block will be garbage
    # since the challenge only checks for the amount, receiver_account_id, receiver_account_name and timestamp,
    # we can try replacing different numbers of blocks to see where the garbage block can be inserted such that
    # the server still verifies it as correct (ie. meets Eve's requirements)

    # identify the plaintext at each block
    # observe that block 7 to block 11 can accept the garbage block
    given_data = {
        "amount": "100.00",
        "receiver_account_id": "CBA54321XZ",
        "receiver_account_name": "Eve's Extra Income",
        "sender_account_id": "ABC12345ZQ",
        "sender_account_name": "Alice's Savings",
        "timestamp": "2022-01-01 00:00:00",
        "transaction_status": "pending",
        "transaction_type": "transfer",
    }
    data_bytes = json.dumps(given_data).encode()
    for i in range(0, len(data_bytes), 16):
        print(data_bytes[i : i + 16])

    # since we will not know which ciphertext contains the transaction for which account
    # we can loop through all accounts and try them out to see which one contains Eve's account
    # only those with Eve's account can be used to modify the intercepted ciphertext

    # also, since we know that AES-CBC decryption works by XOR-ing the ciphertext of the previous
    # block with the decrypted value of the current block to get the plaintext,
    # we can add one overlap block so that we will be adding a garbage block instead of replacing
    # a legitimate block with a garbage block
    # this makes it esaier to hide the garbage block within the json
    given_ciphertext = "dCIKPyYB2uxmPCDIMyayylLl3sjkDiBpK+bWpZONsnnHQgszM/ztD2syZU4/rPVIsS/VxqhxxmvOpinKP+j+kXKAKYUA9Jx08XH0JUYi4n0tkQJtPi/LooKvpsmTKbc+ibVCVz31xnxoFtOvtu0nNmJRUMvTjabXoNrter708AL4RSURq1VBTylMXWqzboyar/8LUOF+w+Ni+EKq07jJ9zsAgHoyulc7Vbe11o80IlKxokeJj6sCtvwXqoBwXiR4nlp+d4P56p7bwkOczMa4WTI0bFCpNw2eSqvO6hymAuPeZXpVHvL/w2buLkdHLWmYMP7CjHLxm72PWu3zqG02+sV04/nZQfYY0r3K2SfvVdil5+a/F+sGMPzs1uT4CHmf"
    given_mac = "pefmvxfrBjD87Nbk+Ah5nw=="
    ciphertext_bytes = base64.b64decode(given_ciphertext.encode())

    for c in ciphertexts:
        modified_ciphertext_bytes = c[:128] + ciphertext_bytes[112:]
        modified_ciphertext = base64.b64encode(modified_ciphertext_bytes).decode()
        print(modified_ciphertext)
        print()

        # we test each modified ciphertext against the given API and see which ciphertext can give the flag
        # there is only one ciphertext that will produce the flag as there is only one transaction with Eve in the list of ciphertexts
        res = requests.post(
            "http://localhost:5000/submit",
            data=json.dumps({"ciphertext": modified_ciphertext, "mac": given_mac}),
            headers={"Content-Type": "application/json"},
        )
        print(res.json())
