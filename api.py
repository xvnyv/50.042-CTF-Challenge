import base64
import json
from json.decoder import JSONDecodeError
from flask import Flask, request
from util import decrypt, verify, BLOCK_SIZE

app = Flask(__name__)
flag = "CTF{Thanks for the money! Eve has awarded you 0.5 points for lab 10.}"
correct_mac = "pefmvxfrBjD87Nbk+Ah5nw=="
correct_ciphertext_length = 384
unaccepted_ciphertexts = [
    "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",
]


@app.route("/submit", methods=["POST"])
def submit():
    data = request.json
    if data is None:
        return {
            "plaintext": None,
            "flag": None,
            "message": "Please provide an encrypted message",
        }

    ciphertext = data.get("ciphertext", None)
    mac = data.get("mac", None)
    if ciphertext is None or mac is None:
        return {
            "plaintext": None,
            "flag": None,
            "message": 'Please provide data in the form of: {"ciphertext": <base64-encrypted-message>. "mac": <base64-mac>}',
        }

    if mac != correct_mac:
        return {
            "plaintext": None,
            "flag": None,
            "message": "Provided MAC does not match the intercepted MAC",
        }

    if ciphertext in unaccepted_ciphertexts:
        return {
            "plaintext": None,
            "flag": None,
            "message": "Nice try, but this looks like one of the given ciphertexts",
        }

    # if len(ciphertext) != 384:
    #     return {
    #         "plaintext": None,
    #         "flag": None,
    #         "message": "Incorrect ciphertext length",
    #     }
    try:
        ciphertext_in_bytes = base64.b64decode(ciphertext.encode())
        plaintext = decrypt(ciphertext_in_bytes)
    except:
        return {
            "plaintext": None,
            "flag": None,
            "message": "Incorrect modification caused an exception while decrypting ciphertext",
        }

    try:
        authentic = verify(plaintext, ciphertext_in_bytes[-BLOCK_SIZE:])
        if not authentic:
            return {
                "plaintext": plaintext.decode("unicode-escape"),
                "flag": None,
                "message": "Nice try, that message was not authentic",
            }
    except:
        return {
            "plaintext": plaintext.decode("unicode-escape"),
            "flag": None,
            "message": "Oops, we encountered an exception while verifying your MAC. Guess your message was not authentic...",
        }
    try:
        transaction_json = json.loads(plaintext.decode("unicode-escape"), strict=False)
    except JSONDecodeError:
        return {
            "plaintext": plaintext.decode("unicode-escape"),
            "flag": None,
            "message": "JSON decoding error",
        }
    try:
        if (
            transaction_json["timestamp"] != "2022-01-01 00:00:00"
            or float(transaction_json["amount"]) <= 100.00
            or transaction_json["receiver_account_id"] != "CBA54321XZ"
            or transaction_json["receiver_account_name"] != "Eve's Extra Income"
        ):
            return {
                "plaintext": plaintext.decode("unicode-escape"),
                "flag": None,
                "message": "Oops, your message modifications did not meet Eve's requirements",
            }
    except KeyError:
        return {
            "plaintext": plaintext.decode("unicode-escape"),
            "flag": None,
            "message": "Oops, your message modifications did not meet Eve's requirements",
        }
    return {
        "plaintext": plaintext.decode("unicode-escape"),
        "flag": flag,
        "message": "Congrats!",
    }


app.run(host="127.0.0.1", port="5000", debug=True)
