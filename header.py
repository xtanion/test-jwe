import json
import datetime
from jwcrypto import jwe, jwk
import base64

unix_time = int(datetime.datetime.timestamp(datetime.datetime.now()))
print(unix_time)

header = {
    "alg":"RSA-OAEP",
    "enc":"A256GCM",
    "x-hcx-timestamp": unix_time,
    "x-hcx-sender_code": "aesdc17d818f2yuchwci19ciui",
    "x-hcx-recipient_code": "cnq78ft21hf0919f0989vg2bu1089"
}

payload = {
    "name": "xtanion",
    "type": "student",
    "gender": "male",
    "education": "iitr"
}


def encrypt():
    with open("public.pem", "r") as f:
        key_cont = f.read()
    public_key = jwk.JWK.from_pem(key_cont.encode('utf-8'))
    enc_payload = jwe.JWE(str(json.dumps(payload)),
                          recipient=public_key, 
                          protected=json.dumps(header))
    enc = enc_payload.serialize(compact=True)
    with open("encfile.txt", "w") as e:
        e.write(enc)
    return enc

def decrypt(encrypted_string):
    enctxt = None
    with open("encfile.txt", "r") as e:
        enctxt = e.read()
    with open("private.pem", "r") as p:
        pkey = p.read()
    private_key = jwk.JWK.from_pem(pkey.encode("utf-8"))
    jwe_token = jwe.JWE()
    jwe_token.deserialize(encrypted_string, key=private_key)
    jwe_token.decrypt(key=private_key)
    print(jwe_token.payload)
    print(jwe_token.jose_header)


encrypted_text = encrypt()
decrypt(encrypted_text)