from Crypto.PublicKey import RSA
import os
from pydash import py_
import math


file_list = os.listdir("./challenge")
pem_file_list = py_.filter(file_list, lambda x: x.find(".pem") > 0 and x.find("private") < 0)
pub_keys = []
pem_files = []
vul_pem_files = []
vul_keys = []
vul_file_name = []
vul_file_names = []


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b//a) * y, y


def mod_inv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x % m


def find_vul_keys(pub_key, o_key):
    gcd = math.gcd(pub_key, o_key)
    if gcd != 1:
        file = py_.find(pem_files, lambda x: py_.includes(x, pub_key))
        key_number = list(file.keys())[0]
        if pub_key % gcd == 0 and pub_key == gcd * (pub_key // gcd):
            return key_number, pub_key, gcd, pub_key // gcd


for file_name in pem_file_list:
    pem_file = open("./challenge/" + file_name).read()
    key = RSA.importKey(pem_file)
    pem_files.append({file_name[:-4]: key.n})
    pub_keys.append(key.n)


for pub_key in pub_keys:
    other_keys = py_.filter(pub_keys, lambda x: pub_keys.index(x) != pub_keys.index(pub_key))
    for o_key in other_keys:
        vul_keys.append(find_vul_keys(pub_key, o_key))


vul_keys = py_.compact(vul_keys)


for vul_key in vul_keys:
    file_number = vul_key[0]
    p = vul_key[2]
    q = vul_key[3]
    pem_file = open("./challenge/" + file_number + ".pem").read()
    pub_key = RSA.importKey(pem_file)
    n = pub_key.n
    e = pub_key.e
    phi = (p-1) * (q-1)
    d = mod_inv(e, phi)
    private_key = RSA.construct((n, e, d))
    with open("./challenge/" + file_number + ".private.pem", "wb") as f:
        f.write(private_key.exportKey())
