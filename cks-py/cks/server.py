#!/usr/bin/env python
# from Crypto.Cipher import AES
# from Crypto.Util import Counter
# from rubenesque.codecs.sec import encode, decode
import socket
import time
from . import rsa_utils
from . import ecc_utils
from . import sexp

#from flask import Flask
#app = Flask(__name__)

#@app.route("/sign")
def sign():
    #for i in range(10):
        upstream = socket.socket()
        upstream.connect(("localhost", 7000))
        upstream.send(b"((9:operation6:pksign)(4:data32:0123456789ABCDEF0123456789ABCDEF))")
        res = upstream.recv(4096)
        #print(res)
        upstream.close()
        return res

def main():
    l_sock = socket.socket()
    l_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    l_sock.bind(("localhost", 7000))
    l_sock.listen(0)

    key_db = {}

    while True:
        client, addr = l_sock.accept()
        #upstream = socket.socket()
        #upstream.connect(("localhost", 7001))
        s = client.recv(4096)
        #upstream.send(s)

        buf = process(s, key_db)

        #print("Local processing result")
        #print(buf)

        #print("Getting response from upstream")
        #print(upstream.recv(4096))

        client.send(buf)
        time.sleep(2)
        client.close()
        #upstream.close()

openpgp_key_to_int = {"OPENPGP.1": 0, "OPENPGP.2": 1, "OPENPGP.3": 2}

def process(s, key_db):
    print(s)
    operation = sexp.sexp_get_key(s, b'operation')
    user = sexp.sexp_get_key(s, b'username')
    print(operation)
    print(user)
    if user not in key_db:
        key_db[user] = []

    if operation == b"setkeytype":
        key_db[user].append( (sexp.sexp_get_key(s, b"keytypestr").decode("utf-8"),
            None, None, None) )

    if operation == b'genkey':
        keyid = sexp.sexp_get_key(s, b"keyid").decode("utf-8")
        try:
            keyid = openpgp_key_to_int[keyid]
        except KeyError:
            keyid = int(keyid) - 1

        print("Keyid: {0}".format(keyid))

        if len(key_db[user]) > 0:
            new_key_type = key_db[user][0][0]
            if key_db[user][0][1] is None:
                key_db[user] = [None, None, None]
        else:
            new_key_type = "rsa"

        key_type, pub, priv, ts = gen_key(new_key_type)
        key_db[user][keyid] = (key_type, pub, priv, ts)
        return pub_key_to_sexp(pub, key_type)

    if operation == b'keyattr':
        return keyattr(key_db[user])

    if operation == b'readkey':
        keyid = sexp.sexp_get_key(s, b"keyid").decode("utf-8")
        print("Keyid: {0}".format(keyid))
        try:
            keyid = openpgp_key_to_int[keyid]
        except KeyError:
            keyid = int(keyid)
        try:
            s = read_key(key_db[user][keyid])
        except IndexError:
            return b'OK'
        return read_key(key_db[user][keyid])

    if operation == b'writekey':
        key_type, pub, priv, ts = import_key(s)
        key_db[user].append( (key_type, pub, priv, ts) )
        return b"OK"

    if operation == b'pksign':
        keyid = sexp.sexp_get_key(s, b"signing_key").decode("utf-8")
        print("Keyid: {0}".format(keyid))
        sig = pksign(key_db[user][openpgp_key_to_int[keyid]], s)

        # verify(key_db, s, sig)
        return sig

    if operation == b'pkdecrypt':
        dec = pkdecrypt(key_db, s)
        dec_bytes = bytearray(int.to_bytes(dec, byteorder="big", length=384))[1:]
        #dec_bytes[0] = 0x02
        # mpi_get_buffer already remove the leading zero
        # Also only if no card, it scans till zero and skips it
        zero_ind = dec_bytes.find(b'\x00')
        #return bytes(dec_bytes[zero_ind + 1:])
        return int.to_bytes(dec, byteorder="big", length=384)
    return b"OK"

def pub_key_to_sexp(pub, key_type = "rsa"):
    if key_type == "rsa":
        return rsa_utils.pub_rsa_key_to_sexp(pub)
    elif key_type == "ecc":
        return ecc_utils.pub_ecc_key_to_sexp(pub)
    else:
        return b"()"

def gen_key(key_type = "rsa"):
    ts = int(time.time())
    if key_type == "rsa":
        pub, priv = rsa_utils.gen_rsa_key()
        return key_type, pub, priv, ts

    elif key_type == "ecc":
        print("Generating EC key")
        pub, priv = ecc_utils.gen_ecc_key()
        return key_type, pub, priv, ts
    else:
        return None, None, None, ts
 
def verify(key_db, s, sig_bytes, key_type = "rsa"):
    sig = int.from_bytes(sig_bytes, byteorder='big')
    if key_type == "rsa":
        return rsa_utils.rsa_verify(s, sig_bytes, key_db[0][0])
    return False

def pksign(key, s):
    key_type, pub, priv, ts = key
    if key_type == "rsa":
        return rsa_utils.rsa_pksign(s, priv)
    elif key_type == "ecc":
        r, s = ecc_utils.ecc_pksign(s, priv)
        r_len = "{0}".format(len(r)).encode("utf-8")
        s_len = "{0}".format(len(s)).encode("utf-8")
        return b"(1:r" + r_len + b":" + r + b")(1:s" + s_len + b":" + s + b")"

def pkdecrypt(key_db, s):
    return rsa_utils.rsa_pkdecrypt(s, key_db[0][1])

def import_key(s):
    rsa_token = s.find(b"rsa")
    print( "rsa token: {0}".format(rsa_token) )
    ecc_token = s.find(b"ecc")
    print( "ecc token: {0}".format(ecc_token) )

    if rsa_token != -1:
        pub, priv, ts = rsa_utils.import_rsa_key(s)
        return ("rsa", pub, priv, ts)
    elif ecc_token != -1:
        pub, priv, ts = ecc_utils.import_ecc_key(s)
        return ("ecc", pub, priv, ts)
    else:
        print( "unknown key type" )
        return (None, None, None, None)

def read_key(key):
    key_type, pub, priv, ts = key
    if key_type == "ecc":
        key = b"(10:public-key(3:ecc(5:curve10:NIST P-256)" + \
               ecc_utils.pub_ecc_key_to_sexp(pub, True) + b"))\00"
        return key
    return b""


def keyattr(keys):
    res = b""
    key_no = 1
    for key in keys:
        key_type, pub, priv, ts = key
        key_no_bytes = ("{0}".format(key_no)).encode("utf-8")

        fpr = "e4c23edf561c6688b68471bc63d757e5618c5148"
        if key_type == "rsa":
            key_algo_sexp_bytes = b"(9:key" + key_no_bytes + b"_algo6:1 3072)"
            if pub is not None:
                fpr = rsa_utils.rsa_keyfpr(ts, pub)
        elif key_type == "ecc":
            if key_no == 2:
                algo_bytes = b"18 NIST P-256"
            else:
                algo_bytes = b"19 NIST P-256"
            key_algo_sexp_bytes = b"(9:key" + key_no_bytes + b"_algo13:" + algo_bytes + b")"
            if pub is not None:
                fpr = ecc_utils.ecc_keyfpr(ts, pub)
        else:
            continue

        fpr_bytes = bytes.fromhex(fpr)

        key_fpr_sexp_bytes = b"(8:key" + key_no_bytes + b"_fpr20:" + fpr_bytes + b")"
        res = res + b"(" + key_algo_sexp_bytes + key_fpr_sexp_bytes + b")"

        key_no = key_no + 1
    return res

def sexp_get_bytes(sexp, key, length):
    token = key + str(length).encode("utf-8") + b':'
    index = sexp.find(token) + len(token)
    return sexp[ index: index + length ]

def sexp_get_key(sexp, key):
    len_start = sexp.find(key) + len(key)
    len_end = len_start + sexp[len_start:].find(b':')
    #print("Finding {0} at {1} till {2}".format(str(key), len_start, len_end))
    length = int(sexp[len_start: len_end])
    return sexp_get_bytes(sexp, key, length)

if __name__ == "__main__":
    main()
