#!/usr/bin/env python
from Crypto.Cipher import AES
from Crypto.Util import Counter
# from rubenesque.codecs.sec import encode, decode
import rubenesque.curves
import hashlib
import socket
import rsa.key
import sys

private_key = None
asn256 = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'

def sexp_get_bytes(sexp, key, length):
    token = key + str(length).encode("utf-8") + b':'
    index = sexp.find(token) + len(token)
    return sexp[ index: index + length ]

def sexp_get_key(sexp, key):
    len_start = sexp.find(key) + len(key)
    len_end = len_start + sexp[len_start:].find(b':')
    length = int(sexp[len_start: len_end])
    return sexp_get_bytes(sexp, key, length)

def derive_key(dh_bytes):
    sha256 = hashlib.sha256()
    dh_x = dh_bytes[0:32]
    dh_y = dh_bytes[32:64]
    #sha256.update(dh_str.encode("utf-8"))
    dh_x_int = int.from_bytes(dh_x, byteorder='big')
    dh_x_int_little = int.from_bytes(dh_x, byteorder='little')
    dh_x_hex_big = hex(dh_x_int)[2:]
    dh_x_hex_little = hex(dh_x_int_little)[2:]
    print("feeding sha with")
    print(dh_x_hex_little)
    sha256.update(dh_x_hex_little.encode("utf-8"))
    print("SHA256")
    print(sha256.digest())
    return sha256.digest()

def get_ga_from_quote(quote):
    secp256r1 = rubenesque.curves.find("secp256r1")

    report = quote[48:432]
    ga_xy = report[320:384]
    ga_x = int.from_bytes(ga_xy[0:32], byteorder='big')
    ga_y = int.from_bytes(ga_xy[32:64], byteorder='big')

    ga_x_little = int.from_bytes(ga_xy[0:32], byteorder='little')
    ga_y_little = int.from_bytes(ga_xy[32:64], byteorder='little')

    return (secp256r1(ga_x, ga_y), secp256r1(ga_x_little, ga_y_little))

def gen_dh_keypair():
    secp256r1 = rubenesque.curves.find("secp256r1")
    b = secp256r1.private_key()
    gb = secp256r1.generator() * b
    # print(gb)
    # print(encode(gb))
    # print(hex(gb.x))
    # print(hex(gb.y))
    return b, gb

def encrypt(pt, key):
    ctr = Counter.new(128)
    ciph = AES.new(key, mode = AES.MODE_CTR, counter = ctr)
    ct = ciph.encrypt(pt.encode("utf-8"))
    return ct

def decrypt(ct, key):
    ctr = Counter.new(128)
    ciph = AES.new(key, mode = AES.MODE_CTR, counter = ctr)
    pt = ciph.decrypt(ct)
    print("Plaintext")
    print(pt)
    return pt

def genkey(keyid):
    k = str(keyid)
    l = len(k)
    res = "((9:operation6:genkey)(8:username9:test_user))(5:keyid{0}:{1})".format(l, k)
    return res.encode("utf-8")

def readkey(keyid):
    k = str(keyid)
    l = len(k)
    res = "((9:operation7:readkey)(8:username9:test_user))(5:keyid{0}:{1})".format(l, k)
    return res.encode("utf-8")

def set_ecc_key():
    return b"((9:operation10:setkeytype)(8:username9:test_user)(10:keytypestr3:ecc))"

def set_rsa_key():
    return b"((9:operation10:setkeytype)(8:username9:test_user)(10:keytypestr3:rsa))"

def keyattr():
    return b"((9:operation7:keyattr)(8:username9:test_user))"

def getquote():
    return b"((9:operation8:getquote))"

def test_enc(sock, key, gb_bytes):
    to_encrypt = "((9:operation6:genkey)(8:username9:test_user))"
    ct = encrypt(to_encrypt, key)
    decrypt(ct, key)

    hex_enc = hex(int.from_bytes(ct,byteorder='big'))[2:]

    bundle = b"((4:data" + "{0}".format(len(ct)).encode("utf-8") +\
             b":" + ct + b")(2:gb" + "{0}".format(len(gb_bytes)).encode("utf-8") +\
             b":" + gb_bytes + b"))"

    print("Sending")
    print(bundle)
    sock.send(bundle)
    print(sock.recv(4096))

def process_keyattr(sock, settings):
    sock.send(keyattr())
    s = sock.recv(4096)

    #for i in [b"key1_fpr", b"key2_fpr", b"key3_fpr"]:
    #    b = sexp_get_key(s, i)
    #    print("Key finger print in hex {0}".format(b.hex()))

    #for i in [b"key1_algo", b"key2_algo", b"key3_algo"]:
    #    b = sexp_get_key(s, i)
    #    print("Key algo {0}".format(b))

    print(s)

def process_genkey(sock, settings):
    sock.send(genkey(settings["keyid"]))
    print(sock.recv(4096))

def process_readkey(sock, settings):
    sock.send(readkey(settings["keyid"]))
    print(sock.recv(4096))

def process_set_ecc_key(sock, settings):
    sock.send(set_ecc_key())
    print(sock.recv(4096))

def process_set_rsa_key(sock, settings):
    sock.send(set_rsa_key())
    print(sock.recv(4096))

def process_quote(sock, settings):
    sock.send(getquote())
    quote = sock.recv(4096)
    ga, ga_little = get_ga_from_quote(quote)
    b, gb = gen_dh_keypair()
    gb_str = hex(gb.x)[2:] + hex(gb.y)[2:]
    gb_bytes = int.to_bytes(gb.x, length=32, byteorder='big') + int.to_bytes(gb.y, length=32, byteorder='big')
    print("Gb string and len")
    print(gb_str)
    dh = ga*b
    dh_str = hex(dh.x)[2:] + hex(dh.y)[2:]
    print("Shared key: " + dh_str)
    dh_bytes = int.to_bytes(dh.x, length=32, byteorder='big') + int.to_bytes(dh.y, length=32, byteorder='big')
    key = derive_key(dh_bytes)[0:16]
    print("Derived key len and key")
    print(len(key))
    print(key)

    test_enc(sock, key, gb_bytes)

def main(args):
    #s = b"((9:operation14:benchmark_sign)(4:data32:0123456789ABCDEF0123456789ABCDEF))"
    commands = {"genkey": (process_genkey, "Generate a key"),
                "readkey": (process_readkey, "Read an existing key"),
                "quote": (process_quote, "Obtain the quote from the enclave"),
                "keyattr": (process_keyattr, "Get key attributes"),
                "ecc": (process_set_ecc_key, "Set the key type to EC"),
                "rsa": (process_set_rsa_key, "Set the key type to RSA")}

    options = {"-p, --port": (int, "Cloud Key Store server port", "port", 7000),
               "-k, --keyid": (int, "The key id to pass to CKS", "keyid", 1)}
    settings = {}
    for k, v in options.items():
        settings[ v[2] ] = v[3]

    if (len(args) == 1) or (args[-1] not in commands.keys()):
        print("""
  Usage: client <command>
  Commands:""")
        for k, v in commands.items():
            print("    {0: <10} {1}".format(k, v[1]))

        print("""

  Options:""")
        for k, v in options.items():
            print("    {0: <12} {1}".format(k, v[1]))

        return

    for k, v in options.items():
        a_spec = k.split(", ")
        for a in a_spec:
            if a in args:
                try:
                    parse_func = options[k][0]
                    settings[ v[2] ] = parse_func(args[args.index(a) + 1])
                except IndexError:
                    pass


    upstream = socket.socket()
    try:
        upstream.connect(("localhost", settings["port"]))
    except ConnectionRefusedError:
        print("Could not connect to CKS at localhost:{0}".format(settings["port"]))
        return

    p = commands[args[-1]][0]

    p(upstream, settings)
    upstream.close()

if __name__ == "__main__":
    main(sys.argv)
