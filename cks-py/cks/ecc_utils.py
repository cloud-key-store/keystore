#!/usr/bin/env python
import hashlib
import rubenesque.curves
from rubenesque.signatures.ecdsa import sign as ecdsa_sign
from . import sexp

def gen_ecc_key():
    secp256r1 = rubenesque.curves.find("secp256r1")
    private_ecc_key = secp256r1.private_key()
    public_ecc_key = secp256r1.generator() * private_ecc_key
    return (public_ecc_key, private_ecc_key)

def ecc_pksign(s, private_ecc_key):
    md_bytes = sexp.sexp_get_key(s, b'data')
    secp256r1 = rubenesque.curves.find("secp256r1")
    r, s = ecdsa_sign(secp256r1, private_ecc_key, md_bytes)
    print("r: {0}".format(r))
    print("s: {0}".format(s))
    return (int.to_bytes(r, byteorder='big', length=32), int.to_bytes(s, byteorder='big', length=32))

def wrap_sha(sha1, b):
    #print(b, end = '  ')
    sha1.update(b)

def ecc_keyfpr(ts, public_ecc_key):
    # Hash of 0x99, 2 byte length
    # 1 byte version(4), timestamp 4 bytes, algo 1 byte
    sha1 = hashlib.sha1()
    n = 6 + 9 + 67
    wrap_sha(sha1, b'\x99')
    wrap_sha(sha1, int.to_bytes(n, 2, 'big'))
    wrap_sha(sha1, b'\x04')

    wrap_sha(sha1, int.to_bytes(ts, 4, 'big'))
    wrap_sha(sha1, b'\x13')
    wrap_sha(sha1, int.to_bytes(8, 1, 'big'))
    oid = b'\x2a\x86\x48\xce\x3d\x03\x01\x07'
    wrap_sha(sha1, oid)
    wrap_sha(sha1, int.to_bytes(515, 2, 'big'))
    wrap_sha(sha1, b'\x04')
    wrap_sha(sha1, int.to_bytes(public_ecc_key.x, 32, 'big'))
    wrap_sha(sha1, int.to_bytes(public_ecc_key.y, 32, 'big'))
    return sha1.hexdigest()

def import_ecc_key(s):
    secp256r1 = rubenesque.curves.find("secp256r1")
    q_bytes = sexp.sexp_get_bytes(s, b'q', 65)
    x = int.from_bytes(q_bytes[1:33], byteorder='big')
    y = int.from_bytes(q_bytes[33:65], byteorder='big')

    d_bytes = sexp.sexp_get_bytes(s, b'd', 32)
    d = int.from_bytes(d_bytes, byteorder='big')
    private_ecc_key = d
    public_ecc_key = secp256r1.generator() * d

    ts_bytes = sexp.sexp_get_bytes(s, b'created-at', 10)
    ts = int(ts_bytes)

    # x_little = x.to_bytes(32, byteorder='little')
    # print("x_little in hex: {0}".format(x_little.hex()))
    # y_little = y.to_bytes(32, byteorder='little')
    # print("y_little in hex: {0}".format(y_little.hex()))

    return (public_ecc_key, private_ecc_key, ts)

def import_pub_ecc_key(s):
    secp256r1 = rubenesque.curves.find("secp256r1")
    q_bytes = sexp.sexp_get_bytes(s, b'q', 65)
    x = int.from_bytes(q_bytes[1:33], byteorder='big')
    y = int.from_bytes(q_bytes[33:65], byteorder='big')

    public_ecc_key = secp256r1.create(x, y)

    ts_bytes = sexp.sexp_get_bytes(s, b'created-at', 10)
    ts = int(ts_bytes)

    # x_little = x.to_bytes(32, byteorder='little')
    # print("x_little in hex: {0}".format(x_little.hex()))
    # y_little = y.to_bytes(32, byteorder='little')
    # print("y_little in hex: {0}".format(y_little.hex()))

    return (public_ecc_key, ts)

def import_priv_ecc_key(d_bytes):
    secp256r1 = rubenesque.curves.find("secp256r1")

    d = int.from_bytes(d_bytes, byteorder='big')
    private_ecc_key = d

    public_ecc_key = secp256r1.generator() * d

    # x_little = x.to_bytes(32, byteorder='little')
    # print("x_little in hex: {0}".format(x_little.hex()))
    # y_little = y.to_bytes(32, byteorder='little')
    # print("y_little in hex: {0}".format(y_little.hex()))

    return (public_ecc_key, 0)

def read_ecc_key(public_ecc_key):
    pub = public_ecc_key
    pub_x_hex = hex(pub.x)[2:]
    pub_y_hex = hex(pub.y)[2:]
    try:
        pub_x_bytes = bytes.fromhex(pub_x_hex)
        pub_y_bytes = bytes.fromhex(pub_y_hex)
    except ValueError as e:
        print("Value error when bytes from hex of key X or Y")
        print(e)

    key = b"(10:public-key(3:ecc(5:curve10:NIST P-256)(1:q65:" + b"\x04" + pub_x_bytes + pub_y_bytes + b")))\00"
    return key

def pub_ecc_key_to_sexp(pub, with_prefix = False):
    pub_x_hex = hex(pub.x)[2:]
    pub_y_hex = hex(pub.y)[2:]
    while len(pub_x_hex) < 64:
       pub_x_hex = "0" + pub_x_hex
    while len(pub_y_hex) < 64:
       pub_y_hex = "0" + pub_y_hex
    pub_x_bytes = pub_x_hex.encode("utf-8")
    pub_y_bytes = pub_y_hex.encode("utf-8")
    if with_prefix:
        prefix_byte = b'\x04'
        len_bytes = "{0}".format(1+len(pub_x_hex)+len(pub_y_hex)).encode("utf-8")
    else:
        prefix_byte = b''
        len_bytes = "{0}".format(len(pub_x_hex)+len(pub_y_hex)).encode("utf-8")

    return b"(1:q" + len_bytes + b":" + prefix_byte + pub_x_bytes + pub_y_bytes + b")"
