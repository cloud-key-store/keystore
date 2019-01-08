#!/usr/bin/env python
import hashlib
import rsa.key
from . import sexp

def gen_rsa_key():
    public_rsa_key, private_rsa_key = rsa.key.newkeys(3072)
    print("n")
    print(private_rsa_key.n)
    print("e")
    print(private_rsa_key.e)
    print("p")
    print(private_rsa_key.p)
    print("q")
    print(private_rsa_key.q)
    return (public_rsa_key, private_rsa_key)

def rsa_pksign(s, private_rsa_key):
    md_bytes = sexp.sexp_get_key(s, b'data')
    frame_bytes = get_frame( md_bytes )
    padded_int = int.from_bytes(frame_bytes, byteorder='big')
    signature = pow(padded_int, private_rsa_key.d, private_rsa_key.n)
    return int.to_bytes(signature, byteorder='big', length=384)

def rsa_pkdecrypt(s, private_rsa_key):
    data = sexp.sexp_get_key(s, b'data')
    data_int = int.from_bytes(data, byteorder='big')
    dec = pow(data_int, private_rsa_key.d, private_rsa_key.n)
    return dec

def rsa_verify(s, sig_bytes, public_rsa_key):
    return True

asn256 = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'

def get_frame(md):
    frame = b'\x00\x01'
    padlen = 384 - len(md) - len(asn256) - 3
    frame += b'\xff'*padlen
    frame += b'\x00'
    frame += asn256
    frame += md
    print("Frame: {0}".format(frame))
    return frame

def wrap_sha(sha1, b):
    #print(b, end = '  ')
    sha1.update(b)

def rsa_keyfpr(ts, public_rsa_key):
    # Hash of 0x99, 2 byte length
    # 1 byte version(4), timestamp 4 bytes, algo 1 byte
    sha1 = hashlib.sha1()
    n = 6 + 386 + 5
    exponent = 65537
    n_bytes = int.to_bytes(public_rsa_key.n, 384, 'big')
    wrap_sha(sha1, b'\x99')
    wrap_sha(sha1, int.to_bytes(n, 2, 'big'))
    wrap_sha(sha1, b'\x04')
    wrap_sha(sha1, int.to_bytes(ts, 4, 'big'))
    wrap_sha(sha1, b'\x01')
    wrap_sha(sha1, int.to_bytes(3072, 2, 'big'))
    wrap_sha(sha1, n_bytes)
    wrap_sha(sha1, int.to_bytes(17, 2, 'big'))
    e_bytes = int.to_bytes(exponent, 3, 'big')
    #print( "Exponent bytes: {0}".format(e_bytes) )
    wrap_sha(sha1, e_bytes)
    print( "fpr: {0}".format(sha1.hexdigest()) )
    return sha1.hexdigest()

def import_rsa_key(s):
    n_bytes = sexp.sexp_get_bytes(s, b'n', 384)
    p_bytes = sexp.sexp_get_bytes(s, b'p', 192)
    q_bytes = sexp.sexp_get_bytes(s, b'q', 192)
    n = int.from_bytes(n_bytes, byteorder = 'big')
    p = int.from_bytes(p_bytes, byteorder = 'big')
    q = int.from_bytes(q_bytes, byteorder = 'big')
    exponent, d = rsa.key.calculate_keys(p, q)
    private_rsa_key = rsa.key.PrivateKey(n, exponent, d, p, q)
    public_rsa_key = rsa.key.PublicKey(n, exponent)
    print("n: {0}".format(hex(n)[2:])) #n_bytes.hex()))

    ts_bytes = sexp.sexp_get_bytes(s, b'created-at', 10)
    ts = int(ts_bytes)

    rsa_keyfpr(public_rsa_key)
    return (public_rsa_key, private_rsa_key, ts)

def pub_rsa_key_to_sexp(pub):
    pub_n_hex = hex(pub.n)[2:] # pub.n.to_bytes(384, 'big').hex()
    pub_e_hex = hex(pub.e)[2:] # pub.e.to_bytes(8, 'big').hex()
    return ("((1:n{0}:{1})(1:e{2}:{3}))".format(len(pub_n_hex), pub_n_hex,
        len(pub_e_hex), pub_e_hex)).encode("utf-8")
