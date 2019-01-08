#!/usr/bin/env python
import os
import ecc_utils

def bytes_as_printed_to_hex(b):
    """ '\x23' -> '23'
        '2'    -> '50'    """
    a = ""
    skip = 0
    for i in range(len(b)):
        if skip > 0:
            skip -= 1
            continue
        if b[i] == "\\":
            if b[i+1] == "x":
                a += b[i+2]
                a += b[i+3]
                skip = 3
        else:
            a += str(hex(ord(b[i]))[2:])

    return a

def main():
    key_dir = os.path.expanduser("~/.gnupg/private-keys-v1.d")
    keys = os.listdir(key_dir)
    for key in keys:
        #if not key.startswith("CD"):
        #    continue
        print(key, end = ": ")
        process(key_dir + os.path.sep + key)
        print("")

    with open('priv_keys.bin', "rt") as f:
        while True:
            priv_printed = f.readline().strip()
            if priv_printed == "":
                break
            priv_hex = bytes_as_printed_to_hex(priv_printed)
            try:
                priv = bytes.fromhex(priv_hex)
            except ValueError:
                print( "Non hex value? ", end = '' )
                print( priv_hex )
                print( priv_hex[64] )
                priv = b'\x00'*32
            pub, ts = ecc_utils.import_priv_ecc_key( priv )
            i = 1525856625
            print( pub )
            print( ecc_utils.ecc_keyfpr(i, pub) )

def process(key_filename):
    with open(key_filename, "rb") as f:
        key = f.readline()
        key = key + b'(10:created-at10:1536127425)'
        pub, ts = ecc_utils.import_pub_ecc_key( key )
        #print( ecc_utils.ecc_keyfpr(1536127425, pub) )
        #print( ecc_utils.ecc_keyfpr(0, pub) )
        i = 1525856625
        fpr = ecc_utils.ecc_keyfpr(i, pub)
        print( ecc_utils.ecc_keyfpr(i, pub) )

        print( pub )

if __name__ == "__main__":
    main()
