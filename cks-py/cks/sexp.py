#!/usr/bin/env python

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
