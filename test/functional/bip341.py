# encoding=utf8

# https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

from bip340 import *

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def taproot_tweak_pubkey(pubkey, h):
    t = int_from_bytes(tagged_hash("TapTweak", pubkey + h))
    if t >= SECP256K1_ORDER:
        raise ValueError
    P = lift_x(int_from_bytes(pubkey))
    if P is None:
        raise ValueError
    Q = point_add(P, point_mul(G, t))
    return 0 if has_even_y(Q) else 1, bytes_from_int(x(Q))

def taproot_tweak_seckey(seckey0, h):
    seckey0 = int_from_bytes(seckey0)
    P = point_mul(G, seckey0)
    seckey = seckey0 if has_even_y(P) else SECP256K1_ORDER - seckey0
    t = int_from_bytes(tagged_hash("TapTweak", bytes_from_int(x(P)) + h))
    if t >= SECP256K1_ORDER:
        raise ValueError
    return bytes_from_int((seckey + t) % SECP256K1_ORDER)