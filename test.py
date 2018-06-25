#!/usr/bin/env python3

from curve25519 import Private, Public
from binascii import hexlify

keys = set()

for i in range(30):
    myPrivate = Private()
    val = int.to_bytes(325606250916557431795983626356110631294008115727848805560023387167927233504, 32, 'little')
    theirPublic = Public(val)
    shared = myPrivate.get_shared_key(theirPublic)
    print(hexlify(shared))
    keys.add(shared)

print("[~] Num of different keys: {}".format(len(keys)))
