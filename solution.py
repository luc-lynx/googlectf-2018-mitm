#!/usr/bin/env python3

from curve25519 import Public
import nacl.secret
import socket
import binascii

socket_server = ("mitm.ctfcompetition.com", 1337)
public_key_val = Public(int.to_bytes(325606250916557431795983626356110631294008115727848805560023387167927233504, 32, 'little'))
shared_key = binascii.unhexlify(b'68b59f127c671255346e099c3b9ea067a5595ba2adf26daa5e69d6a8a29d191a')


def make_sockets():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect(socket_server)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(socket_server)

    return server, client


def attack():
    s, c = make_sockets()
    s.send(b's\n')
    c.send(b'c\n')

    server_pub = s.recv(4096)[:-1]
    print(server_pub.decode())
    server_nonce = s.recv(4096)[:-1]
    print(server_nonce.decode())

    client_pub = c.recv(4096)[:-1]
    print(client_pub.decode())
    client_nonce = c.recv(4096)[:-1]
    print(client_nonce.decode())

    s.send(binascii.hexlify(public_key_val.serialize()) + b'\n')
    s.send(client_nonce + b'\n')

    c.send(binascii.hexlify(public_key_val.serialize()) + b'\n')
    c.send(server_nonce + b'\n')

    server_proof = s.recv(4096)[:-1]
    client_proof = c.recv(4096)[:-1]

    # send server's proof to the client
    c.send(server_proof + b'\n')

    # send client's proof to the server
    s.send(client_proof + b'\n')

    # close client socket
    c.close()

    # read auth string
    auth_string = s.recv(4096)[:-1]

    box = nacl.secret.SecretBox(shared_key)
    data = box.decrypt(binascii.unhexlify(auth_string))
    if data == b'AUTHENTICATED':
        print("[~] Got AUTHENTICATED")

    get_flag_cmd = b"getflag"
    encrypted_cmd = box.encrypt(get_flag_cmd)

    s.send(binascii.hexlify(encrypted_cmd) + b'\n')
    encrypted_flag = s.recv(4096)[:-1]

    data = box.decrypt(binascii.unhexlify(encrypted_flag))
    print("[~] The flag is {}".format(data.decode()))


if __name__ == "__main__":
    attack()
