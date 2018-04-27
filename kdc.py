#!/usr/bin/env python

import socket
import binascii
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

server_address = '127.0.0.1'
server_port = 8888

user_keys = {'alice':b'23FCE5AE61E7BFCB29AC85725E7EC77DB9DBA460EACA7458070B719CE0B1DC31'}


def encrypt(key, data):
    # Setup the cipher to encrypt the data
    cipher = AES.new(binascii.unhexlify(key), AES.MODE_SIV)

    # Encrypt the data
    ciphertext, digest = cipher.encrypt_and_digest(data)

    # Convert to ascii to comply with assignment description
    ascii_ciphertext = binascii.hexlify(ciphertext)
    ascii_digest = binascii.hexlify(digest)

    # Concatenate the ciphertext and digest
    return ascii_ciphertext + b'-' + ascii_digest


if __name__ == '__main__':
    # Create public and private keys
    key = RSA.generate(2048)
    private_key_plaintext = key.export_key()
    public_key_plaintext = key.publickey().export_key()

    # Setup socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    sock.bind((server_address, server_port))
    print('KDC: Listening on ' + server_address + ':' + str(server_port))

    while True:
        # Waits for a message from Alice
        print()
        print('KDC: waiting for request...')
        payload, client_address = sock.recvfrom(4096)

        # Separate the information from Alice
        split_payload = payload.split()

        # Verify the message

        if len(split_payload) == 1:
            if split_payload[0] == b'request_public_key':
                print('KDC: Sending public key to user')
                sock.sendto(public_key_plaintext, client_address)
        elif len(split_payload) == 3:
            if split_payload[0] == b'add_user':
                print('KDC: Adding ' + split_payload[1].decode() + '\'s key to the database')

                # Decrypt the key
                private_key = RSA.import_key(private_key_plaintext)
                cipher_rsa = PKCS1_OAEP.new(private_key)
                user_key = cipher_rsa.decrypt(binascii.unhexlify(split_payload[2]))

                # Add the new user's key and print out the new directory
                user_keys[split_payload[1].decode()] = user_key
                print(user_keys)
        elif len(split_payload) != 4:
            print('KDC: Wrong amount of info received')
        elif split_payload[1] == b'Alice' and split_payload[2].decode().lower() in user_keys:
            # Bob refers the the other user Alice is trying to talk to
            bob = split_payload[2].decode().lower()
            print('KDC: Message from Alice received, sending response')
            alices_nonce = split_payload[0]
            bobs_encrypted_nonce = split_payload[3]

            # Create the ticket for Bob
            ticket = user_keys['alice'] + user_keys[bob] + b' Alice ' + bobs_encrypted_nonce
            encrypted_ticket = encrypt(user_keys[bob], ticket)

            # Form the response to Alice
            response = alices_nonce + b' ' + bob.encode() + b' ' + user_keys['alice'] + user_keys[bob] + b' ' + encrypted_ticket
            message = encrypt(user_keys['alice'], response)

            # Send the response to Alice
            sock.sendto(message, client_address)
