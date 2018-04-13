#!/usr/bin/env python

import socket
import binascii
from Crypto.Cipher import AES

server_address = '127.0.0.1'
server_port = 8888

alices_key = b'23FCE5AE61E7BFCB29AC85725E7EC77DB9DBA460EACA7458070B719CE0B1DC31'
bobs_key = b'A41503A5D9E66B34FAC9F2FC9FD14CA24D728B17DE0FCC2C3676DED6A191A1F1'


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
    # Setup socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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

        if len(split_payload) != 4:
            print('KDC: Wrong amount of info received')
        elif split_payload[1] == b'Alice' and split_payload[2] == b'Bob':
            print('KDC: Message from Alice received, sending response')
            alices_nonce = split_payload[0]
            bobs_encrypted_nonce = split_payload[3]

            # Create the ticket for Bob
            ticket = alices_key + bobs_key + b' Alice ' + bobs_encrypted_nonce
            encrypted_ticket = encrypt(bobs_key, ticket)

            # Form the response to Alice
            response = alices_nonce + b' Bob ' + alices_key + bobs_key + b' ' + encrypted_ticket
            message = encrypt(alices_key, response)

            # Send the response to Alice
            sock.sendto(message, client_address)
