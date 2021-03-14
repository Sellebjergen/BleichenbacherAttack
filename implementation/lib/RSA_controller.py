from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

"""
    Simple class for encrypting and decrypting various messages using lib encryption and PKCS 1.5 padding.
"""


class RSA_controller:
    def __init__(self, amount_of_bits):
        self.amount_of_bits = amount_of_bits
        key = RSA.generate(amount_of_bits)
        self.private_key = key.export_key('PEM')
        self.public_key = key.publickey().exportKey('PEM')

    def encrypt(self, msg):
        msg = str.encode(msg)
        rsa_public_key = RSA.importKey(self.public_key)
        rsa_public_key = PKCS1_v1_5.new(rsa_public_key)
        encrypted_text = rsa_public_key.encrypt(msg)
        return encrypted_text

    def decrypt(self, encrypted_text):
        rsa_private_key = RSA.importKey(self.private_key)
        rsa_private_key = PKCS1_v1_5.new(rsa_private_key)
        decrypted_text = rsa_private_key.decrypt(encrypted_text, str.encode("Error"))
        return decrypted_text

    def get_public_key(self):
        return self.public_key

    def get_amount_of_bits(self):
        return self.amount_of_bits
