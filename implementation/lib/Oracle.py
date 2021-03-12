from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

"""
    Class representing the oracle in bleichenbachers attack.
"""

class Oracle:
    def __init__(self, RSA):
        self.RSA_controller = RSA

    def get_conforming_status(self, cipher):
        print(f"trying with cipher: {cipher}")
        sentinel = str.encode("Is not PKCS conforming.")
        rsa_private_key = RSA.importKey(self.RSA_controller.private_key)
        rsa_private_key = PKCS1_v1_5.new(rsa_private_key)
        decrypted_text = rsa_private_key.decrypt(cipher, sentinel)
        if decrypted_text == sentinel:
            return False
        else:
            return True
