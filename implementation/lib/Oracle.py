from Crypto.Cipher import PKCS1_v1_5

"""
    Class representing the oracle in bleichenbachers attack.
"""


class Oracle:
    def __init__(self, rsa):
        self.RSA_controller = rsa
        self.amount_of_calls = 0

    def get_conforming_status(self, cipher):
        self.amount_of_calls += 1
        try:
            sentinel = str.encode("Is not PKCS conforming.")
            rsa_private_key = PKCS1_v1_5.new(self.RSA_controller.private_key)
            decrypted_text = rsa_private_key.decrypt(cipher, sentinel)

            if decrypted_text == sentinel:
                return False
            else:
                return True
        except:
            return False

    def get_amount_of_calls(self):
        return self.amount_of_calls
