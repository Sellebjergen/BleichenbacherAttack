import rsa

"""
    Class representing the oracle in bleichenbachers attack.
"""


class Oracle2:
    def __init__(self, rsa_controller):
        self.RSA_controller = rsa_controller
        self.amount_of_calls = 0

    def get_conforming_status(self, cipher):
        self.amount_of_calls += 1
        try:
            unused = rsa.decrypt(cipher, self.RSA_controller.get_private_key())
            return True
        except:
            return False

    def get_amount_of_calls(self):
        return self.amount_of_calls
