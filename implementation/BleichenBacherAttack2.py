from Crypto.Util.number import bytes_to_long, long_to_bytes
from collections import namedtuple


class BleichenBacherAttack2:
    def __init__(self, cipher_bytes, rsa, oracle):
        self.cipher_bytes = cipher_bytes
        self.rsa = rsa
        self.oracle = oracle

    def run(self):
        B = B = 2 ** (8 * (self.rsa.get_amount_of_bits - 2))
        pass
