from Crypto.Util.number import bytes_to_long, long_to_bytes
import numpy as np

# TODO: Checking the type of the oracle, if we give it an url, make a request instead.
# TODO: Can we search after for values in the blinding phase more efficiently?


class BleichenBacherAttack:
    def __init__(self, cipher_bytes, oracle, rsa):
        self.cipher_bytes = cipher_bytes
        self.rsa = rsa
        self.oracle = oracle

    def blinding_phase(self, lower_bound, upper_bound):
        print("starting blinding phase")
        e = self.rsa.get_public_key().e
        n = self.rsa.get_public_key().n
        c = bytes_to_long(self.cipher_bytes)
        i = 1
        for s_i in range(lower_bound, upper_bound):
            if s_i % 100000 == 0:
                print("I'm still alive, don't worry about it man...")

            c_0 = (c * pow(s_i, e, n)) % n
            c_0_bytes = long_to_bytes(c_0)

            if self.oracle.get_conforming_status(c_0_bytes):
                print("found a value")
                return c_0, s_i, i

        # if nothing was found i return None.
        return None

    def phase2_a(self, c_0, s_i, i):
        B = 2 ** (8 * (self.rsa.amount_of_bits - 2))
        e = self.rsa.get_public_key().e
        n = self.rsa.get_public_key().n

        if i == 1:
            s_1 = n // 3*B + 1
            math = c_0 * pow(s_1, e, n) % n
            math_bytes = long_to_bytes(math)
            while not self.oracle.get_conforming_status(math_bytes):
                s_1 += 1
                math = c_0 * pow(s_1, e, n) % n
                math_bytes = long_to_bytes(math)
            print("We've found the next value in the interval.")
            return s_1

    def run(self):
        B = 2 ** (8 * (self.rsa.amount_of_bits - 2))
        lower_bound = 2*B
        upper_bound = 3*B - 1

        # step 1.   blinding
        c_0, s_i, i = self.blinding_phase(lower_bound, upper_bound)

        print("jumping to phase 2 instead.")
        s_1 = self.phase2_a(c_0, s_i, i)

        print(s_1)
        # step 2.   searching for PKCS conforming messages
        # step 2.a  starting the search
        # step 2.b  searching with more than one interval
        # step 2.c  searching with one interval left
        # step 3    narrowing the set of solutions
        # step 4    computing the solutions
