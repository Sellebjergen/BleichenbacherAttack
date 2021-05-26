from Crypto.Util.number import bytes_to_long, long_to_bytes
from collections import namedtuple

"""
    Implementation of the bleichen bacher oracle attack according to
    the original paper written by Daniel bleichen bacher.

    http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
"""

verbose = False


class BleichenBacherAttack:
    def __init__(self, rsa, oracle):
        self.rsa = rsa
        self.rsa_e = self.rsa.get_public_key().e
        self.rsa_n = self.rsa.get_public_key().n
        self.k = self.rsa.get_amount_of_bits() // 8
        self.B = 2 ** (8 * (self.k - 2))
        self.oracle = oracle
        self.Interval = namedtuple("Interval", ["lower_bound", "upper_bound"])

        # These values are only to try and see what happens in the attack.
        self.amount_step2a = 0
        self.amount_step2b = 0
        self.amount_step2c = 0

    @staticmethod
    def ceil(a, b):
        return a // b + (a % b > 0)

    @staticmethod
    def floor(a, b):
        return a // b

    def blinding_phase(self, c):
        if verbose:
            print("starting the blinding phase")
        s_0 = 1
        while True:
            c_0_math = c * pow(s_0, self.rsa_e, self.rsa_n) % self.rsa_n
            c_0_math_bytes = long_to_bytes(c_0_math)
            if self.oracle.get_conforming_status(c_0_math_bytes):
                return c_0_math
            s_0 += 1

    def phase2a(self, c):
        global i
        if verbose:
            print("starting phase 2a")
        s_1 = self.ceil(self.rsa_n, 3 * self.B)
        if verbose:
            print(f"starting with the value of: {s_1}")
            i = 0
        while True:
            if verbose:
                if i % 25000:
                    print(f"I'm still searching, we're at {i}")
            math = (c * pow(s_1, self.rsa_e, self.rsa_n)) % self.rsa_n
            math_bytes = long_to_bytes(math)
            if self.oracle.get_conforming_status(math_bytes):
                if verbose:
                    print("now the value of s_1 is")
                    print(s_1)
                return s_1
            s_1 += 1

    def phase2b(self, c, s_i):
        if verbose:
            print("starting phase 2b")
        while True:
            math = (c * pow(s_i, self.rsa_e, self.rsa_n)) % self.rsa_n
            math_bytes = long_to_bytes(math)
            if self.oracle.get_conforming_status(math_bytes):
                if verbose:
                    print("now the value of s_1 is")
                    print(s_i)
                return s_i
            s_i += 1

    def phase2c(self, c_0, s_i, interval):
        if verbose:
            print("starting phase 2c")
        a, b = interval
        r_i = self.ceil(2 * (b * s_i - 2 * self.B), self.rsa_n)
        while True:
            lower_bound = self.ceil(2 * self.B + r_i * self.rsa_n, b)
            higher_bound = self.ceil(3 * self.B + r_i * self.rsa_n, a)
            if lower_bound > higher_bound:
                if verbose:
                    print(f"difference: {higher_bound - lower_bound}")
                exit(1)
            for s in range(lower_bound, higher_bound):
                math = c_0 * pow(s, self.rsa_e, self.rsa_n) % self.rsa_n
                math_bytes = long_to_bytes(math)
                if self.oracle.get_conforming_status(math_bytes):
                    if verbose:
                        print("found a suitable values of r_i and s_i")
                    return s
            r_i += 1

    def phase3(self, s, M):
        if verbose:
            print(f"there are {len(M)} intervals here in phase 3.")
            print("starting phase 3")
        new_M = []
        for a, b in M:
            lower_r = self.ceil(a * s - 3 * self.B + 1, self.rsa_n)
            higher_r = self.ceil(b * s - 2 * self.B, self.rsa_n)
            if verbose:
                print(f"Differences in r higher and lower: {higher_r - lower_r}")
            for r in range(lower_r, higher_r):
                lower_bound = max(a, self.ceil(2 * self.B + r * self.rsa_n, s))
                higher_bound = min(b, self.floor(3 * self.B - 1 + r * self.rsa_n, s))
                temp_interval = self.Interval(lower_bound, higher_bound)
                new_M.append(temp_interval)
        if verbose:
            print(f"we've defined some new intervals there are now: {len(new_M)}")
        return new_M

    def run(self, cipher_bytes):
        global s_i
        if verbose:
            print("starting attack.")
        cipher_integer = bytes_to_long(cipher_bytes)
        M = [self.Interval(2 * self.B, 3 * self.B + 1)]
        i = 1

        while True:
            # Doing step 2
            if i == 1:
                self.amount_step2a += 1
                s_i = self.phase2a(cipher_integer)
            elif i > 1 and len(M) >= 2:
                self.amount_step2b += 1
                s_i = self.phase2b(cipher_integer, s_i + 1)
            elif len(M) == 1:
                self.amount_step2c += 1
                s_i = self.phase2c(cipher_integer, s_i, M[0])

            # Doing step 3
            M = self.phase3(s_i, M)

            # Doing step 4
            if len(M) == 1 and M[0].lower_bound == M[0].upper_bound:
                if verbose:
                    print("seems like we're done. Returning the resulting message.")
                result = M[0].lower_bound % self.rsa_n
                result_bytes = long_to_bytes(result)
                return result_bytes.split(b"\x00")[1]
            i += 1
            if verbose:
                print("Doing another iteration of step 2.")
