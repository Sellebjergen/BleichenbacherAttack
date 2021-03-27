from Crypto.Util.number import bytes_to_long, long_to_bytes
from collections import namedtuple

# TODO: Checking the type of the oracle, if we give it an url, make a request instead.
# TODO: Can we search after for values in the blinding phase more efficiently?
# TODO: Do some minor cleanup on the code.

Interval = namedtuple("Interval", ["lower_bound", "upper_bound"])


def safe_interval_insert(M_new, interval):
    for i, (a, b) in enumerate(M_new):

        # overlap found, construct the larger interval
        if (b >= interval.lower_bound) and (a <= interval.upper_bound):
            lb = min(a, interval.lower_bound)
            ub = max(b, interval.upper_bound)

            M_new[i] = Interval(lb, ub)
            return M_new

    # no overlaps found, just insert the new interval
    M_new.append(interval)

    return M_new


class BleichenBacherAttack:
    def __init__(self, cipher_bytes, oracle, rsa):
        self.cipher_bytes = cipher_bytes
        self.rsa = rsa
        self.oracle = oracle
        self.rsa_e = rsa.get_public_key().e
        self.rsa_n = rsa.get_public_key().n

    @staticmethod
    def floor(a, b):
        return a // b

    @staticmethod
    def ceil(a, b):
        return a // b + (a % b > 0)

    def call_oracle(self, lower_bound):
        pass

    def blinding_phase(self, lower_bound, upper_bound):
        print("starting blinding phase")
        e = self.rsa.get_public_key().e
        n = self.rsa.get_public_key().n
        c = bytes_to_long(self.cipher_bytes)
        i = 1
        # TODO: This should probably just be a search with random values instead, but it seems to work really well.
        for s_i in range(lower_bound, upper_bound):
            if s_i % 100000 == 0:
                print("I'm still alive, don't worry about it man...")

            c_0 = (c * pow(s_i, e, n)) % n
            c_0_bytes = long_to_bytes(c_0)

            if self.oracle.get_conforming_status(c_0_bytes):
                print("found a value")
                return c_0, i

        # TODO: should maybe raise an exception?
        return None

    def phase2_a(self, c_0):
        B = 2 ** (8 * (self.rsa.amount_of_bits - 2))
        print("value of B")
        print(B)
        s_1 = self.floor(self.rsa_n, 3*B)
        print(f"s_1 {s_1}")
        math = c_0 * pow(s_1, self.rsa_e, self.rsa_n) % self.rsa_n
        math_bytes = long_to_bytes(math)
        while not self.oracle.get_conforming_status(math_bytes):
            s_1 += 1
            math = c_0 * pow(s_1, self.rsa_e, self.rsa_n) % self.rsa_n
            math_bytes = long_to_bytes(math)
        print("We've found the next value in the interval.")
        return s_1

    def phase3(self, B, M, s_i):
        M_new = []
        for a, b in M:
            r_low = self.ceil(a * s_i - 3 * B + 1, self.rsa_n)
            r_up =  self.ceil(b * s_i - 2 * B, self.rsa_n)

            print(f"r range: {r_up - r_low}")

            for r in range(r_low, r_up):
                lower_bound = max(a, self.ceil(2 * B + r * self.rsa_n, s_i))
                upper_bound = min(b, self.floor(3 * B - 1 + r * self.rsa_n, s_i))
                interval = Interval(lower_bound, upper_bound)
                M_new = safe_interval_insert(M_new, interval)

        M.clear()
        return M_new

    def run(self):
        B = 2 ** (8 * (self.rsa.amount_of_bits - 2))
        lower_bound = 2*B
        upper_bound = 3*B - 1
        M = [Interval(lower_bound, upper_bound)]

        # TODO: check if the cipher by itself is PKCS conforming. Skip step 1 in such case.

        # step 1.   blinding
        c_0, i = self.blinding_phase(lower_bound, upper_bound)

        # step 2.   searching for PKCS conforming messages
        # step 2.a  starting the search
        print("jumping to phase 2.")
        s_1 = 0
        if i == 1:
            s_1 = self.phase2_a(c_0)
        # TODO: make phase 2.b and 2.c

        print(s_1)
        print("done with phase 2")

        # step 3    narrowing the set of solutions
        self.phase3(B, M, s_1)
        print("yeah we got through.")

        # step 2.b  searching with more than one interval
        # step 2.c  searching with one interval left
        # step 4    computing the solutions
