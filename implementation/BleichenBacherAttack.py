from Crypto.Util.number import bytes_to_long, long_to_bytes


# TODO: Checking the type of the oracle, if we give it an url, make a request instead.
# TODO: Can we search after for values in the blinding phase more efficiently?


class BleichenBacherAttack:
    def __init__(self, cipher_bytes, oracle, rsa):
        self.cipher_bytes = cipher_bytes
        self.rsa = rsa

        self.oracle = oracle

    def call_oracle(self, lower_bound, upper_bound):
        e = self.rsa.get_public_key().e
        n = self.rsa.get_public_key().n
        c = bytes_to_long(self.cipher_bytes)

        for s_i in range(lower_bound, upper_bound):
            if s_i % 1000000 == 0:
                print(s_i)
            c_i = (c * pow(s_i, e, n)) % n
            c_i_bytes = long_to_bytes(c_i)
            if self.oracle.get_conforming_status(c_i_bytes):
                print("found a value")

        print("searching has completed")

    def run(self):
        B = 2 ** (8 * (self.rsa.amount_of_bits - 2))
        lower_bound = 2*B
        upper_bound = 3*B - 1
        e = self.rsa.get_public_key().e
        n = self.rsa.get_public_key().n

        # step 1.   blinding
        self.call_oracle(lower_bound, upper_bound)

        # step 2.   searching for PKCS conforming messages
        # step 2.a  starting the search
        # step 2.b  searching with more than one interval
        # step 2.c  searching with one interval left
        # step 3    narrowing the set of solutions
        # step 4    computing the solutions
        pass
