import intervals as I

# TODO: troubles finding a good package for the intervals. Should i make my own solution?


class BleichenBacherAttack:
    def __init__(self, RSA_controller, oracle):
        self.bits = RSA_controller.get_amount_of_bits()
        self.B = 2 ** (8 * (self.bits - 2))
        print(self.B)
        a = 2 * self.B
        b = 3 * self.B - 1
        # self.M = pd.interval_range(start=a, end=b)
        self.M = I.DecimalInterval(a, b)
        self.i = 1

    def print_iteration(self):
        pass

    def run(self):
        pass
