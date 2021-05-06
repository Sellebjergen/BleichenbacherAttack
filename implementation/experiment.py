from lib.BleichenBacherAttack import BleichenBacherAttack
from lib.Oracle import Oracle
from lib.RSA_controller import RSA_controller
from time import time

import matplotlib.pyplot as plt

# Just some options to configure the tests really quick
amount_of_tries = 100


def use_attack(bitsize):
    rsa = RSA_controller(bitsize)
    oracle = Oracle(rsa)
    msg = "secret message with a very secret aes key inside."
    msg_encrypted_bytes = rsa.encrypt(msg)
    start = time()
    result = BleichenBacherAttack(rsa, oracle).run(msg_encrypted_bytes)
    time_used = time() - start
    return result, time_used, oracle.get_amount_of_calls()


def save_data(bitsize, oracle_calls, time_used, message):
    with open("data/data.csv", "a") as file:
        insertion_string = str(bitsize) + ", " \
                           + str(oracle_calls) + ", " \
                           + str(time_used) + ", " \
                           + str(message.decode("utf-8")) + \
                           "\n"
        file.write(insertion_string)


def run_attack_with_bitsize(bitsize):
    print("-" * 80)
    print(f"Trying to do the bleichenbacher attack on bitsize {bitsize}")
    result, time_used, oracle_calls = use_attack(bitsize)
    print(result)
    print(f"we called the oracle {oracle_calls} times")
    print(f"and took {time_used} seconds to run.")
    save_data(bitsize, oracle_calls, time_used, result)


def draw_barchart(bits):
    x_bar = get_amount_of_oracle_calls(bits)
    plt.bar(range(len(x_bar)), x_bar)
    plt.title(f"Amount of oracle calls for {bits} bit")
    plt.ylabel("Amount of oracle calls")
    plt.show()


def get_mean_amountOfCalls(bits):
    x_bar = get_amount_of_oracle_calls(bits)
    mean = sum(x_bar) / len(x_bar)
    return mean


def get_amount_of_oracle_calls(bits):
    x_bar = []
    with open("data/data.csv", "r") as f:
        lines = f.readlines()
        for line in lines[1:]:
            line = line.split(",")
            bitamount = int(line[0])
            if bitamount == bits:
                oracle_calls = int(line[1])
                x_bar.append(oracle_calls)
    return x_bar


if __name__ == '__main__':
    print("something seems to be right here.")
    draw_barchart(4096)
    print(get_mean_amountOfCalls(1024))
