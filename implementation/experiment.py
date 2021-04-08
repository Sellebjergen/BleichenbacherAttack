from lib.BleichenBacherAttack import BleichenBacherAttack
from lib.Oracle import Oracle
from lib.RSA_controller import RSA_controller
from time import time

# Just some options to configure the tests really quick
amount_of_tries = 1

# TODO: run again to make sure that it's not just the msg.


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


if __name__ == '__main__':
    # for i in range(amount_of_tries):
    #     run_attack_with_bitsize(256)
    #
    # for i in range(amount_of_tries):
    #     run_attack_with_bitsize(512)

    for i in range(amount_of_tries):
        run_attack_with_bitsize(1024)

    # for i in range(amount_of_tries):
    #     run_attack_with_bitsize(2048)
    #
    # for i in range(amount_of_tries):
    #     run_attack_with_bitsize(4096)
