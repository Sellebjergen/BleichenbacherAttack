from implementation.lib.oracles.rsa.Oracle2 import Oracle2
from implementation.lib.oracles.rsa.RSA_controller2 import RSA_controller2
from lib.BleichenBacherAttack import BleichenBacherAttack
from time import time
from math import floor


import matplotlib.pyplot as plt


def use_attack(bitsize, oracle, rsa):
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
                           + str(message.decode("utf-8")) + ", " \
                           + "using oracle, only checking first 2 bytes" \
                           + "\n"
        file.write(insertion_string)


def run_attack_with_bitsize(bitsize, oracle, rsa):
    print("-" * 80)
    print(f"Trying to do the bleichenbacher attack on bitsize {bitsize}")
    result, time_used, oracle_calls = use_attack(bitsize, oracle, rsa)
    print(result)
    print(f"we called the oracle {oracle_calls} times")
    print(f"and took {time_used} seconds to run.")
    save_data(bitsize, oracle_calls, time_used, result)


def draw_barchart(bits, save=False):
    threshold = 0
    mean_value = 0
    x_bar = get_amount_of_oracle_calls(bits)
    plt.bar(range(len(x_bar)), x_bar, )
    plt.title(f"Amount of oracle calls for {bits} bit")
    plt.ylabel("Amount of oracle calls")
    plt.xlabel("Amount of tries")

    if bits == 1024:
        threshold = 554898
        mean_value = get_mean_amountOfCalls(1024)
    elif bits == 2048:
        threshold = 334517
        mean_value = get_mean_amountOfCalls(2048)
    elif bits == 4096:
        threshold = 245854
        mean_value = get_mean_amountOfCalls(4096)
    mean_value = floor(mean_value)

    plt.axhline(threshold, color="red", lw=0.5, ls="--")
    plt.axhline(mean_value, color="green", lw=0.5, ls="--")
    plt.legend([f"Threshold of {threshold} calls",
                f"Mean value of {mean_value} calls"])

    if save:
        plt.savefig(f"data/charts/barchart_{bits}")

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


def draw_barcharts():
    print("Drawing barchart for 1024 bits")
    draw_barchart(1024)
    print("Drawing barchart for 2048 bits")
    draw_barchart(2048)
    print("Drawing barchart for 4096 bits")
    draw_barchart(4096)


def get_mean_values():
    calls_1024 = get_mean_amountOfCalls(1024)
    calls_2048 = get_mean_amountOfCalls(2048)
    calls_4096 = get_mean_amountOfCalls(4096)

    print(f"mean calls to oracle for 1024 bits: ")
    print(calls_1024)
    print("-" * 25)
    print("mean calls to oracle for 2048 bits")
    print(calls_2048)
    print("-" * 25)
    print("mean calls to oracle for 4096 bits")
    print(calls_4096)
    print("-" * 25)


def get_amount_above_threshold_value(bits):
    amount = 0
    threshold = 0

    if bits == 1024:
        threshold = 554898
    elif bits == 2048:
        threshold = 334517
    elif bits == 4096:
        threshold = 245845

    with open("data/data.csv", "r") as file:
        lines = file.readlines()
        for line in lines[1:]:
            line = line.split(",")
            if int(line[0]) == bits and int(line[1]) > threshold:
                amount += 1
    return amount


def get_amount_below_lowerbound_value(bits):
    amount = 0
    lower_bound = 15644

    with open("data/data.csv", "r") as file:
        lines = file.readlines()
        for line in lines[1:]:
            line = line.split(",")
            if int(line[0]) == bits and int(line[1]) < lower_bound:
                print(line)
                amount += 1
    return amount


def get_total_number_of_values(bits):
    amount = 0
    with open("data/data.csv", "r") as file:
        lines = file.readlines()
        for line in lines[1:]:
            line = line.split(",")
            if int(line[0]) == bits:
                amount += 1
    return amount


def find_highest_amount_oracle_calls(bits):
    highest = 0
    with open("data/data.csv", "r") as file:
        lines = file.readlines()
        for line in lines[1:]:
            line = line.split(",")
            if int(line[0]) == bits and int(line[1]) > highest:
                highest = int(line[1])
    return highest


# this is a dangerous method. As it depends on the exact placement of the values in data.csv
def find_mean_amount_oracle_calls_2BytesOracle():
    result = []
    with open("data/data.csv", "r") as file:
        lines = file.readlines()
        for line in lines[390:]:
            line = line.split(",")
            calls = int(line[1])
            bitsize = int(line[0])
            if bitsize == 1024:
                result.append(calls)
    return sum(result) / len(result)


if __name__ == '__main__':
    print(find_mean_amount_oracle_calls_2BytesOracle())
