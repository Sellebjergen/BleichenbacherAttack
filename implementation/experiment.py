from lib.BleichenBacherAttack import BleichenBacherAttack
from lib.Oracle import Oracle
from lib.RSA_controller import RSA_controller
from time import time
import threading

threads = []
amount_of_threads = 8


def do_work():
    start = time()
    rsa = RSA_controller(2048)
    oracle = Oracle(rsa)
    msg = "secret message"
    msg_encrypted_bytes = rsa.encrypt(msg)
    result = BleichenBacherAttack(rsa, oracle).run(msg_encrypted_bytes)
    print(result)
    print(f"we called the oracle {oracle.get_amount_of_calls()} times")
    print(f"and took {time() - start} seconds to run.")


if __name__ == '__main__':
    for i in range(amount_of_threads):
        print("starting new thread.")
        t = threading.Thread(target=do_work)
        threads.append(t)

    for i in range(amount_of_threads):
        threads[i].start()

    for i in range(amount_of_threads):
        threads[i].join()
