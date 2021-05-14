from implementation.lib.BleichenBacherAttack import BleichenBacherAttack
from implementation.lib.Oracle import Oracle
from implementation.lib.RSA_controller import RSA_controller

if __name__ == '__main__':
    print("--- Simulating Bleichenbacher oracle padding attack ---")
    # Setting up the RSA and oracle to use.
    rsa = RSA_controller(1024)
    oracle = Oracle(rsa)

    # encrypting the message.
    msg = "secret message"
    msg_encrypted_bytes = rsa.encrypt(msg)

    # performing the attack given the rsa and oracle.
    attack = BleichenBacherAttack(rsa, oracle)
    attack.run(msg_encrypted_bytes)
    print(attack)

    print("----")
    print(f"we called the oracle {oracle.get_amount_of_calls()} times")
    print(f"Step 2.a was performed: {attack.amount_step2a}")
    print(f"Step 2.b was performed: {attack.amount_step2b}")
    print(f"Step 2.c was performed: {attack.amount_step2c}")
    print("----")
