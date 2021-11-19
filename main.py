from implementation.lib.BleichenBacherAttack import BleichenBacherAttack
from implementation.lib.oracles.rsa.Oracle2 import Oracle2
from implementation.lib.oracles.rsa.RSA_controller2 import RSA_controller2


if __name__ == '__main__':
    print("--- Simulating Bleichenbacher oracle padding attack ---")
    # Setting up the RSA and oracle to use.
    rsa = RSA_controller2(1024)
    oracle = Oracle2(rsa)

    # encrypting the message.
    msg = "secret message"
    msg_encrypted_bytes = rsa.encrypt(msg)

    # performing the attack given the rsa and oracle.
    attack = BleichenBacherAttack(rsa, oracle)
    result = attack.run(msg_encrypted_bytes)

    # Just some pretty printing.
    print(result)
    print("----")
    print(f"we called the oracle a total amount of {oracle.get_amount_of_calls()} times")
    print(f"Step 2.a was performed: {attack.amount_step2a}")
    print(f"Step 2.b was performed: {attack.amount_step2b}")
    print(f"Step 2.c was performed: {attack.amount_step2c}")
    print("----")
