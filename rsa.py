import math
import random


def generate_e(phi_n):
    for i in range(2, phi_n):
        if math.gcd(i, phi_n) == 1:
            return i


def generate_random_e(phi_n):
    e = random.randint(2, phi_n - 1)
    while math.gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)
    return e


def encrypt(M, public_key):
    M = int(M, 16)
    if (M >= 0 and M < public_key["n"]) == False:
        raise ValueError(f"Your message in integer form is {
                         M}, which is not in the range [0, {public_key['n']})")
    C = M ** public_key["e"] % public_key["n"]
    return C


def decrypt(C, private_key):
    M = C ** private_key["d"] % private_key["n"]
    M = hex(M)[2:].upper().rjust(16, "0")
    return M
