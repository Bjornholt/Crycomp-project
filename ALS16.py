from Crypto.Util.number import getPrime, isPrime
import math
from secrets import randbelow
from sage.all import ZZ, RealField
from sage.stats.distributions.discrete_gaussian_integer import (
    DiscreteGaussianDistributionIntegerSampler,
)
from itertools import product
import argparse

def sample_s(length, bits, N):
    R = RealField(2 * bits)
    sigma = R(bits).sqrt() * R(length * N).sqrt() ** (length + 1)

    D = DiscreteGaussianDistributionIntegerSampler(sigma=sigma)
    s = [int(ZZ(D())) for _ in range(length)]
    return s

SMALL_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]

class Authority:
    def __init__(self):
       pass 

    def GroupGen(self, bits):
            while True:
                q = getPrime(bits - 1)
                if any(q % sp == 0 for sp in SMALL_PRIMES):
                    print("Skipping q")
                    continue
                p = 2 * q + 1
                if isPrime(p):
                    break
            return p

    def setup(self, length, bits):
        p = self.GroupGen(bits)
        q = self.GroupGen(bits)
        N = p * q
        print("got N")
        
        while True:
            g_mark = randbelow(N**2 - 1) + 1
            if math.gcd(g_mark, N) == 1:
                break
        g = pow(g_mark, 2 * N, N**2)
        
        s = sample_s(length, bits, N)
        
        h = [pow(g, s_i, N**2) for s_i in s]
        mpk = (N, g, h)
        self.msk = s
        return N, mpk 

    def keygen(self, y):
        sk_y =  sum(self.msk[i] * y[i] for i in range(len(y)))
        return sk_y


class Alice():
    def __init__(self, mpk):
        self.N, self.g, self.h = mpk

    def encrypt(self, x):
        r = randbelow((self.N//4)+1)
        ciphertext = [pow(self.g,r,self.N**2)]
        ciphertext.extend(
            ((1 + xi * self.N) * pow(self.h[i], r, self.N**2)) % self.N**2
            for i, xi in enumerate(x)
        )
        return ciphertext


class Bob():
    def __init__(self, N, authority):
        self.N = N
        self.authority = authority
        
    def decrypt(self, y, ciphertext):
        sk_y = self.authority.keygen(y)
        C_y = 1
        for ct_i, y_i in zip(ciphertext[1:], y):
            C_y *= pow(ct_i, y_i, self.N**2) % self.N**2
        C_y *= pow(ciphertext[0], -sk_y, self.N**2) % self.N**2
        return ((C_y - 1) % self.N**2) // self.N


def main():
    # Coordinate order: O-, O+, A-, A+, B-, B+, AB-, AB+.
    capabilities = [
        [1, 0, 0, 0, 0, 0, 0, 0],
        [1, 1, 0, 0, 0, 0, 0, 0],
        [1, 0, 1, 0, 0, 0, 0, 0],
        [1, 1, 1, 1, 0, 0, 0, 0],
        [1, 0, 0, 0, 1, 0, 0, 0],
        [1, 1, 0, 0, 1, 1, 0, 0],
        [1, 0, 1, 0, 1, 0, 1, 0],
        [1, 1, 1, 1, 1, 1, 1, 1],
    ]
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="run all 64 pairs")
    parser.add_argument("--one", nargs=2, type=int, metavar=("DONOR_INDEX", "RECIPIENT_INDEX"), help="run one pair")
    args = parser.parse_args()
    if args.all:
        pairs = [(d, r) for d in range(8) for r in range(8)]
    else:
        pair = args.one or (0, 0)
        if any(value not in range(8) for value in pair):
            parser.error("blood type indices must be from 0 to 7")
        pairs = [tuple(pair)]

    authority = Authority()
    N, mpk = authority.setup(length=8, bits=128)  # Demo parameters only.
    alice, bob = Alice(mpk), Bob(N, authority)
    for donor, recipient in pairs:
        x = [int(i == donor) for i in range(8)]
        y = capabilities[recipient]
        result = bob.decrypt(y, alice.encrypt(x))
        expected = y[donor]
        print(f"donor {donor} -> recipient {recipient}: got {result}, expected {expected}")
        assert result == expected
    print(f"Passed {len(pairs)} ALS16 test(s).")


if __name__ == "__main__":
    main()
