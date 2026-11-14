import argparse
from secrets import randbelow
from Crypto.Util.number import getPrime, isPrime

class Authority:
    def __init__(self, length, bits=2048):
        self.length = length
        self.p, self.q, self.g, self.msk, self.mpk = self.setup(length, bits)

    def GroupGen(self, bits=2048):
        while True:
            q = getPrime(bits - 1)
            p = 2 * q + 1
            if isPrime(p):
                break

        while True:
            h = randbelow(p - 3) + 2
            g = pow(h, 2, p)
            if g != 1:
                return p, q, g

    def setup(self, length, bits=2048):
        p, q, g = self.GroupGen(bits)
        msk = [randbelow(q) for _ in range(length)]
        mpk = [pow(g, s, p) for s in msk]
        return p, q, g, msk, mpk

    def keyGen(self, msk, y, q):
        return sum(msk[i] * y[i] for i in range(len(y))) % q

    def getAlice(self):
        return self.length, self.g, self.mpk, self.p, self.q

    def getSk(self, y):
        return self.keyGen(self.msk, y, self.q)


class Alice:
    def __init__(self, length, g, mpk, p, q, x):
        self.length, self.g, self.mpk, self.p, self.q, self.x = length, g, mpk, p, q, x

    def Encrypt(self):
        if len(self.x) != self.length:
            raise ValueError("x must have the configured vector length")
        r = randbelow(self.q)
        ciphertext = [pow(self.g, r, self.p)]
        ciphertext.extend(
            (pow(self.mpk[i], r, self.p) * pow(self.g, xi % self.q, self.p)) % self.p
            for i, xi in enumerate(self.x)
        )
        return ciphertext


class Bob:
    def __init__(self, y, p, q, g, sk_y, ):
        self.y, self.p, self.q, self.g = y, p, q, g
        self.sk_y = sk_y

    def discrete_log(self, g, value, p, max_x=1000):
        current = 1
        for x in range(max_x + 1):
            if current == value:
                return x
            current = current * g % p
        raise ValueError("inner product is outside the discrete-log search range")

    def Decrypt(self, c):
        value = 1
        for ct_i, y_i in zip(c[1:], self.y):
            value = value * pow(ct_i, y_i, self.p) % self.p
        value = value * pow(c[0], -self.sk_y, self.p) % self.p

        return self.discrete_log(self.g, value, self.p)


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
    authority = Authority(length=8, bits=2048)  # Demo parameters only.
    for donor, recipient in pairs:
        x = [int(i == donor) for i in range(8)]
        y = capabilities[recipient]
        ciphertext = Alice(*authority.getAlice(), x).Encrypt()
        sk_y = authority.getSk(y)
        result = Bob(y, authority.p, authority.q, authority.g, sk_y).Decrypt(ciphertext)
        expected = y[donor]
        print(f"donor {donor} -> recipient {recipient}: got {result}, expected {expected}")
        assert result == expected
        elapsed = time.perf_counter() - start
    print(f"Passed {len(pairs)} ABDP15 test(s).")

    


if __name__ == "__main__":
    main()
