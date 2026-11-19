import argparse
from secrets import randbelow

from sage.all import EllipticCurve, GF, Integer


def GroupGen():
    """secp256k1 curve"""
    field_p = Integer(
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    )
    order = Integer(
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    )
    curve = EllipticCurve(GF(field_p), [0, 7])
    generator = curve(
        Integer(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798),
        Integer(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
    )
    return curve, generator, order


class Authority:
    def __init__(self, length):
        self.length = length
        self.curve, self.g, self.p = GroupGen()
        self.msk = [randbelow(int(self.p)) for _ in range(length)]
        self.mpk = [s * self.g for s in self.msk]

    def getAlice(self):
        return self.length, self.g, self.mpk, self.p

    def getSk(self, y):
        if len(y) != self.length:
            raise ValueError("y must have the configured vector length")
        return sum(s * yi for s, yi in zip(self.msk, y)) % self.p


class Alice:
    def __init__(self, length, g, mpk, p, x):
        self.length, self.g, self.mpk, self.p, self.x = length, g, mpk, p, x

    def Encrypt(self):
        if len(self.x) != self.length:
            raise ValueError("x must have the configured vector length")
        r = randbelow(int(self.p))
        return [r * self.g] + [r * self.mpk[i] + (xi % self.p) * self.g
                                for i, xi in enumerate(self.x)]


class Bob:
    def __init__(self, y, g, p, sk_y, max_inner_product=1000):
        self.y, self.g, self.p, self.sk_y = y, g, p, sk_y
        self.max_inner_product = max_inner_product

    def Decrypt(self, ciphertext):
        if len(ciphertext) != len(self.y) + 1:
            raise ValueError("ciphertext and y must have matching lengths")
        result = sum(yi * ci for yi, ci in zip(self.y, ciphertext[1:]))
        result -= self.sk_y * ciphertext[0]

        point = self.g.curve()(0)
        for value in range(self.max_inner_product + 1):
            if point == result:
                return value
            point += self.g
        raise ValueError("inner product is outside the discrete-log search range")


def compatible(donor, recipient):
    donor_abo, donor_rh = donor[:-1], donor[-1]
    recipient_abo, recipient_rh = recipient[:-1], recipient[-1]
    return (recipient_abo == "AB" or donor_abo == "O" or donor_abo == recipient_abo) \
        and (donor_rh == "-" or recipient_rh == "+")


def main():
    blood_types = ["O-", "O+", "A-", "A+", "B-", "B+", "AB-", "AB+"]
    capabilities = [
        [int(compatible(donor, recipient)) for donor in blood_types]
        for recipient in blood_types
    ]
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="run all 64 pairs")
    parser.add_argument("--one", nargs=2, type=int, metavar=("DONOR_INDEX", "RECIPIENT_INDEX"))
    args = parser.parse_args()
    if args.all:
        pairs = [(d, r) for d in range(8) for r in range(8)]
    else:
        pair = args.one or (0, 0)
        if any(index not in range(8) for index in pair):
            parser.error("indices must be from 0 to 7 (O-, O+, A-, A+, B-, B+, AB-, AB+)")
        pairs = [tuple(pair)]

    authority = Authority(length=8)
    for donor, recipient in pairs:
        x = [int(i == donor) for i in range(8)]
        y = capabilities[recipient]
        ciphertext = Alice(*authority.getAlice(), x).Encrypt()
        sk_y = authority.getSk(y)
        result = Bob(y, authority.g, authority.p, sk_y).Decrypt(ciphertext)
        expected = y[donor]
        print(f"donor {donor} -> recipient {recipient}: got {result}, expected {expected}")
        assert result == expected
    print(f"Passed {len(pairs)} ABDP15 EC test(s).")


if __name__ == "__main__":
    main()
