import argparse
from secrets import randbelow
from Crypto.Util.number import getPrime, isPrime

def parse_bool(value):
    value = value.lower()
    if value in ("true", "1", "yes"):
        return True
    if value in ("false", "0", "no"):
        return False
    raise argparse.ArgumentTypeError("use True or False")

class Authority:
    def __init__(self, bits=2048, hardcoded= True):
        self.length = 8
        self.modulus, self.p, self.g, self.msk, self.mpk = self.setup(8, bits, hardcoded)

    def GroupGen(self, bits=2048):
        """Return (modulus, p, g): p is the group order, modulus is 2*p+1."""
        i = 0
        while True:
            i += 1
            p = getPrime(bits - 1)
            modulus = 2 * p + 1
            print("tried", i)
            if isPrime(modulus):
                break
        while True:
            h = randbelow(modulus - 3) + 2
            g = pow(h, 2, modulus)
            if g != 1:
                return modulus, p, g

    def setup(self, length, bits=2048, hardcoded=True):
        if hardcoded:
            modulus =  3664454705235626187252289342184991399346923406136597859973765081066802650253662011924674103769894306270697058708986706911538679431969256606448308922931293547194947324681831036144418524063405203080865256775042109713815028358516452478832578163771537429005118493116290232125317528174718001438016945517432609996340240131731687148630378251628677994640430489710754870557300301842450914997890952811171062247931727440379055151550435957562620569287892388083568697910191228962910433742469184022095182939621821430465558547027336697558355492047590952647482508514235401802473765374116948197422051681906261326380885208271908044349541400506730855965375154581133595312267098937879654225807995931197923085939701053185569080627856438143425262220780742317033777068858622023808596705653118214242315494640144922150991576182575600987664577193586169653545412899176768992716610826304506377350183794367116395164489635330859432072476050692995154078639
            p =  1832227352617813093626144671092495699673461703068298929986882540533401325126831005962337051884947153135348529354493353455769339715984628303224154461465646773597473662340915518072209262031702601540432628387521054856907514179258226239416289081885768714502559246558145116062658764087359000719008472758716304998170120065865843574315189125814338997320215244855377435278650150921225457498945476405585531123965863720189527575775217978781310284643946194041784348955095614481455216871234592011047591469810910715232779273513668348779177746023795476323741254257117700901236882687058474098711025840953130663190442604135954022174770700253365427982687577290566797656133549468939827112903997965598961542969850526592784540313928219071712631110390371158516888534429311011904298352826559107121157747320072461075495788091287800493832288596793084826772706449588384496358305413152253188675091897183558197582244817665429716036238025346497577039319
            g =  3153880494681130693291342321424000789185525228626752876330321251299693662750453680247928343447550822490491951832929966793772830861871415229774386625320670997124131998491885761431764881625187063905916199628072637333087510684304260592991731748827671768772686182906661170382256336904055648615985216436948674282725467435862277024693475034145804753465680343777506034592838538449753748041439092050352747382946583768575759117071495863775189829874174012534887370375688486733195189150484525979917880355139355413968071574693205722143267150350482255294513512734746816889291034477773505730801863265462395924747126337827419735618543528694430073800228732963866763866488881686272907798630677399700711547195797469975174021594515150424040692280483864394088881819430053534718706216212833960997514741844135236735267199973546672885944546788039747026472426766913943233542133269928318919105703004527771575112323292881304454005536468261029576738615
        else: 
            modulus, p, g = self.GroupGen(bits)
        msk = [randbelow(p) for _ in range(length)]
        mpk = [pow(g, s, modulus) for s in msk]
        return modulus, p, g, msk, mpk

    def keyGen(self, msk, y, p):
        return sum(msk[i] * y[i] for i in range(len(y))) % p

    def getAlice(self):
        return self.length, self.g, self.mpk, self.modulus, self.p

    def getSk(self, y):
        return self.keyGen(self.msk, y, self.p)


class Alice:
    def __init__(self, length, g, mpk, modulus, p, x):
        self.length, self.g, self.mpk = length, g, mpk
        self.modulus, self.p, self.x = modulus, p, x

    def Encrypt(self):
        if len(self.x) != self.length:
            raise ValueError("x must have the configured vector length")
        r = randbelow(self.p)
        ciphertext = [pow(self.g, r, self.modulus)]
        ciphertext.extend(
            (pow(self.mpk[i], r, self.modulus)
             * pow(self.g, xi % self.p, self.modulus)) % self.modulus
            for i, xi in enumerate(self.x)
        )
        return ciphertext


class Bob:
    def __init__(self, y, modulus, p, g, sk_y):
        self.y, self.modulus, self.p, self.g = y, modulus, p, g
        self.sk_y = sk_y

    def discrete_log(self, g, value, modulus, max_x=1000):
        current = 1
        for x in range(max_x + 1):
            if current == value:
                return x
            current = current * g % modulus
        raise ValueError("inner product is outside the discrete-log search range")

    def Decrypt(self, c):
        value = 1
        for ct_i, y_i in zip(c[1:], self.y):
            value = value * pow(ct_i, y_i, self.modulus) % self.modulus
        value = value * pow(c[0], -self.sk_y, self.modulus) % self.modulus

        return self.discrete_log(self.g, value, self.modulus)

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
    parser.add_argument("hardcoded", nargs="?", type=parse_bool, default=True,
                        help="True uses saved group parameters; False generates them (default: True)")
    parser.add_argument("bits", nargs="?", type=int, default=512, 
                        help="modulus bit size when generating parameters")
    args = parser.parse_args()
    if args.all:
        pairs = [(d, r) for d in range(8) for r in range(8)]
    else:
        pair = args.one or (0, 0)
        if any(value not in range(8) for value in pair):
            parser.error("blood type indices must be from 0 to 7")
        pairs = [tuple(pair)]
    authority = Authority(bits=args.bits, hardcoded=args.hardcoded)

    for donor, recipient in pairs:
        x = [int(i == donor) for i in range(8)]
        y = capabilities[recipient]
        ciphertext = Alice(*authority.getAlice(), x).Encrypt()
        sk_y = authority.getSk(y)
        result = Bob(y, authority.modulus, authority.p, authority.g, sk_y).Decrypt(ciphertext)
        expected = y[donor]
        print(f"donor {donor} -> recipient {recipient}: got {result}, expected {expected}")
        assert result == expected
    print(f"Passed {len(pairs)} ABDP15 test(s).")

    
if __name__ == "__main__":
    main()
