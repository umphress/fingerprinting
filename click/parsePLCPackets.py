from aes import AES
import math
import pickle


def get_hex_list_str(l):
    out = ""
    for idx, x in enumerate(l):
        out += "0x{:02X} ".format(x)
        if idx%16 == 15:
            out += "\n"
    out = out[:-1]
    return out


def _decrypt(message, masterKey, dataThing):
    aes = AES(masterKey)

    output = []
    for x in range(8):
        dataThing[15] = 0x8C+x
        encThing = aes.encrypt_block(dataThing)

        for y in range(16):
            if x*16+y == len(message):
                return output
            temp = message[x*16 + y] ^ encThing[y]
            output.append(temp)
    return output


# RSA encrypt 8 32bit values from plaintextArray array to create master key
# arg2 is N, arg1 is D (n,d) is private key)
def genMasterKey(plaintextArray, RSA_N, RSA_D):
    output = []
    # RSA encrypt with private key 8 32bit values from plaintextArray to create master key
    for x in range(8):
        arg0 = plaintextArray[x*4+0] << 24 | plaintextArray[x*4+1] << 16 | plaintextArray[x*4+2] << 8 | plaintextArray[x*4+3]

        A = pow(arg0, RSA_D, RSA_N) # A = (arg0^RSA_D) % RSA_N
        if (A != A&0xFFFF):
            raise ValueError("")

        output.append((A >> 8) & 0xFF)
        output.append(A & 0xFF)
    return output


def msvcrt_rand(seed):
    # return next seed and rand value [0-32767]
    seed = (seed*0x343fd)+0x269EC3
    return seed, (seed >> 0x10) & 0x7FFF


# Returns N, E, D (public key is (N, E), private key is (D))
def genRSAKeys(seed):
    RSA_N = None
    RSA_E = None
    RSA_D = None

    primesList = [0]*2295
    primesList = genPrimesList(primesList) # prime number array generator
    val = 0x8d6

    RSA_D = 0x800001 # arbitrary value to get into while loop
    while (RSA_D > 0x800000):
        uVar2 = 0
        while ((uVar2 < 0x1000000) or (0xf0000000 < uVar2)):
            uVar3 = 0
            uVar4 = 0
            while (uVar3 == uVar4):
                seed, randVal = msvcrt_rand(seed)
                iVar1 = int(val*randVal*(1/32768)) # rand value from 0 to val
                uVar3 = primesList[iVar1+1]; # added +1 to make it work as expected

                seed, randVal = msvcrt_rand(seed)
                iVar1 = int(val*randVal*(1/32768)) # rand value from 0 to val
                uVar4 = primesList[iVar1+1]; # added +1 to make it work as expected
                uVar2 = uVar4 * uVar3;
                RSA_N = uVar2;

        uVar2 = uVar4;
        if (uVar3 < uVar4):
            uVar2 = uVar3;
            uVar3 = uVar4;

        uVar3 = sub_40DF2A(uVar3 - 1,uVar2 - 1); # Carmichael's totient function 
        RSA_E = 2;

        RSA_E = 1
        iVar1 = 0
        while (iVar1 != 1):
            RSA_E = RSA_E + 1;
            iVar1 = math.gcd(int(uVar3),RSA_E);

        _,_,RSA_D = gcdExtended(uVar3,RSA_E)
        if RSA_D < 0:
            RSA_D += uVar3
        RSA_D = int(RSA_D)

    return RSA_N, RSA_E, RSA_D

# function for extended Euclidean Algorithm
def gcdExtended(a, b):
    # Base Case
    if a == 0 :
        return b,0,1

    gcd,x1,y1 = gcdExtended(b%a, a)

    # Update x and y using results of recursive call
    x = y1 - (b//a) * x1
    y = x1

    return gcd,x,y

def genPrimesList(argList):
    stack = [0]*20000

    piVar3 = 3;
    piVar2 = 0;
    for iVar1 in range(20000, 0, -1):
        stack[piVar2] = 0;
        piVar2 = piVar2 + 1;

    iVar1 = 2;
    while True:
        iVar4 = iVar1 * 2;
        piVar2 = piVar3;

        while True:
            if (stack[piVar2] == 0):
                stack[piVar2] = 1;

            iVar4 = iVar4 + iVar1;
            piVar2 = piVar2 + iVar1;
            if (iVar4 >= 20001):
                break

        iVar1 = iVar1 + 1;
        piVar3 = piVar3 + 2;
        if (iVar1 >= 10001):
                break

    iVar1 = 0;
    piVar3 = 0;
    argListIdx = 0
    while True:
        if (stack[piVar3] == 0):
            argList[argListIdx] = iVar1 + 1;
            argListIdx += 1;

        iVar1 = iVar1 + 1;
        piVar3 = piVar3 + 1;
        if iVar1 >= 20000:
            break

    return argList
    #return unaff_EBX, argList;


# Carmichael's Totient Function: lcm(p-1,q-1)
def sub_40DF2A(param_1, param_2):
    uVar1 = math.gcd(param_1,param_2)
    return (param_1 * param_2) / uVar1;


# GCD function
def sub_40DF11(param_1, param_2):
    while (param_2 != 0):
        temp_p2 = param_2
        param_2 = param_1 % param_2
        param_1 = temp_p2
    return param_1


class Packet(object):
    def __init__(self, data, timestamp):
        self.data = data
        self.timestamp = timestamp

def parsePacketsFromPickle(filename):
    # for reading also binary mode is important
    dbfile = open(filename, 'rb')
    db = pickle.load(dbfile)
    dbfile.close()

    SW_packets = db['SW']
    PLC_packets = db['PLC']

    finished = False
    packetBlockIdx = 0
    while True:
        initialMasterKey = [0x17,0xde,0x34,0x45,0x34,0x15,0xff,0xee,
                            0xa6,0xe5,0x7b,0x75,0x79,0x11,0x08,0xf7]
        dataThing = [0x97,0x31,0x8F,0xAC,0x2F,0x3D,0xF9,0xD9,
                    0xE2,0x34,0x3A,0xD8,0x43,0x3C,0xE9,0x8C]

        # Print unencrypted messages
        print("Message {0} from SW (U)".format(1+packetBlockIdx))
        print("Length: {0}".format(len(SW_packets[packetBlockIdx+0].data)))
        print(get_hex_list_str(SW_packets[packetBlockIdx+0].data))
        print("")

        print("Message {0} from PLC (U)".format(1+packetBlockIdx))
        print("Length: {0}".format(len(PLC_packets[packetBlockIdx+0].data)))
        print(get_hex_list_str(PLC_packets[packetBlockIdx+0].data))
        print("")

        print("Message {0} from SW (U)".format(2+packetBlockIdx))
        print("Length: {0}".format(len(SW_packets[packetBlockIdx+1].data)))
        print(get_hex_list_str(SW_packets[packetBlockIdx+1].data))
        print("")

        print("Message {0} from PLC (U)".format(2+packetBlockIdx))
        print("Length: {0}".format(len(PLC_packets[packetBlockIdx+1].data)))
        print(get_hex_list_str(PLC_packets[packetBlockIdx+1].data))
        print("")

        # Encrypted Messages
        firstEncryptedMessageFromSW = SW_packets[packetBlockIdx+2].data
        decryptedMessage = _decrypt(firstEncryptedMessageFromSW, initialMasterKey, dataThing)
        print("Message {0} from SW (E)".format(3+packetBlockIdx))
        print("Length: {0}".format(len(SW_packets[packetBlockIdx+2].data)))
        print(get_hex_list_str(decryptedMessage))
        print("")

        expected_RSA_N = decryptedMessage[0x5A:0x5A+4] # expected_RSA_N = esi[0x860] # value in first encrypted message from SW: msg[0x5a:0x5E]
        expected_RSA_N = expected_RSA_N[0] << 24 | expected_RSA_N[1] << 16 | expected_RSA_N[2] << 8 | expected_RSA_N[3]

        # First encrypted messsage from PLC
        firstEncryptedMessageFromPLC = PLC_packets[packetBlockIdx+2].data

        decryptedMessage = _decrypt(firstEncryptedMessageFromPLC, initialMasterKey, dataThing)
        print("Message {0} from PLC (E)".format(3+packetBlockIdx))
        print("Length: {0}".format(len(PLC_packets[packetBlockIdx+2].data)))
        print(get_hex_list_str(decryptedMessage))
        print("")

        seedIdx = 0
        seedFound = False
        while not seedFound:
            for seedIdxSign in range(2):
                # Time of first encrypted message sent from SW
                if seedIdxSign == 0:
                    tSeedIdx = seedIdx*1
                elif seedIdxSign == 1:
                    tSeedIdx = seedIdx*-1
                print("Check Seed Idx offset: {0}".format(-1*tSeedIdx))

                seed = SW_packets[packetBlockIdx+2].timestamp - seedIdx
                print("Seed: {0}".format(hex(seed)))

                print("Generating parameter for next key based on timestamp")
                RSA_N, RSA_E, RSA_D = genRSAKeys(seed)
                print("RSA N:", hex(RSA_N))
                if (RSA_N == expected_RSA_N):
                    seedFound = True
                    print("Found Seed Idx offset: {0}\n".format(-1*tSeedIdx))

                    print("Generating Next Key")
                    nextMasterKey = genMasterKey(decryptedMessage[0x1E:0x1E+0x20], RSA_N, RSA_D)
                    break

                if seedIdx == 0:
                    break

            seedIdx += 1

        idx = 0
        while True:
            # Next encrypted message from SW
            nextEncryptedMessageFromSW = SW_packets[packetBlockIdx+3+idx].data
            if (nextEncryptedMessageFromSW[0] == 0x4b and
                nextEncryptedMessageFromSW[1] == 0x4f and
                nextEncryptedMessageFromSW[2] == 0x50):
                # The key we have didn't work for this message, so it must have changed
                break

            decryptedMessage = _decrypt(nextEncryptedMessageFromSW, nextMasterKey, dataThing)
            print("Message {0} from SW (E)".format(4+idx+packetBlockIdx))
            print("Length: {0}".format(len(SW_packets[packetBlockIdx+3+idx].data)))
            print(get_hex_list_str(decryptedMessage))
            print("")

            # Next encrypted messsage from PLC
            nextEncryptedMessageFromPLC = PLC_packets[packetBlockIdx+3+idx].data

            decryptedMessage = _decrypt(nextEncryptedMessageFromPLC, nextMasterKey, dataThing)
            print("Message {0} from PLC (E)".format(4+idx+packetBlockIdx))
            print("Length: {0}".format(len(PLC_packets[packetBlockIdx+3+idx].data)))
            print(get_hex_list_str(decryptedMessage))
            print("")

            idx += 1
            if (packetBlockIdx+3+idx >= len(SW_packets)):
                finished = True
                break
        if finished:
            break

        packetBlockIdx += 3 + idx


if __name__ == '__main__':
    parsePacketsFromPickle('capture_connect_and_one_password.pkl')

