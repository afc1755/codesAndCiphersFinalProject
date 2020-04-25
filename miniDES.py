# Created by: Andrew Chabot
# mini DES implementation
import random
import bitarray
import math
import time

def runMiniDES(filename, key=-1, verbose=False):
    if key == -1:
        key = random.getrandbits(8)
    key = format(key, '08b')

    if verbose:
        print("Performing mini DES with key: " + key)

    plainTextFile = open(filename, "r")
    plaintext = plainTextFile.read().replace(' ', '')
    bitPlain = bitarray.bitarray()
    bitPlain.frombytes(plaintext.encode('utf-8'))
    bitPlainL = bitPlain.tolist()
    textBlocks = []
    for i in range(0, math.ceil(len(bitPlainL)/8)):
        if 8 * (i + 1) > len(bitPlainL):
            textBlocks.append(bitPlainL[(8 * i):len(bitPlainL)])
            for x in range(len(bitPlainL), (8 * (i + 1))):
                textBlocks[i] += "0"
        else:
            textBlocks.append(bitPlainL[(8 * i):(8 * (i + 1))])

    # run DES algorithm, get the result in blocks
    cipherBlocks = []
    for blockStep in range(0, len(textBlocks)):
        cipherBlocks.append(mDESRun(textBlocks[blockStep], 16, key))

    # recombine blocks into full ciphertext
    cipherText = ""
    for i in range(0, len(cipherBlocks)):
        for j in range(0, len(cipherBlocks[i])):
            cipherText += str(cipherBlocks[i][j])

    binPlain = ""
    for i in range(0, len(bitPlain)):
        binPlain += str(int(bitPlain[i]))

    cipherBin = cipherText
    if verbose:
        print("Binary Plaintext: " + binPlain)
        print("Plaintext: " + plaintext)
        print("Binary Ciphertext: " + cipherBin)
        cipherText = "".join(chr(int("".join(map(str,cipherText[i:i+8])),2)) for i in range(0,len(cipherText),8))
        print("Ciphertext: " + cipherText)

    return binPlain, cipherBin


def mDESRun(pB, rounds, fullKey):

    # initial permutation
    fullKey = [fullKey[1], fullKey[2], fullKey[3], fullKey[4], fullKey[5], fullKey[6], fullKey[7], fullKey[0]]

    # initial split up of halves
    leftBlock = pB[:4]
    rightBlock = pB[4:]

    # rounds where the round key is rotated twice instead of jsut once
    twoRoundList = [3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15]
    leftKey = list(fullKey[:4])
    rightKey = list(fullKey[4:])
    for i in range(0, rounds):

        # key rotation
        leftKey.append(leftKey.pop(0))
        rightKey.append(rightKey.pop(0))
        if i in twoRoundList:
            leftKey.append(leftKey.pop(0))
            rightKey.append(rightKey.pop(0))
        k8 = leftKey.copy()
        k8.extend(rightKey)

        # key permutation
        key6 = [k8[5], k8[4], k8[3], k8[2], k8[1], k8[0]]

        # switch right and left side, and xor with the feistel function, actual encryption
        leftBlock, rightBlock = rightBlock, xor(leftBlock, feistel(leftBlock, key6))

    return leftBlock + rightBlock

# helpful xor function for two blocks of the same size
def xor(b1, b2):
    outB = []
    for i in range(0, len(b1)):
        if(int(b1[i]) == int(b2[i])):
            outB.append(0)
        else:
            outB.append(1)
    return outB

# fesitel fucntion that permutes and does S-box work
def feistel(currBlock, rKey):

    #exapnsions function
    currBlock = [currBlock[3], currBlock[0], currBlock[1], currBlock[2], currBlock[3], currBlock[1]]
    currBlock = xor(currBlock, rKey)
    sBox = [[14, 4 , 13, 1, 2 ,15, 11, 8 , 3 , 10, 6 , 12, 5 , 9 , 0, 7],
            [0 , 15, 7 , 4, 14, 2, 13, 1 , 10, 6 , 12, 11, 9 , 5 , 3, 8],
            [4 , 1 , 14, 8, 13, 6, 2 , 11, 15, 12, 9 , 7 , 3 , 10, 5, 0],
            [15, 12, 8 , 2, 4 , 9, 1 , 7 , 5 , 11, 3 , 14, 10, 0 , 6, 13]]
    column = bin2dec(int(str(currBlock[0]) + str(currBlock[5])))
    row = bin2dec(int(str(currBlock[1]) + str(currBlock[2]) + str(currBlock[3]) + str(currBlock[4])))
    sBoxBlock = list(str(dec2bin(sBox[column][row])))
    return [sBoxBlock[1], sBoxBlock[2], sBoxBlock[3], sBoxBlock[0]]

# Binary to decimal conversion
def bin2dec(binary):
    binary1 = binary
    decimal, i, n = 0, 0, 0
    while (binary != 0):
        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary // 10
        i += 1
    return decimal


# Decimal to binary conversion
def dec2bin(num):
    res = bin(num).replace("0b", "")
    if (len(res) % 4 != 0):
        div = len(res) / 4
        div = int(div)
        counter = (4 * (div + 1)) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res

def crackMiniDES():
    plainT, cipherT = runMiniDES("plain.txt")

    print("Plaintext: " + plainT)
    print("Ciphertext to find: " + cipherT)

    #search for a key
    start = time.time()
    for potentialKey in range(0, 256):
        potP, potC = runMiniDES("plain.txt", potentialKey)
        if potC == cipherT:
            print("Key found: " + format(potentialKey, '08b'))
            end = time.time()
            print("Crack completed in " + str(end - start) + " seconds")
            break

def runMiniDESVerbose():
    runMiniDES("plain.txt", verbose=True)

choice = input("Type c for crack program or e for verbose mini DES encryption: ")
if choice.lower() == 'c':
    crackMiniDES()
else:
    runMiniDESVerbose()

