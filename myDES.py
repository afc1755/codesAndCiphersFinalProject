# Created by: Andrew Chabot
# my attempt to implement DES before I found the code, doesn't work correctly unfortunately
import random
import bitarray
import math

def runDES(filename):
    intkey = random.getrandbits(64)
    firstKey = format(intkey, '064b')
    key = ""
    for i in range(len(firstKey), 0, -1):
        if i % 8 != 0:
            key += firstKey[i]

    plainTextFile = open(filename, "r")
    plaintext = plainTextFile.read().replace(' ', '')
    bitPlain = bitarray.bitarray()
    bitPlain.frombytes(plaintext.encode('utf-8'))
    bitPlainL = bitPlain.tolist()
    textBlocks = []
    for i in range(0, math.ceil(len(bitPlainL)/64)):
        if 64 * (i + 1) > len(bitPlainL):
            textBlocks.append(bitPlainL[(64 * i):len(bitPlainL)])
            for x in range(len(bitPlainL), (64 * (i + 1))):
                textBlocks[i] += "0"
        else:
            textBlocks.append(bitPlainL[(64 * i):(64 * (i + 1))])

    # run DES algorithm, get the result in blocks
    cipherBlocks = []
    for blockStep in range(0, len(textBlocks)):
        cipherBlocks.append(DESRun(textBlocks[blockStep], 16, key))

    # recombine blocks into full ciphertext
    cipherText = ""
    for i in range(0, len(cipherBlocks)):
        for j in range(0, len(cipherBlocks[i])):
            cipherText += cipherBlocks[i][j]

    binPlain = ""
    for i in range(0, len(bitPlain)):
        binPlain += str(int(bitPlain[i]))
    print("Binary Plaintext: " + binPlain)
    print("Plaintext: " + plaintext)
    print("Binary Ciphertext: " + cipherText)
    cipherText = "Ciphertext: " + "".join(chr(int("".join(map(str,cipherText[i:i+8])),2)) for i in range(0,len(cipherText),8))
    return cipherText


def DESRun(pB, rounds, fullKey):

    # initial permutation
    pB = [pB[57], pB[49], pB[41], pB[33], pB[25], pB[17], pB[9], pB[1],
          pB[59], pB[51], pB[43], pB[35], pB[27], pB[19], pB[11], pB[3],
          pB[61], pB[53], pB[45], pB[37], pB[29], pB[21], pB[13], pB[5],
          pB[63], pB[55], pB[47], pB[39], pB[31], pB[23], pB[15], pB[7],
          pB[56], pB[48], pB[40], pB[32], pB[24], pB[16], pB[8],  pB[0],
          pB[58], pB[50], pB[42], pB[34], pB[26], pB[18], pB[10], pB[2],
          pB[60], pB[52], pB[44], pB[36], pB[28], pB[20], pB[12], pB[4],
          pB[62], pB[54], pB[46], pB[38], pB[30], pB[22], pB[14], pB[6]]

    leftBlock = pB[:32]
    rightBlock = pB[32:]
    twoRoundList = [3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15]
    leftKey = list(fullKey[:28])
    rightKey = list(fullKey[28:])
    for i in range(0, rounds):

        # key rotation
        leftKey.append(leftKey.pop(0))
        rightKey.append(rightKey.pop(0))
        if i in twoRoundList:
            leftKey.append(leftKey.pop(0))
            rightKey.append(rightKey.pop(0))
        k56 = leftKey.copy()
        k56.extend(rightKey)

        # key permutation
        key48 = [k56[13], k56[16], k56[10], k56[23], k56[0], k56[4], k56[2], k56[27],
                 k56[14], k56[5], k56[20], k56[9], k56[22], k56[18], k56[11], k56[3],
                 k56[25], k56[7], k56[15], k56[6], k56[26], k56[19], k56[12], k56[1],
                 k56[40], k56[51], k56[30], k56[36], k56[46], k56[54], k56[29], k56[39],
                 k56[50], k56[44], k56[32], k56[47], k56[43], k56[48], k56[38], k56[55],
                 k56[33], k56[52], k56[45], k56[41], k56[49], k56[35], k56[28], k56[31]]

        # expand the right block
        expandedRight = [rightBlock[31], rightBlock[0], rightBlock[1], rightBlock[2], rightBlock[3], rightBlock[4],
                         rightBlock[3], rightBlock[4], rightBlock[5], rightBlock[6], rightBlock[7], rightBlock[8],
                         rightBlock[7], rightBlock[8], rightBlock[9], rightBlock[10], rightBlock[11], rightBlock[12],
                         rightBlock[11], rightBlock[12], rightBlock[13], rightBlock[14], rightBlock[15], rightBlock[16],
                         rightBlock[15], rightBlock[16], rightBlock[17], rightBlock[18], rightBlock[19], rightBlock[20],
                         rightBlock[19], rightBlock[20], rightBlock[21], rightBlock[22], rightBlock[23], rightBlock[24],
                         rightBlock[23], rightBlock[24], rightBlock[25], rightBlock[26], rightBlock[27], rightBlock[28],
                         rightBlock[27], rightBlock[28], rightBlock[29], rightBlock[30], rightBlock[31], rightBlock[0]]

        # xor the right block with the round key
        xorRight = []
        for xorCount in range(0, len(expandedRight)):
            if int(expandedRight[xorCount]) == int(key48[xorCount]):
                xorRight.append('0')
            else:
                xorRight.append('1')

        # run the sbox substitutions with the XORed block
        sBoxRight = sBoxRound(xorRight)

        # run the mid-round permutation on the sboxed block
        permRight = perm(sBoxRight)

        # xor the left block with the new right block
        for xorCount in range(0, len(permRight)):
            if permRight[xorCount] == leftBlock[xorCount]:
                leftBlock[xorCount] = '0'
            else:
                leftBlock[xorCount] = '1'

        # switch the keys, as long as it's not the last round
        if i != 15:
            leftBlock, rightBlock = permRight, leftBlock

    # recombine the left and right
    prePerm = leftBlock + rightBlock

    # final permutation
    cipherBlock = finalPerm(prePerm)
    return cipherBlock


# function that takes in a block and runs the sbox computations and returns the new block
def sBoxRound(xB):
    sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
             [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
             [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
             [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
            [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
             [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
             [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
             [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
            [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
             [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
             [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
             [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
            [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
             [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
             [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
             [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
            [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
             [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
             [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
             [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
            [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
             [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
             [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
             [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
            [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
             [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
             [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
             [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
    sBoxOut = ""
    for j in range(0, 8):
        row = int(xB[j * 6] + xB[j * 6 + 5], 2)
        col = int((xB[j * 6 + 1] + xB[j * 6 + 2] + xB[j * 6 + 3] + xB[j * 6 + 4]), 2)
        val = sbox[j][row][col]
        sBoxOut = sBoxOut + format(val, '04b')
    return sBoxOut


# mid-round permutation function
def perm(sB):
    sB = [sB[15], sB[6], sB[19], sB[20], sB[28], sB[11], sB[27], sB[16],
         sB[0], sB[14], sB[22], sB[25], sB[4], sB[17], sB[30], sB[9],
         sB[1], sB[7], sB[23], sB[13], sB[31], sB[26], sB[2], sB[8],
         sB[18], sB[12], sB[29], sB[5], sB[21], sB[10], sB[3], sB[24]]
    return sB


# function for the final permutation at the end of the DES cipher
def finalPerm(fB):
    fB = [fB[39], fB[7], fB[47], fB[15], fB[55], fB[23], fB[63], fB[31],
          fB[38], fB[6], fB[46], fB[14], fB[54], fB[22], fB[62], fB[30],
          fB[37], fB[5], fB[45], fB[13], fB[53], fB[21], fB[61], fB[29],
          fB[36], fB[4], fB[44], fB[12], fB[52], fB[20], fB[60], fB[28],
          fB[35], fB[3], fB[43], fB[11], fB[51], fB[19], fB[59], fB[27],
          fB[34], fB[2], fB[42], fB[10], fB[50], fB[18], fB[58], fB[26],
          fB[33], fB[1], fB[41], fB[9], fB[49], fB[17], fB[57], fB[25],
          fB[32], fB[0], fB[40], fB[8], fB[48], fB[16], fB[56], fB[24]]
    return fB


def frombits(bits):
    chars = []
    for b in range(int(len(bits) / 8)):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)

print(runDES("plain.txt"))
