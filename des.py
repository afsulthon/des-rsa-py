# Matriks permutasi awal (IP)
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

# Matriks permutasi kompresi 1 (PC1)
PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

# Matriks banyak pergeseran bit tiap ronde
shift_mat = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Matriks permutasi kompresi 2 (PC2)
PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

# Matriks permutasi ekspansi
E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

# Matriks permutasi P
P_Box = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

# 8 matriks kotak-S
S_Box = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
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

# Matriks permutasi awal balikan (IP^-1)
IP_INV = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]


def hex2bin(s):
    mp = {
        '0': "0000",
        '1': "0001",
        '2': "0010",
        '3': "0011",
        '4': "0100",
        '5': "0101",
        '6': "0110",
        '7': "0111",
        '8': "1000",
        '9': "1001",
        'A': "1010",
        'B': "1011",
        'C': "1100",
        'D': "1101",
        'E': "1110",
        'F': "1111"
    }
    bin = ""
    for i in range(len(s)):
        bin = bin + mp[s[i]]
    return bin


def bin2hex(s):
    mp = {
        "0000": '0',
        "0001": '1',
        "0010": '2',
        "0011": '3',
        "0100": '4',
        "0101": '5',
        "0110": '6',
        "0111": '7',
        "1000": '8',
        "1001": '9',
        "1010": 'A',
        "1011": 'B',
        "1100": 'C',
        "1101": 'D',
        "1110": 'E',
        "1111": 'F'
    }
    hex = ""
    for i in range(0, len(s), 4):
        ch = ""
        ch += s[i]
        ch += s[i + 1]
        ch += s[i + 2]
        ch += s[i + 3]
        hex += mp[ch]
    return hex


def bin2dec(binary):
    decimal = 0
    binary = binary[::-1]
    for i in range(len(binary)):
        if binary[i] == '1':
            decimal += 2**i
    return decimal


def dec2bin(decimal):
    res = bin(decimal).replace("0b", "")
    if (len(res) % 4 != 0):
        div = len(res) / 4
        div = int(div)
        counter = (4 * (div + 1)) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res


def permute(str, mat):
    permutation = ""
    for i in range(len(mat)):
        permutation += str[mat[i] - 1]
    return permutation


def shift_left(str, n):
    temp = ""
    for _ in range(n):
        for i in range(1, len(str)):
            temp += str[i]
        temp += str[0]
        str = temp
        temp = ""
    return str


def xor(str1, str2):
    xor_str = ""
    for i in range(len(str1)):
        if str1[i] == str2[i]:
            xor_str += "0"
        else:
            xor_str += "1"
    return xor_str


def encrypt(text, round_key):
    # Konversi string heksadesimal ke biner
    text = hex2bin(text)

    # Permutasi awal
    text = permute(text, IP)

    # Pembagian string teks menjadi dua blok (kiri dan kanan)
    left = text[0:32]
    right = text[32:64]

    # 16 ronde enkripsi
    for i in range(16):
        # Ekspansi 32-bit blok teks kanan ke 48-bit
        right_exp = permute(right, E)

        # XOR kunci ronde saat ini dengan blok teks kanan yang telah diekspansi
        A = xor(right_exp, round_key[i])

        # Substitusi kotak-S
        # Bagi A menjadi 8 bagian (masing-masing 6-bit)
        B = ""
        for j in range(8):
            row = bin2dec(A[j * 6] + A[j * 6 + 5])  # b1b6
            col = bin2dec(A[j * 6 + 1] + A[j * 6 + 2] +
                          A[j * 6 + 3] + A[j * 6 + 4])  # b2b3b4b5
            # Ambil nilai kotak-S dari baris dan kolom yang sesuai
            B += dec2bin(S_Box[j][row][col])

        # Permutasi hasil substitusi kotak-S 48-bit dengan matriks P-box menjadi 32-bit
        B = permute(B, P_Box)

        # XOR blok teks kiri dengan hasil permutasi P-box
        result = xor(left, B)
        left = result

        # Tukar blok teks kiri dan kanan untuk ronde selanjutnya
        if (i != 15):
            left, right = right, left

    # Gabungkan blok teks kiri dan kanan
    combine = left + right

    # Permutasi terakhir dengan matriks permutasi awal balikan
    cipher_text = permute(combine, IP_INV)

    return bin2hex(cipher_text)


def decrypt(cipher_text, round_key):
    round_key_rev = round_key[::-1]
    return encrypt(cipher_text, round_key_rev)


def generate_round_key(key):
    # Konversi string key dari heksadesimal ke biner
    key = hex2bin(key)

    # Kompresi 64-bit kunci DEF dengan PC-1 untuk mendapatkan 56-bit kunci
    key = permute(key, PC1)

    # Pembagian kunci DEF menjadi dua bagian
    left = key[0:28]
    right = key[28:56]

    # Inisialisasi list untuk kunci setiap ronde
    round_key = []

    for i in range(16):
        # Shift left bit string key kiri dan kanan sebanyak n kali (sesuai shift_mat)
        left = shift_left(left, shift_mat[i])
        right = shift_left(right, shift_mat[i])

        # Gabungkan key kiri dan kanan
        combine_str = left + right

        # Kompresi 56-bit kunci DEF dengan PC-2 untuk mendapatkan 48-bit kunci ronde
        cur_rk = permute(combine_str, PC2)

        # Tambahkan kunci ronde ke dalam list
        round_key.append(cur_rk)

    return round_key

# text = "A1B4C7D2E5F80913"
# key = "2F6A8D1B3C7E5904"

# round_key = generate_round_key(key)

# cipher_text = encrypt(text, round_key)
# print("Cipher text:", cipher_text)

# text = decrypt(cipher_text, round_key)
# print("Plain text:", text)
