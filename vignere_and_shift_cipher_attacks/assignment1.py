import math
import os

char_freq_table = {
        'A' : .082,
        'B' : .015,
        'C' : .028,
        'D' : .042,
        'E' : .127,
        'F' : .022,
        'G' : .02,
        'H' : .061,
        'I' : .07,
        'J' : .001,
        'K' : .008,
        'L' : .04,
        'M' : .024,
        'N' : .067,
        'O' : .075,
        'P' : .019,
        'Q' : .001,
        'R' : .06,
        'S' : .063,
        'T' : .09,
        'U' : .028,
        'V' : .01,
        'W' : .024,
        'X' : .02,
        'Y' : .001,
        'Z' : .001
}

# question 1 Shift Cipher ------------------------------------------------------------------------------------------------

def letter_to_int(letter):
    return ord(letter) - ord('A')

# 0 to 25 to letter
def int_to_letter(number):
    return chr(ord('A') + number)

# apply shift and return new number
def shift_char(letter, shift_num):
    shifted_char = int_to_letter((letter_to_int(letter) + shift_num) % 26)
    return shifted_char

# create new string based on shift
def create_shifted_string(old_string, shift):
    new_str = ""
    for ch in old_string:

        new_str += shift_char(ch, shift)
    return new_str

def get_char_freq(string):
    character_count_map = {}
    for ch in string:
        if ch in character_count_map:
            character_count_map[ch] += 1
        else:
            character_count_map[ch] = 1
    return character_count_map

# calculate probability of string
def calculate_probability(string):
    # probability will be occurence of letter divided by total length
    total_length = len(string)
    # hashmap storing the count of each character
    character_count_map = get_char_freq(string)
    # get the probability of all chars A to Z and see if it is approx 0.065
    probability_summation = 0
    for i in range(0, 26):
        current_char = int_to_letter(i)
        char_prob = 0 if current_char not in character_count_map else character_count_map[current_char] / total_length
        probability_summation += (char_freq_table[int_to_letter(i)] * char_prob)

    return probability_summation

def get_key(cipher):
    # try every shift from 0 to 25
    best_probability = 0
    best_shift = 0
    curr_probability = 0
    for i in range(0, 26):
        new_str = create_shifted_string(cipher, i)
        curr_probability = calculate_probability(new_str)
        if abs(best_probability - 0.065) > abs(curr_probability - 0.065):
            best_probability = curr_probability
            best_shift = i 

    return best_shift


def shift_cipher_attack(cipher):
    best_shift = get_key(cipher)

    # test out the result and decrypt
    decrypted_message = create_shifted_string(cipher, best_shift)
    print("The decrypted message is:\n")
    print(decrypted_message)

cipher = """KWSVVSYXKSBOKRKBNRKDKXNKNBEXUKBOKDKLKBGROXDROIQODDROSBLOOBC
DROIXYDSMOKPVISXOKMRWEQDROWSVVSYXKSBOZYVSDOVIKCUCDROLKBDOXN
OBPYBKXYDROBLOOBDROXZBYMOONCDYCSZSDDRORKBNRKDCZSVVCYEDTECDO
XYEQRDYQODBSNYPDROPVIKXNAEKPPCDROBOCDSDCXYGDRONBEXUCDEBXROC
DSMUCRSCRKXNSXDYDROLOOBQBKLCDROPVILIDROGSXQCKXNCRYEDCCZSDSD
YEDCZSDSDYEDBOKNOBCNSQOCDPOLBEKBIDGYDRYECKXNDOX"""
print("\nQuestion 1 -----------------------------------\n")
shift_cipher_attack(cipher)



    
# question 2 Vigenere Ciper ---------------------------------------------------------------------------------------------

def divide_into_subtexts(cipher_text, key_length):
    sub_texts = [''] * key_length
    for index, ch in enumerate(cipher_text):
        sub_texts[index % key_length] += ch
    return sub_texts

def determine_key_length(cipher_text):
    # Clean the ciphertext: remove extra chars 
    cipher_text = ''.join(filter(str.isalpha, cipher_text.upper()))

    best_key_length = 0
    best_num = 0
    # Assuming key length is below 20 characters
    for key_length in range(1, 21):

        sub_texts = divide_into_subtexts(cipher_text, key_length)
        # Compute IoC for each subtext
        sum_of_IoC = 0
        for subtext in sub_texts:
            character_count_map = get_char_freq(subtext)
            subtext_len = len(subtext)
            IoC = 0
            for freq in character_count_map.values():
                IoC += freq * (freq - 1)
            if subtext_len > 1:
                IoC /= (subtext_len * (subtext_len - 1))
            else:
                IoC = 0
            sum_of_IoC += IoC

        average_IoC = sum_of_IoC / key_length

        if abs(best_num - 0.065) > abs(average_IoC - 0.065):
            best_num = average_IoC
            best_key_length = key_length

    print("The best key length is", best_key_length, "and the IoC value is", best_num)

    return best_key_length



def chi_squared_statistic(observed_freq, expected_freq, total_letters):
    chi_squared = 0
    for letter in char_freq_table:
        observed = observed_freq.get(letter, 0)
        expected = expected_freq[letter] * total_letters
        chi_squared += ((observed - expected) ** 2) / expected if expected != 0 else 0
    return chi_squared

def find_best_shift(subtext):
    total_letters = len(subtext)
    observed_freq = get_char_freq(subtext)
    min_chi_squared = None
    best_shift = None

    for shift in range(26):
        # decrypt, shift backward
        shifted_text = create_shifted_string(subtext, -shift)  
        shifted_freq = get_char_freq(shifted_text)

        chi_squared = chi_squared_statistic(shifted_freq, char_freq_table, total_letters)

        if min_chi_squared is None or chi_squared < min_chi_squared:
            min_chi_squared = chi_squared
            best_shift = shift

    return best_shift

def find_key(sub_texts):
    key = ''
    for subtext in sub_texts:
        best_shift = find_best_shift(subtext)
        key_letter = int_to_letter(best_shift)
        key += key_letter
    return key

def decrypt_vigenere(cipher_text, key):
    decrypted_text = ''
    key_length = len(key)
    for index, ch in enumerate(cipher_text):
        key_char = key[index % key_length]
        shift = letter_to_int(key_char)
        decrypted_char = shift_char(ch, -shift)  
        decrypted_text += decrypted_char
    return decrypted_text


def vigenere_cipher_attack(cipher_text):
    # Clean the ciphertext
    cipher_text = ''.join(filter(str.isalpha, cipher_text.upper()))

    # Determine the key length
    key_length = determine_key_length(cipher_text)

    # Divide the ciphertext into subtexts
    sub_texts = divide_into_subtexts(cipher_text, key_length)

    # Find the key
    key = find_key(sub_texts)
    print("Recovered key:", key)

    # Decrypt the ciphertext
    decrypted_text = decrypt_vigenere(cipher_text, key)
    print("Decrypted text:", decrypted_text)

vigenere_cipher_text = """VPTHPDQVSAVVGEPZMEVMCAEKKDTIPFUADTXYGLPF
WNGZTSSEIMGVJKGVTUHZPOLPXYOIVUMWKKTUXVXM
CPRXUWUJSITCVHXVFXXUOJMQTZXYGPJUXZPOHLEJ
QVLHWFXMGDMKJPDBRUUICKKLPAEBXRYINMSIUQMT
SEVPHALVXQCLCRTLHDIIGJJZCRIIXUEJVPTDICNW
GNEEKHTKJRTUTYWKTMPAIUVPTPVMKVTZEEFBWLQF
TMAHGBCLPPWZEIAUIZIPQVVJJCGYMVFBDKSKJMEY
YEKVVALVAAWVYCFPPCIUQVTPREQDTTFVT"""

print("\nQuestion 2 -----------------------------------\n")
vigenere_cipher_attack(vigenere_cipher_text)


# Question 3 Bitwise Shift Cipher -------------------------------------------------------------------------------------------------------------------------


# check if key file exists, else create it, and write to file
key_file_path = './key.txt'
plain_text_path = './plain.txt'
cipher_text_path = './cipher.txt'


print("\nQuestion 3 -----------------------------------\n")
if not os.path.exists(key_file_path):
    with open(key_file_path, 'w') as file:
        key_hex = '2E'
        file.write()

key_hex = ''
with open(key_file_path, 'r') as key_file:
    key_hex = key_file.read().strip()

key_byte = int(key_hex, 16)

plain_text = ""
with open(plain_text_path, 'r') as plain_file:
    plain_text = plain_file.read().strip()

def encrypt_bitwise_shift_cipher(plain_text, key_byte):
    ciphertext_hex = ''
    for char in plain_text:
        plaintext_byte = ord(char)
        encrypted_byte = plaintext_byte ^ key_byte
        encrypted_hex = format(encrypted_byte, '02x')
        ciphertext_hex += encrypted_hex
    print("Encrypted message\n")
    print(ciphertext_hex, "\n")
    return ciphertext_hex

def decrypt_bitwise_shift_cipher(cipher_text, key_byte):
    message = ""
    for i in range(0, len(cipher_text), 2):
        # interpret each char as hex
        encrypted_hex = cipher_text[i:i+2]
        encrypted_byte = int(encrypted_hex, 16)

        message += chr(encrypted_byte ^ key_byte)
    return message
   

# encrypt
with open(cipher_text_path, 'w') as cipher_file:
    ciphertext_hex = encrypt_bitwise_shift_cipher(plain_text, key_byte)
    cipher_file.write(ciphertext_hex)

# De-crypt
with open(cipher_text_path, 'r') as cipher_file:
    cipher_text = cipher_file.read().strip()
    message = decrypt_bitwise_shift_cipher(cipher_text, key_byte) 
    with open("./decrypted.txt", 'w') as decrypted:
        decrypted.write(message)
    print("Message successfully decrypted:\n")
    print(message)























