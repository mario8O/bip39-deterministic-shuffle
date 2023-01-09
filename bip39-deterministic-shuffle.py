"""
This script can be used to prepare BIP39 seed phrase encryption/decryption using paper only.
Encryption/decryption maps created by this script are deterministically derived from the given password
and therefore don't have to be kept.
"""

from hashlib import sha256
from json import dumps

encrypt_map = {}
decrypt_map = {}


def remove_line_breaks(x):
    """ Remove line breaks in elements of list x in place. """
    for i in range(0, len(x)):
        x[i] = x[i].replace("\n", "")


def read_words():
    """
    Load original BIP39 word list from
    https://github.com/bitcoin/bips/tree/master/bip-0039
    """
    with open("english.txt", "r") as in_file:
        words = in_file.readlines()
    remove_line_breaks(words)
    return words


def str_to_hash(s):
    """ Return SHA256 value for given string. """
    return sha256(s.encode('utf-8')).hexdigest()


def hex_to_int(h):
    """ Return int value from given hex string. """
    return int(h[:8], 16)  # using left 4 bytes


def deterministic_shuffle(x, seed):
    """
    Shuffle list x in place depending on given seed string.
    Better not rely on random.shuffle to be independent of hardware, OS and Python.
    """
    seed_hash = str_to_hash(seed)
    for i in range(0, len(x)):
        rand = hex_to_int(seed_hash)
        # pick an element in x[:i+1] with which to exchange x[i]
        j = rand % len(x)
        x[i], x[j] = x[j], x[i]
        seed_hash = str_to_hash(seed_hash)


def create_maps(shuffled_words):
    """ Create encrypt/decrypt maps. """
    for w in read_words():
        encrypt_map[w] = shuffled_words.index(w) + 1
    for i in range(0, len(shuffled_words)):
        decrypt_map[i + 1] = shuffled_words[i]


def check_maps():
    """ Perform checks to ensure correctness and return checksum. """
    words = read_words()
    for w in words:
        if w not in encrypt_map:
            print(f"[ERROR] Missing word '{w}'")
            exit(1)
        if encrypt_map[w] == words.index(w) + 1:
            print(f"[INFO] Unchanged index for word '{w}'")
        if decrypt_map[encrypt_map[w]] != w:
            print(f"[ERROR] Failed to encrypt/decrypt word '{w}'")
            exit(1)
    return str_to_hash(dumps(encrypt_map))[:7]


def write_maps(signature):
    """ Write encrypt/decrypt maps as dictionary files. """
    with open(f"encrypt_{signature}.dict", "w") as out_file:
        out_file.write(dumps(encrypt_map))
    with open(f"decrypt_{signature}.dict", "w") as out_file:
        out_file.write(dumps(decrypt_map))


def main(seed, is_test=False):
    shuffled_words = read_words()
    deterministic_shuffle(shuffled_words, seed)
    create_maps(shuffled_words)
    checksum = check_maps()
    if not is_test:
        write_maps(checksum)
    return checksum


def test():
    """ Perform script and original word list test. """
    if hex_to_int(str_to_hash("test")) != 2676412545:
        print("[ERROR] Unexpected hash to integer value!")
        exit(1)
    if main("test", True) != "dbbcf31":
        print("[ERROR] Test failed with unexpected checksum!")
        exit(1)
    print("Test passed.")


test()
password = input("Enter password: ")
print("Encrypt map checksum: " + main(password))
