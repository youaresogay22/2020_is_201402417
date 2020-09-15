import string
from enum import Enum

lower_alphabet_list = list(string.ascii_lowercase)
upper_alphabet_list = list(string.ascii_uppercase)
number_list = list(string.digits)


class EncryptionMode(Enum):
    ENC = 'ENCRYPT'
    DEC = 'DECRYPT'


def vigenere_encrypt_decrypt(text: str, key: str, mode: EncryptionMode) -> str:
    """
    비제네르 암호를 이용하여 암호화 혹은 복호화를 수행하는 암호 알고리즘
    :param text: 암호화할 문자열
    :param key: 암호화에 사용할 key의 배열
    :param mode: 암호화할 지 복호화할 지 구분하기 위한 값
    :return: 비제네르 암호를 이용한 암호문 혹은 복호화된 문자열
    """
    keylist = list(key)
    strlist = list(text)

    if len(text) == len(key):
        keylist = list(key)
    else:

        for i in range(len(text) - len(key)):
            keylist.append(keylist[i % len(key)])

        '''
        print(len(key_merged))
        print(len(keylist))
        '''

    if mode == EncryptionMode.ENC:
        enc_text = []

        for j in range(len(text)):
            if strlist[j] in lower_alphabet_list:
                x = (ord(strlist[j]) + ord(keylist[j]) - 97 - 97) % 26
                x += ord('a')
                enc_text.append(chr(x))

            elif strlist[j] in upper_alphabet_list:
                x = (ord(strlist[j]) + ord(keylist[j]) - 65 - 97) % 26
                x += ord('A')
                enc_text.append(chr(x))

            elif strlist[j] in number_list:
                x = (ord(strlist[j]) + ord(keylist[j]) - 48 - 97) % 10
                x += ord('0')
                enc_text.append(chr(x))

        return('' . join(enc_text))

    elif mode == EncryptionMode.DEC:
        dec_text = []

        for i in range(len(text)):
            if strlist[i] in lower_alphabet_list:
                x = (ord(strlist[i]) - ord(keylist[i]) + 26) % 26
                x += ord('a')
                dec_text.append(chr(x))

            elif strlist[i] in upper_alphabet_list:
                x = (ord(strlist[i]) - ord(keylist[i]) + 32 + 26) % 26
                x += ord('A')
                dec_text.append(chr(x))

            elif strlist[i] in number_list:
                x = (ord(strlist[i]) - ord(keylist[i]) + 49 + 10) % 10
                x += ord('0')
                dec_text.append(chr(x))

        return('' . join(dec_text))