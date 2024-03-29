import string

lower_alphabet_list = list(string.ascii_lowercase)
upper_alphabet_list = list(string.ascii_uppercase)
number_list = list(string.digits)


def caesar_encrypt_decrypt(text: str, key: int) -> str:
    """
    시저 암호를 이용하여 암호화 혹은 복호화를 수행하는 암호 알고리즘
    :param text: 암호화할 문자열
    :param key: 암호화에 사용할 key
    :return: 시저 암호를 이용한 암호문 혹은 복호화된 문자열
    """

    strlist = list(text)
    result = []

    for j in range(len(text)):
        if strlist[j] in lower_alphabet_list:
            x = (ord(strlist[j]) - 97 + key) % 26
            x += ord('a')
            result.append(chr(x))

        elif strlist[j] in upper_alphabet_list:
            x = (ord(strlist[j]) - 65 + key) % 26
            x += ord('A')
            result.append(chr(x))

        elif strlist[j] in number_list:
            x = (ord(strlist[j]) - 48 + key) % 10
            x += ord('0')
            result.append(chr(x))

    return('' . join(result))