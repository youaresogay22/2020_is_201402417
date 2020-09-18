from typing import List
from bitarray import bitarray


def string_to_bits(string: str) -> List[bool]:
    bits = bitarray()
    bits.frombytes(string.encode('utf-8'))
    return bits.tolist()


def bits_to_string(bits: List[bool]) -> str:
    return bitarray(bits).tobytes().decode('utf-8')


def xor_encrypt_decrypt(message: str, key: str) -> str:
    """
    exclusive or 연산(^연산자)을 이용해 암호화 및 복호화를 수행하는 함수
    파라미터로 받은 문자열을 비트로 변환한 뒤 
    1비트마다 키의 비트 배열과 xor 연산을 계속 수행하여 암호화 또는 복호화
    :param message: 암호화 또는 복호화할 문자열
    :param key: 암호화 또는 복호화에 이용할 key 값
    :return: exclusive or 연산을 통해 암호화 또는 복호화된 문자열
    """
    message_bits = string_to_bits(message)
    key_bits = string_to_bits(key)

    for i in range(len(message_bits)):
        message_bits[i] = message_bits[i] ^ key_bits[i % len(key_bits)]

    return bits_to_string(message_bits)
