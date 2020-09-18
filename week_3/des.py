from Crypto.Cipher import DES


def encrypt_des(message: str, key: str, mode: int, iv=None) -> (bytes, bytes):
    """
    pycrypto DES 라이브러리를 이용하여 주어진 평문을 암호화하는 함수

    :param message: 암호화할 문자열
    :param key: 암호화에 사용할 키값. 8바이트
    :param mode: 암호화 시 어떤 모드로 동작할 지 설정. 기본값은 MODE_ECB
    :param iv: 초기화 벡터(initialization vector), 블록 암호에서
    첫 블록을 암호화할 때에 사용하는 문자열. MODE OFB에서의 길이는 8이며 기본값은 0
    :return: DES cipher 객체를 이용해 암호화된 문자열과 이때 사용된 초기화 벡터
    """

    cipher = DES.new(bytes(key, 'utf-8'), mode, iv=iv)
    return cipher.iv, cipher.encrypt(bytes(message, 'utf-8'))


def decrypt_des(encrypted: bytes, key: str, mode: int, iv: bytes) -> str:
    """
    pycrypto DES 라이브러리를 이용하여 주어진 평문을 암호화하는 함수
    :param encrypted: 암호화된 문자열
    :param key: 복호화에 사용할 키값. 8바이트, 비밀 키.
    :param mode: 암호화 시 어떤 모드로 동작할 지 설정
    :param iv: 암호화 시 사용한 초기화 벡터(initialization vector)값, 모르면 복호화할 수 없다
    :return: DES cipher 객체를 이용해 복호화된 문자열
    """

    cipher = DES.new(bytes(key, 'utf-8'), mode, iv=iv)
    return cipher.decrypt(encrypted).decode('utf-8')
