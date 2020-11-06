from socket import *
import threading
import time
from Crypto.Cipher import AES
import random


def pad(s: str):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def unpad(s: bytes):
    return s[0:-s[-1]]


def encrypt(data: str, key: bytes) -> bytes:
    data = pad(data).encode('utf-8')
    aes = AES.new(key, AES.MODE_CBC)
    iv = aes.iv
    enc = aes.encrypt(data)
    return iv + enc


def decrypt(data: bytes, key: bytes) -> str:
    iv = data[:16]
    enc = data[16:]
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    dec = aes.decrypt(enc)
    return unpad(dec).decode('utf-8')


def send(sock, key):
    while True:
        send_data = input('>>>')
        sock.send(encrypt(send_data, key))


def receive(sock, key):
    while True:
        recv_data = sock.recv(1024)
        print('상대방 :', decrypt(recv_data, key))


def login(socket):
    """
    TODO: 아이디와 패스워드 값을 전송하는 함수
    만들어진 send 못쓴이유: key가 없어서
    :return: 없음
    """
    user_id = input('id: ')
    password = input('pw: ')
    # socket 통신으로 id와 password를 전송
    data = (user_id + "/"+password).encode('utf-8')
    socket.send(data)


def generate_key(key: int or None = None) -> int:
    """
    테스트를 위해 임의 key를 입력할 경우에 해당 key를 반환하도록 구현
    기본적으로 랜덤한 secret 키를 생성
    :param key: 반환받을 키값
    :return: 랜덤 키 생성 혹은 입력값 그대로 반환
    저는 테스트 안해봐서 모르겠습니다. 필요한가?
    """
    if key is not None:
        return key
    return random.randint(10000000000000000, 100000000000000000000000000000000000000000000000)


def diffie_hellman(my_secret_key: int, target_public_key: int) -> bytes:
    """
    TODO: [함수 설명] 16byte 크기로 잘라 반 <-?
    설명이 뭔지 몰라서
    생성된 키를 byte 변환한 것의 앞 16바이트 잘라서 사용
    
    :param my_secret_key: 내 개인키
    :param target_public_key: 상대방 공개키
    :return: 상대방 공개키** 내 개인키 (mod p) 값의 앞 16바이트
    """
    p = 9723448991222331098330293371197519246446906995517093957384966642329511534161627658859950763542683697458467770974347360725590854862427735703874399411721649
    g = 2348329574892572380947382043
    original_key = pow(target_public_key, my_secret_key, p)
    key = original_key.to_bytes(1024, byteorder='little')

    return key[:16]


def public_key(secret_key: int) -> int:
    """
    TODO: diffie hellman에서의 public key를 계산하여 반환하는 함수
    :param secret_key: 내 개인키
    :return: 전송할 공개키
    """
    p = 9723448991222331098330293371197519246446906995517093957384966642329511534161627658859950763542683697458467770974347360725590854862427735703874399411721649
    g = 2348329574892572380947382043
    return pow(g, secret_key, p)

def connect_socket():
    port = 8081

    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(('127.0.0.1', port))
    print('접속 완료')

    login(client_socket)
    print('로그인 완료')

    my_secret_key = generate_key()
    # TODO: 자신의 public key를 전송해야 함
    '''
    키교환 코드 부분이 자연스럽게 실행되게 하면 서버에서 인식오류가 나서
    116번째 라인 빈 변수를 사용하여 임의로 통신흐름을 제어함
    더 깔끔하게 할 방법은 모르겠음
    이정도면 굉장히 노력했다고 생각합니다.
    '''
    dunnohowtostop = input('press enter to send key')
    my_pub_key = public_key(my_secret_key)
    client_socket.send(my_pub_key.to_bytes(1024, byteorder='little'))

    target_public_key = int.from_bytes(client_socket.recv(1024), byteorder='little')  # little endian 으로 보내야 함
    key = diffie_hellman(my_secret_key, target_public_key)
    print('키 교환 완료')

    sender = threading.Thread(target=send, args=(client_socket, key))
    receiver = threading.Thread(target=receive, args=(client_socket, key))

    sender.start()
    receiver.start()

    while True:
        time.sleep(1)
        pass


if __name__ == '__main__':
    connect_socket()
    # p = 9723448991222331098330293371197519246446906995517093957384966642329511534161627658859950763542683697458467770974347360725590854862427735703874399411721649
    # print(p.to_bytes(64, byteorder='little'))
    # print(int.from_bytes(p.to_bytes(64, byteorder='little'), byteorder='little'))
