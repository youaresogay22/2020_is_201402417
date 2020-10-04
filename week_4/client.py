from socket import *
import threading
import time
from Crypto.Cipher import AES


def pad(s: str):
    """
    AES의 CBC 모드 사용 시 최소 16바이트의 평문 블록이 필요하므로
    그 미만의 입력이 들어온 경우 padding 규칙이 적용된 
    16바이트 문자열을 리턴하는 함수
    :param s: 16바이트 미만의 스트링
    :return: padding된 문자열
    """
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def unpad(s: bytes):
    """
    padding한 문자열의 원래 문자열을 리턴하는 함수 
    :param s: padding된 문자열(padding되지 않아도 상관없음)
    :return: unpadding된 문자열
    """
    return s[0:-s[-1]]


def encrypt(data: str, key: bytes) -> bytes:
    """
    AES-CBC 모드로 평문을 암호화하는 함수
    iv는 pycrypto 생성자에서 생성한 것을 사용함
    :param data: 전달을 원하는 평문
    :param key: AES 키값, 항상 16바이트 입력을 받는다고 가정
    :return: iv와 암호화된 문자열을 merge한 바이트 스트림
    """
    #  TODO: 구현할 부분 (data.encode('utf-8') 도 변경해도 됨)
    cipher = AES.new(key, AES.MODE_CBC)
    data = cipher.iv + cipher.encrypt(pad(data).encode('utf-8'))

    return data


def decrypt(data: bytes, key: bytes) -> str:
    """
    AES-CBC 모드로 암호화된 평문을 복호화하는 함수
    iv에 해당하는 바이트 문자열을 떼어낸 뒤 
    나머지 문자열을 iv를 이용하여 복호화함
    :param data: iv와 암호문이 합쳐진 바이트 스트림
    :param key: 사용자가 지정한 AES 키값
    :return: 복호화된 평문
    """
    #  TODO: 구현할 부분 (data.decode('utf-8') 도 변경해도 됨)
    myiv = data[0:16]
    cipher = AES.new(key, AES.MODE_CBC, iv=myiv)
    data = cipher.decrypt(data[16:])
    data = unpad(data)
    
    return data.decode('utf-8')


def send(sock, key):
    """
    함수설명:
    TCP 소켓 통신 클라이언트의 send 함수
    무한반복문 내에서 쓰레드로 동작하며 사용자 입력으로
    받은 문자열을 AES 암호화하여 전송하는 함수
    :param sock: 파이썬 소켓 객체(TCP,IPv4)
    :param key: 사용자 입력 AES 키값
    :return: 없음
    """
    while True:
        send_data = input('>>>')
        sock.send(encrypt(send_data, key))


def receive(sock, key):
    """
    함수설명:
    TCP 소켓 통신 클라이언트의 receive 함수
    무한반복문 내에서 쓰레드로 동작하며 다른 클라이언트에서
    전송한 문자열을 AES 복호화하여 출력하는 함수
    :param sock: 파이썬 소켓 객체(TCP,IPv4)
    :param key: 사용자 입력 AES 키값
    :return: 없음
    """
    while True:
        recv_data = sock.recv(1024)
        print('상대방 :', decrypt(recv_data, key))


port = 8081

clientSock = socket(AF_INET, SOCK_STREAM)
clientSock.connect(('127.0.0.1', port))

print('접속 완료')

key = input('key를 입력해주세요: ')
sender = threading.Thread(target=send, args=(clientSock, key.encode('utf-8')))
receiver = threading.Thread(target=receive, args=(clientSock, key.encode('utf-8')))

sender.start()
receiver.start()

while True:
    time.sleep(1)
    pass
