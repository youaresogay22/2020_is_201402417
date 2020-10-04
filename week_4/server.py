from socket import *
import threading
import time


def send(sock, send_data):
    """
    함수설명:
    TCP 소켓 통신 서버의 send 함수
    무한반복문 내에서 쓰레드로 동작하며 connect된 소켓의 주소로
    전송받은 데이터를 그대로 전송하는 함수
    :param sock: 파이썬 서버 소켓 객체(TCP,IPv4)
    :param send_data: 전송받은 데이터
    :return: 없음
    """
    sock.send(send_data)


def receive(sock, addr, dst):
    """
    함수설명:
    TCP 소켓 통신 서버의 receive 함수
    무한반복문 내에서 쓰레드로 동작하며 connect된 소켓에서
    전송받은 데이터를 자기 프로세스에 출력한 후에
    다른 클라이언트로 전송하는 함수
    
    :param sock: 파이썬 서버 소켓 객체(TCP,IPv4)
    :param addr: 접속된 클라이언트의 ip 주소
    :param dst: 다른 클라이언트의 소켓 객체
    :return: 없음
    """
    while True:
        recv_data = sock.recv(1024)
        try:
            print(f'{addr} :', recv_data.decode('utf-8'))
        except:
            print(f'{addr} :', recv_data)
        send(dst, recv_data)


port = 8081

serverSock = socket(AF_INET, SOCK_STREAM)
serverSock.bind(('', port))
serverSock.listen(2)

print('%d번 포트로 접속 대기중...'%port)

connectionSock1, addr1 = serverSock.accept()
connectionSock2, addr2 = serverSock.accept()

print(str(addr1), '에서 접속되었습니다.')
print(str(addr2), '에서 접속되었습니다.')

receiver1 = threading.Thread(target=receive, args=(connectionSock1,addr1, connectionSock2))
receiver2 = threading.Thread(target=receive, args=(connectionSock2,addr2, connectionSock1))

receiver1.start()
receiver2.start()

try:
    while True:
        time.sleep(1)
        pass
except KeyboardInterrupt:
    serverSock.close()
