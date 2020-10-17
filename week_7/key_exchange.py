from typing import Dict, List

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def pad(s: str):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def unpad(s: bytes):
    return s[0:-s[-1]]


def encrypt(data: str, key: bytes or None) -> bytes:
    if key is None:
        return data.encode('utf-8')
    data = pad(data).encode('utf-8')
    aes = AES.new(key, AES.MODE_CBC)
    iv = aes.iv
    enc = aes.encrypt(data)
    return iv + enc


def decrypt(data: bytes, key: bytes) -> str:
    if key is None:
        return data.decode('utf-8')
    iv = data[:16]
    enc = data[16:]
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    dec = aes.decrypt(enc)
    return unpad(dec).decode('utf-8')


class Proxy:
    def __init__(self):
        self._linked_ip: Dict[str, "Client"] = {}
        self.msg_list: List[str] = []

    def link(self, client: "Client"):
        self._linked_ip[client.ip] = client

    def public_key(self, target_ip: str):
        """
        Public key는 올바르게 전송해줌을 가정합니다.
        :param target_ip: 클라이언트 객체 ip주소
        :return: 매개변수로 받은 ip주소에 해당하는 클라이언트 객체의 공개키
        """
        return self._linked_ip[target_ip].key.publickey()

    def request(self, source_ip: str, target_ip: str, msg: bytes):
        try:
            self.msg_list.append(msg.decode('utf-8'))
        except UnicodeDecodeError:
            print("Can't read Data in proxy")

        self._linked_ip[target_ip].receive(msg, source_ip)

    def client(self, ip: str) -> "Client":
        """
        상대 client를 ip값과 proxy를 통해 얻을 수 있음
        :param ip: 얻을 클라이언트 객체 ip주소
        :return: 매개변수로 받은 ip주소에 해당하는 클라이언트 객체
        """
        return self._linked_ip[ip]


class Client:
    def __init__(self, ip: str, rsa_key=None):
        self.ip = ip
        self.session_key: Dict[str, bytes] = {}   # { ip : session key }
        if rsa_key is None:
            self.key = RSA.generate(2048)             # RSA Key
        else:
            self.key = rsa_key
        self.msg_list: List[str] = []

    def request(self, proxy: Proxy, target_ip: str, msg: str):
        """
        TODO 함수 설명:
        :param proxy: 프록시 서버로 클라이언트 객체를 연결하며 실습자료 ppt에서 공개키 저장소 역할을 수행
                      handshake 함수 내에서 다른 클라이언트 객체를 쉽게 불러올 수 있도록 매개변수로 전달
        :param target_ip: 상대방 ip주소
        :param msg: 송신할 평문
        :return: 없음
        """
        if not self.session_key.get(target_ip):
            self.handshake(proxy, target_ip)
        
        enc = encrypt(msg, self.session_key[target_ip])
        proxy.request(self.ip, target_ip, enc)

    def receive(self, msg: bytes, source_ip: str):
        """
        TODO 함수설명:
        이전에 handshake 과정을 거쳐서 session key를 공유한 상황이어야 함
        :param msg: 공개키 암호를 통해 암호화된 암호문
        :param source_ip: 송신자 ip 주소
        :return: 없음
        """
        dec = decrypt(msg, self.session_key[source_ip])
        self.msg_list.append(dec)

    def handshake(self, proxy: Proxy, target_ip: str, session_key: bytes or None = None):
        """
        상대 ip에 대한 session key가 없을 경우 사용하는 함수
        target ip 주소의 client의 public key를 받아와 public key 로 암호화한 session key를 전송
        공유한 session key는 self.session_key 에 ip와 매핑하여 저장

        session key를 입력받았을 때는 암호화된 session_key를 받았음을 가정한다. test code 참고
        session key를 받지 않았을 경우 session key를 생성해 session key를 상대의 공개키로 암호화하여 handshake 진행
        :param proxy: 프록시 서버로 클라이언트 객체를 연결하며 실습자료 ppt에서 공개키 저장소 역할을 수행, 
                      다른 클라이언트 객체를 불러올 수 있게 해줌
        :param target_ip: 연결된 다른 클라이언트 객체의 ip주소
        :param session_key: 파라미터가 존재한다면, 나의 공개키를 통해 암호화된 세션키
        :return: 없음
        """
        # TODO: mode에 따라 각각 구현
        # handshake를 하는 상대도 session key를 저장해야 함
        if session_key is None:
            session_key = get_random_bytes(16)
            # TODO
            target_client = proxy.client(target_ip)
            target_public = PKCS1_OAEP.new(proxy.public_key(target_ip))
            enc = target_public.encrypt(session_key)
            target_client.handshake(proxy, self.ip, enc)

        else:
            # TODO
            target_client = proxy.client(target_ip)
            my_private = PKCS1_OAEP.new(self.key)
            dec = my_private.decrypt(session_key)
            self.session_key[target_ip] = dec
            target_client.session_key[self.ip] = dec


"""
RSA 라이브러리 활용을 위한 예제 코드
구현 이후에는 아래 코드는 지워주시길 바랍니다.
"""
'''
if __name__ == '__main__':
    key = RSA.generate(2048)  # RSA Key
    pub = key.publickey()

    rsa_pub = PKCS1_OAEP.new(pub)
    rsa_priv = PKCS1_OAEP.new(key)
    print(rsa_pub.encrypt(b'abc'))
    print(rsa_priv.decrypt(rsa_pub.encrypt(b'abc')))
'''