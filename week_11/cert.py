import copy
from dataclasses import dataclass
from typing import List

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


@dataclass
class Cert:
    issuer: bytes
    public: bytes
    sign: bytes


class Issuer:
    def __init__(self, key: bytes, cert_chain=None):
        if cert_chain is None:
            cert_chain = []
        self.__secret = ECC.import_key(key)
        self.public = self.__secret.public_key()
        self.cert_chain: List[Cert] = cert_chain

    def change_secret(self, key: bytes):
        self.__secret = ECC.import_key(key)
        self.public = self.__secret.public_key()
        self.cert_chain = []

    def public_key(self) -> bytes:
        return bytes(self.public.export_key(format='DER'))

    def issue(self, pub_key: bytes):
        """
        TODO:
        자신의 certificate chain 과
        issuer의 public key, holder의 public key와 public key의 Hash에 대한 서명을 가진 dictionary 반환

        issuer가 holder에게 인증서를 발급하는 과정

        :param pub_key: holder의 공개키
        :return: cert_chain: holder의 cert chain
         [ { issuer: pub_key0, public_key: pub_key1, sign: Signature0(Hash(pub_key1)) }, ... ]
        """
        issuer_name = self.public_key()
        my_pub_key = pub_key
        my_cert_chain = self.cert_chain
        new_cert_chain = []
        signer = DSS.new(self.__secret, 'fips-186-3')

        my_pubkey_hash = SHA256.new(my_pub_key)
        my_pubkey_hash_sign = signer.sign(my_pubkey_hash)
        my_cert = Cert(issuer= issuer_name, public= pub_key, sign=my_pubkey_hash_sign)

        new_cert_chain.extend(my_cert_chain)
        new_cert_chain.append(my_cert)

        return new_cert_chain


class Holder:
    def __init__(self, key: bytes):
        self.__secret = ECC.import_key(key)
        self.public = self.__secret.public_key()
        self.cert: List[Cert] = []

    def set_cert(self, cert: List[Cert]):
        self.cert = cert

    def public_key(self) -> bytes:
        return bytes(self.public.export_key(format='DER'))

    def present(self, nonce: bytes) -> (List[Cert], bytes):
        """
        TODO:

        자신이 발급받아온 cert chain을 통해 서명을 증명하는 함수
        :param nonce: 랜덤 값
        :return: cert_chain, sign(nonce)
        """
        signer = DSS.new(self.__secret, 'fips-186-3')
        nonce_hash = SHA256.new(nonce)
        signature = signer.sign(nonce_hash)
        
        return self.cert, signature


class Verifier:
    def __init__(self, root_pub: bytes):
        self.root = root_pub

    def verify(self, cert_chain: List[Cert], pub_key: bytes, nonce: bytes, sign: bytes):
        """
        TODO:

        cert_chain을 검증하고 pub_key의 서명을 확인함

        root issuer는 저장된 root ca에 대한 정보를 이용하여 확인

        cert chain 검증 결과 root ca로부터 연결된 신뢰 관계를 갖고 있을 경우 True 반환

        :param cert_chain: holder의 cert chain
        :param pub_key: holder 공개키
        :param nonce: nonce(임의의 글자)
        :param sign: holder 개인키로 암호화된 nonce
        :return: ture or false
        """
        if self.root == b'':
            nonce_hash = SHA256.new(nonce)
            my_pub_key = ECC.import_key(pub_key)
            
            try:
                dss_verifier2 = DSS.new(my_pub_key, 'fips-186-3')
                dss_verifier2.verify(nonce_hash, sign)
                print('signature done_noca')
                return True
            except:
                return False

       
        elif not cert_chain:
            nonce_hash = SHA256.new(nonce)
            root_pub_key = ECC.import_key(pub_key)
            
            try:
                dss_verifier2 = DSS.new(root_pub_key, 'fips-186-3')
                dss_verifier2.verify(nonce_hash, sign)
                print('signature done_rootca')
                return True

            except:
                return False

        #cert chain 검증
        else:
            for cert_element in cert_chain:
                public_key_hash = SHA256.new(cert_element.public)
                nonce_hash = SHA256.new(nonce)
                issuer_pub_key = ECC.import_key(cert_element.issuer)
                holder_pub_key = ECC.import_key(pub_key)

                try:
                    dss_verifier = DSS.new(issuer_pub_key, 'fips-186-3')
                    dss_verifier.verify(public_key_hash, cert_element.sign)
                    print('cert_chain done')

                    try:
                        dss_verifier2 = DSS.new(holder_pub_key, 'fips-186-3')
                        dss_verifier2.verify(nonce_hash, sign)
                        print('signature done')
                        return True

                    except:
                        return False

                except:
                        return False

            
