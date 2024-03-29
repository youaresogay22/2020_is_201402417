import json
from os.path import join, curdir, abspath
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


def save(cert):
    """
    hw10: 가독성 향상을 위해 임의로 indent 옵션을 추가하였음.
    """
    cert_path = join('week_10', 'cert.json')
    if abspath(curdir).endswith('week_10'):
        cert_path = 'cert.json'
    with open(cert_path, 'w') as f:
        json.dump(cert, f, indent=4)


def load():
    cert_path = join('week_10', 'cert.json')
    if abspath(curdir).endswith('week_10'):
        cert_path = 'cert.json'
    with open(cert_path, 'r') as f:
        return json.load(f)


def sign():
    """
    (cert.json) 인증서에 공개키와 서명을 저장

    Sign: sign( Hash ( student_id | is_success | week ) )

    서명은 bytes 값의 .hex()를 이용해 string으로 저장
    공개키는 .export_key(format='PEM')을 이용해 PEM 형태로 저장
    :return: None
    """
    # TODO:
    json_file = load()
    private_key = ECC.generate(curve='P-256')
    public_key = private_key.public_key()
    signer = DSS.new(private_key, 'fips-186-3')

    hash_string = str(json_file['student_id'])+ json_file['is_success']+ str(json_file['week'])
    hash_val = SHA256.new(hash_string.encode('utf-8'))
    signature = signer.sign(hash_val)
    json_file['sign'] = signature.hex()
    json_file['public_key'] = public_key.export_key(format='PEM')

    save(json_file)

def verify() -> bool:
    """
    (cert.json) 인증서에 저장된 공개키와 서명을 이용해 값을 검증하는 함수

    Sign: sign( Hash ( student_id | is_success | week ) )
    임을 이용해 해시를 생성한 후 서명 검증

    verifier.verify 함수를 이용할 때 true, false가 아닌 exception으로
    검증 여부가 판단되는 점을 주의
    try 문을 이용해 검증 성공 시 true, 실패시 false를 반환
    :return:
    """
    # TODO:
    json_file = load()
    public = ECC.import_key(json_file['public_key'])
    verifier = DSS.new(public, 'fips-186-3')

    hash_string = str(json_file['student_id'])+ json_file['is_success']+ str(json_file['week'])
    hash_val = SHA256.new(hash_string.encode('utf-8'))
    
    try:
        verifier = DSS.new(public, 'fips-186-3')
        verifier.verify(hash_val, bytes.fromhex(json_file['sign']))
        return True
    except:
        return False

if __name__ == '__main__':
    """
    테스트 방법: cert.py 실행
    이후 pytest 실행
    """
    sign()
    # a = load()
    # print(a)

    # 키 생성
    # private_key = ECC.generate(curve='P-256')
    # public = private_key.public_key()
    # 서명
    # signer = DSS.new(private_key, 'fips-186-3')
    # hash_val = SHA256.new('abc'.encode('utf-8'))
    # signature = signer.sign(hash_val)
    # print(signature)
    # 검증
    # verifier = DSS.new(public, 'fips-186-3')
    # verifier.verify(SHA256.new('abc'.encode('utf-8')), bytes.fromhex(a['sign']))
    # 키 및 서명 저장 관련
    # print(public.export_key(format='PEM'))
    # print(signature.hex())
    # print(bytes.fromhex(signature.hex()))
    # 키 가져오기
    # public = ECC.import_key(a['public_key'])
