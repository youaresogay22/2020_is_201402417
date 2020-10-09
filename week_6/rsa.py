
def gcd(a: int, b: int) -> int:
    """
    최대공약수를 구하는 함수
    유클리드 호제법을 이용
    :param a: 최대공약수를 구할 정수 1
    :param b: 최대공약수를 구할 정수 2
    :return: 정수 a와 b의 최대공약수
    """
    while b:
        a, b = b, a % b
    return a


def lcm(a: int, b: int) -> int:
    """
    최소공배수를 구하는 함수
    gcd 값을 이용
    :param a: 최대공약수를 구할 정수 1
    :param b: 최대공약수를 구할 정수 2
    :return: 정수 a와 b의 최소공배수
    """
    # TODO: 이 곳을 채워주세요
    return a*b // gcd(a, b)


def extended_euclidean(a: int, b: int) -> (int, int):
    """
    확장 유클리드 호제법
    ax + by = gcd 를 만족시키는 x, y 값을 계산하는 함수
    :param a: 확장 유클리드 호제법을 만족시키는 정수 1
    :param b: 확장 유클리드 호제법을 만족시키는 정수 2
    :return: 확장 유클리드 호제법에 정수가 주어졌을 때의 x,y값
    """
    x0, y0 = 1, 0
    x1, y1 = 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return x0, y0


def inverse(a: int, mod: int) -> int:
    """
    modular inverse 값
    inverse를 계산할 수 없는 경우 (gcd 값이 1이 아닌 경우) Value Error를 raise 해야 함
    `a mod b = c` 에서 a가 `p * q` 와 같이 곱셈관계일때, 
    어떤 정수 p에 대해 (p * q) ≡ 1 mod n 이 되는 수 q 를 모듈러 역수 또는 역원 이라고 한다.
    :param a: 위의 정의에서 p에 해당
    :param mod: 위의 정의에서 b에 해당
    :return: 위의 정의에서 q에 해당
    """
    # TODO: 이 곳을 채워주세요
    temp_gcd = gcd(a, mod)
    x, y = extended_euclidean(a, mod)

    if temp_gcd != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % mod


class RSAKey:
    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.n = p * q
        self.e = self.public()
        self.d = self.private()

    def public(self, e=2) -> int:
        """
        조건을 만족하는 public key 를 구하는 함수
        e가 totient 함수 값과 서로소여야 함
        :return:
        """
        totient = lcm(self.p-1, self.q-1)
        while gcd(e, totient) != 1:
            e += 1
        return e

    def private(self) -> int:
        """
        public key에 맞는 private key를 계산하는 함수
        totient 함수 값의 mod 연산에 대한 e의 곱셈 역원을 계산
        :return: private key 값
        """
        # TODO: 이 곳을 채워주세요
        '''
        확장 유클리드 호제법 ax+by=gcd에서
        a = public key
        b = totient
        x = private key
        '''
        totient = lcm(self.p-1, self.q-1)
        d,k = extended_euclidean(self.e, totient)

        if d<0  :
            d = totient+d

        return d

    def set_e(self, e: int):
        """
        public key를 설정하는 함수
        :param e: public key
        :return: 없음
        """
        self.e = self.public(e)
        self.d = self.private()
        
    def encrypt(self, m: int):
        """
        공개키로 값을 암호화하는 함수
        개인키로 암호화한 값을 복호화할 수 있음

        암호화 하는 값은 int 값임을 가정
        :param m: 암호화하는 값
        :return:암호화된 값
        """
        # TODO: 이 곳을 채워주세요
        # pow 함수를 이용할 경우 mod n 내에서 제곱 연산을 할 수 있음
      
        return pow(m, self.e, self.n)

    def decrypt(self, m: int):
        """
        개인키로 값을 암호화하는 함수 ( 서명 )
        공개키로 암호화한 값을 복호화할 수 있음
        :param m: 복호화하는 값
        :return: 복호화된 값
        """
        # TODO: 이 곳을 채워주세요
        # pow 함수를 이용할 경우 mod n 내에서 제곱 연산을 할 수 있음
     
        return pow(m, self.d, self.n)