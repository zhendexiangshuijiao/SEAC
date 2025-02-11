from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from random import randint
import hashlib
import random
import time


def random_quadratic_residue(n):
    # 计算模 N 的二次剩余的集合
    residues = set()
    for i in range(1, n):
        residue = (i * i) % n
        if residue in residues:
            break
        residues.add(residue)
    # 随机选取一个二次剩余
    residue = random.choice(list(residues))
    # 计算它的平方根
    g = pow(residue, (n + 1) // 4, n)
    return g


def generate_large_prime(prime_list):
    while True:
        # 随机生成一个大奇数
        p = random.randint(2, 100 - 1)#改动过，原1024-1
        if p % 2 == 0:
            p += 1
        # 判断是否为素数
        if is_prime(p):
            # 判断是否与已有素数重复
            if p not in prime_list:
                prime_list.append(p)
                return p


def is_prime(n):
    # 判断 n 是否为素数
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def extended_euclidean_algorithm(x, y):
    # 初始化
    a1, a2, a3 = 1, 0, x
    b1, b2, b3 = 0, 1, y

    # 执行扩展的欧几里得算法
    while b3 != 0:
        q = a3 // b3
        t1, t2, t3 = a1 - q * b1, a2 - q * b2, a3 - q * b3
        a1, a2, a3 = b1, b2, b3
        b1, b2, b3 = t1, t2, t3

    # 返回α和β
    alpha, beta = a1, a2
    return alpha, beta


class Accumulator:

    def __init__(self):

        self.key = RSA.generate(2048)

        self.accumulator = 27  # 初始值为3
        self.values = [3]  # 初始值为3
        self.g = 3
        self.pri_key = self.key.export_key()
        self.p = self.key.p
        self.q = self.key.q
        self.n = (self.p - 1) * (self.q - 1)

    # 累加器计算
    def eval(self, values):
        for i in values:
            self.accumulator = pow(self.g, i, self.key.publickey().n)
        return self.accumulator

    # 生成witness
    def wit(self, value):
        g = self.g
        for i in self.values:
            if i != value:
                g = pow(g, i, self.key.publickey().n)
        return g

    # 成员验证witness
    def ver(self, value, witness):
        x = pow(witness, value, self.key.publickey().n)
        if x == self.accumulator:
            return True
        else:
            return False

    # 成员添加
    def Add(self, value):
        witness = self.accumulator
        self.accumulator = pow(self.accumulator, value, self.key.publickey().n)
        self.values.append(value)
        aux = ('add', value)
        # print(self.accumulator)
        return witness, aux

    def Del(self, value):
        self.accumulator = pow(self.accumulator, pow(value, -1, self.n), self.key.publickey().n)
        self.values.remove(value)
        aux = ('del', (value, self.accumulator))
        # print(self.values)
        return aux


    # 更新成员证明
    def upd(self, value, aux, witness):
        if aux[0] == 'add':
            add_value = aux[1]
            witness = pow(witness, add_value)
            return witness
        elif aux[0] == 'del':
            del_value = aux[1][0]
            accumulator = aux[1][1]
            alpha, beta = extended_euclidean_algorithm(value, del_value)
            witness = pow(witness, beta) * pow(accumulator, alpha)
            return witness

    def get_an(self):
        return self.accumulator, self.key.publickey().n


class ACL:

    def __init__(self):
        self.accumulators = {}
        self.prime_list = []

    def add2(self, perm):
        if perm not in self.accumulators:
            self.accumulators[perm] = Accumulator()
        acc = self.accumulators[perm]
        value = generate_large_prime(self.prime_list)  # 为新用户随机选取大素数
        witness, aux = acc.Add(value)
        # sig = pss.new(acc.key).sign(SHA256.new(str(witness).encode()))
        # print(acc.key)
        # print(witness)

        return (value, witness), aux

    def revoke(self, perm, value):
        if perm not in self.accumulators:
            return
        acc = self.accumulators[perm]
        aux = acc.Del(value)
        # print(self.prime_list)
        return aux

    def check_permission(self, perm, value, witness):
        if perm not in self.accumulators:
            return False
        acc = self.accumulators[perm]
        result = acc.ver(value, witness)
        return result

    def getan(self, perm):
        acc = self.accumulators[perm]
        a, n = acc.get_an()
        return a, n