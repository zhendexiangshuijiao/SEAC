from math import sqrt, gcd
def mul_inv(a, b):#计算a关于模b的乘法逆元，并返回结果。
    if(gcd(a, b) > 1):
        a = a % b
    b0 = b
    x0, x1 = 0, 1
    if b == 1:
        return 1
    while a > 1 and b != 0:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += b0
    return x1
#a = pow(116,44,161)
#print(a)
#print(mul_inv(11,161))

def bytes_XOR(b1: bytes, b2: bytes):#对两个字节串进行异或操作，并返回结果。
    return (int.from_bytes(b1, 'little') ^ int.from_bytes(b2, 'little')).to_bytes(32, 'little')

a = 'hello'.encode()
b = 'world'.encode()
print(bytes_XOR(a,b))