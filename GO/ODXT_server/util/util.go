package util

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

const KEYSIZE = 1e8
const MAXBITS = 256

// bytesXOR 对两个字节串进行异或操作，并返回结果。
func BytesXOR(b1, b2 []byte) []byte {
	n1 := new(big.Int).SetBytes(b1)
	n2 := new(big.Int).SetBytes(b2)
	n1.Xor(n1, n2)
	return n1.Bytes()
}

// mulInv 计算a关于模b的乘法逆元，并返回结果。
func MulInv(a, b *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, b)
}

// genKeyF 生成一个长度为bitsize的随机密钥字节串，并基于种子λ进行随机化。
// 注意：Go的随机数生成器不支持设置种子为字节串，因此这里的实现略有不同。
func GenKeyF(λ *big.Int, bitsize int) []byte {
	randBytes := make([]byte, bitsize/8)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic(err)
	}
	return randBytes
}

// prfF 使用密钥Key和消息M计算伪随机函数，并返回结果。
func PrfF(Key, M []byte) []byte {
	hash := sha256.New()
	hash.Write(M)
	Mval := new(big.Int).SetBytes(hash.Sum(nil))

	rval := new(big.Int).SetBytes(Key)
	rval.Xor(rval, Mval)

	return rval.Bytes()
}

// prfFp 使用密钥Key、消息M、质数p和原根g计算伪随机函数，并返回结果。
func PrfFp(Key, M []byte, p, g *big.Int) []byte {
	hash := sha256.New()
	hash.Write(M)
	Mval := new(big.Int).SetBytes(hash.Sum(nil))

	rval := new(big.Int).SetBytes(Key)
	rval.Xor(rval, Mval)
	rval.Mod(rval, p)
	if rval.Cmp(big.NewInt(0)) == 0 {
		rval.Add(rval, big.NewInt(1))
	}

	ex := rval.Mod(rval, p)
	result := new(big.Int).Exp(g, ex, p)

	return result.Bytes()
}

// findPrimeFactors 找到给定数n的所有质因子，并将它们添加到集合s中。
func FindPrimeFactors(s map[uint64]bool, n *big.Int) {
	two := big.NewInt(2)
	// 处理偶数部分
	for n.Bit(0) == 0 {
		s[2] = true
		n.Div(n, two)
	}
	// 处理奇数部分
	for i := big.NewInt(3); i.Cmp(new(big.Int).Sqrt(n)) <= 0; i.Add(i, two) {
		for new(big.Int).Mod(n, i).Cmp(big.NewInt(0)) == 0 {
			s[i.Uint64()] = true
			n.Div(n, i)
		}
	}
	// 如果n是一个大于2的质数
	if n.Cmp(two) == 1 {
		s[n.Uint64()] = true
	}
}

// findPrimitive 找到给定数n的原根，并返回结果。
func FindPrimitive(n *big.Int) *big.Int {
	s := make(map[uint64]bool)
	phi := new(big.Int).Sub(n, big.NewInt(1))
	FindPrimeFactors(s, new(big.Int).Set(phi))

	r := big.NewInt(2)
	one := big.NewInt(1)
	for r.Cmp(phi) <= 0 {
		flag := false
		for a := range s {
			if new(big.Int).Exp(r, new(big.Int).Div(phi, big.NewInt(int64(a))), n).Cmp(one) == 0 {
				flag = true
				break
			}
		}
		if !flag {
			return r
		}
		r.Add(r, one)
	}
	return big.NewInt(-1)
}

// func main() {
// 	// 示例：生成一个密钥
// 	key := genKeyF(big.NewInt(12345), MAXBITS)
// 	println("Generated key:", key)
// }
