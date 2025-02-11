package acc

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
)

// isPrime 判断 n 是否为素数。
func isPrime(n *big.Int) bool {
	return n.ProbablyPrime(0)
}

// generateLargePrime 生成一个大素数，不在已有的primeList中。
func generateLargePrime(primeList []*big.Int) *big.Int {
	for {
		// 随机生成一个大奇数
		p, err := rand.Prime(rand.Reader, 1024)
		if err != nil {
			panic(err)
		}
		// 判断是否与已有素数重复
		unique := true
		for _, prime := range primeList {
			if p.Cmp(prime) == 0 {
				unique = false
				break
			}
		}
		if unique {
			primeList = append(primeList, p)
			return p
		}
	}
}

// extendedEuclideanAlgorithm 执行扩展欧几里得算法。
func extendedEuclideanAlgorithm(a, b *big.Int) (*big.Int, *big.Int) {
	var zero = big.NewInt(0)
	var one = big.NewInt(1)

	x, lastX := new(big.Int).Set(zero), new(big.Int).Set(one)
	y, lastY := new(big.Int).Set(one), new(big.Int).Set(zero)
	var quotient, remainder, xTemp, yTemp *big.Int

	for b.Cmp(zero) != 0 {
		quotient = new(big.Int).Div(a, b)
		remainder = new(big.Int).Mod(a, b)

		a.Set(b)
		b.Set(remainder)

		xTemp = new(big.Int).Sub(x, new(big.Int).Mul(quotient, lastX))
		yTemp = new(big.Int).Sub(y, new(big.Int).Mul(quotient, lastY))

		x.Set(lastX)
		lastX.Set(xTemp)

		y.Set(lastY)
		lastY.Set(yTemp)
	}

	return lastX, lastY
}

// Accumulator 结构体代表累加器。
type Accumulator struct {
	Key         *rsa.PrivateKey
	Accumulator *big.Int
	Values      []*big.Int
	G           *big.Int
	PublicKeyN  *big.Int
	PrivateKeyD *big.Int
}

// NewAccumulator 创建一个新的Accumulator实例。
func NewAccumulator() *Accumulator {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err) // 在实际应用中应该返回错误
	}

	acc := &Accumulator{
		Key:         key,
		Accumulator: big.NewInt(27),            // 初始值为3的立方
		Values:      []*big.Int{big.NewInt(3)}, // 初始值列表为3
		G:           big.NewInt(3),
		PublicKeyN:  key.PublicKey.N,
		PrivateKeyD: key.D,
	}

	return acc
}

// Eval 计算累加器的值。
func (acc *Accumulator) Eval(values []*big.Int) *big.Int {
	for _, v := range values {
		acc.Accumulator.Exp(acc.G, v, acc.PublicKeyN)
	}
	return acc.Accumulator
}

// Wit 生成witness。
func (acc *Accumulator) Wit(value *big.Int) *big.Int {
	g := new(big.Int).Set(acc.G)
	for _, v := range acc.Values {
		if v.Cmp(value) != 0 {
			g.Exp(g, v, acc.PublicKeyN)
		}
	}
	return g
}

// Ver 验证成员的witness。
func (acc *Accumulator) Ver(value, witness *big.Int) bool {
	x := new(big.Int).Exp(witness, value, acc.PublicKeyN)
	return x.Cmp(acc.Accumulator) == 0
}

// Add 添加成员。
func (acc *Accumulator) Add(value *big.Int) (*big.Int, []interface{}) {
	witness := new(big.Int).Set(acc.Accumulator)
	acc.Accumulator.Exp(acc.Accumulator, value, acc.PublicKeyN)
	acc.Values = append(acc.Values, value)
	aux := []interface{}{"add", value}
	return witness, aux
}

// Del 删除成员。
func (acc *Accumulator) Del(value *big.Int) []interface{} {
	valueInverse := new(big.Int).ModInverse(value, acc.PrivateKeyD)
	acc.Accumulator.Exp(acc.Accumulator, valueInverse, acc.PublicKeyN)
	// 删除值，这里只是简单示例，实际中需要更复杂的逻辑来确保正确删除
	for i, v := range acc.Values {
		if v.Cmp(value) == 0 {
			acc.Values = append(acc.Values[:i], acc.Values[i+1:]...)
			break
		}
	}
	aux := []interface{}{"del", []interface{}{value, acc.Accumulator}}
	return aux
}

// Upd 更新成员证明。
func (acc *Accumulator) Upd(value *big.Int, aux []interface{}, witness *big.Int) *big.Int {
	action := aux[0].(string)
	if action == "add" {
		addValue := aux[1].(*big.Int)
		witness.Exp(witness, addValue, acc.PublicKeyN)
		return witness
	} else if action == "del" {
		delValue := aux[1].([]interface{})[0].(*big.Int)
		accumulator := aux[1].([]interface{})[1].(*big.Int)
		alpha, beta := extendedEuclideanAlgorithm(value, delValue)
		witness.Exp(witness, beta, acc.PublicKeyN)
		witness.Mul(witness, accumulator.Exp(accumulator, alpha, acc.PublicKeyN))
		return witness
	}
	return nil
}

// GetAn 获取累加器和n的值。
func (acc *Accumulator) GetAn() (*big.Int, *big.Int) {
	return acc.Accumulator, acc.PublicKeyN
}

// ACL 结构体代表访问控制列表。
type ACL struct {
	Accumulators map[string]*Accumulator
	PrimeList    []*big.Int
}

// NewACL 创建一个新的ACL实例。
func NewACL() *ACL {
	return &ACL{
		Accumulators: make(map[string]*Accumulator),
		PrimeList:    []*big.Int{},
	}
}

var globalACL *ACL // 定义全局变量

func init() {
	globalACL = NewACL() // 在init函数中初始化
}

// Add2 添加权限。
func (acl *ACL) Add2(perm string) ([]*big.Int, []interface{}) {
	acc, exists := acl.Accumulators[perm]
	if !exists {
		acc = NewAccumulator()
		acl.Accumulators[perm] = acc
	}
	value := generateLargePrime(acl.PrimeList)
	witness, aux := acc.Add(value)
	return []*big.Int{value, witness}, aux
}

// Revoke 撤销权限。
func (acl *ACL) Revoke(perm string, value *big.Int) []interface{} {
	acc, exists := acl.Accumulators[perm]
	if !exists {
		return nil
	}
	aux := acc.Del(value)
	return aux
}

// Update 更新权限。
func (acl *ACL) Update(perm string, value *big.Int, aux []interface{}, witness *big.Int) *big.Int {
	acc, exists := acl.Accumulators[perm]
	if !exists {
		return nil
	}
	witness = acc.Upd(value, aux, witness)
	return witness
}

// CheckPermission 检查权限。
func (acl *ACL) CheckPermission(perm string, value, witness *big.Int) bool {
	acc, exists := acl.Accumulators[perm]
	if !exists {
		return false
	}
	result := acc.Ver(value, witness)
	return result
}

// GetAn 获取累加器和n的值。
func (acl *ACL) GetAn(perm string) (*big.Int, *big.Int) {
	acc, exists := acl.Accumulators[perm]
	if !exists {
		return nil, nil
	}
	a, n := acc.GetAn()
	return a, n
}

// addUser 通过ACL添加新用户，并返回值和witness。
// func AddUser(this js.Value, p []js.Value) interface{} {
// 	// 假设第一个参数是权限字符串，第二个是用户标识符
// 	// if len(p) != 2 {
// 	// 	return "Invalid number of arguments. Expected 2 arguments."
// 	// }
// 	perm := p[0].String()
// 	userID := p[1].String()

// 	value, aux := globalACL.Add2(perm)

// 	// 创建响应对象
// 	response := map[string]interface{}{
// 		"value":   value[0].String(), // 用户的素数值
// 		"witness": value[1].String(), // 用户的witness
// 		"aux":     aux,               // 附加信息
// 		"userID":  userID,            // 用户标识符
// 	}

// 	// 序列化响应为JSON字符串
// 	jsonResponse, _ := json.Marshal(response)

// 	// 将JSON字符串转换为JavaScript字符串并返回
// 	return js.ValueOf(string(jsonResponse))

// }

// verifyUser 通过ACL验证用户的权限。
// func VerifyUser(this js.Value, p []js.Value) interface{} {
// 	// 假设第一个参数是权限字符串，第二个是用户的素数值，第三个是witness
// 	perm := p[0].String()
// 	value := new(big.Int)
// 	value.SetString(p[1].String(), 10)
// 	witness := new(big.Int)
// 	witness.SetString(p[2].String(), 10)

// 	result := globalACL.CheckPermission(perm, value, witness)

// 	// 返回验证结果
// 	return js.ValueOf(result)
// }

// updateUser 通过ACL更新用户的权限。  全是bug
// func UpdateUser(this js.Value, p []js.Value) interface{} {
// 	// 假设第一个参数是权限字符串，第二个是用户的素数值，第三个是witness
// 	perm := p[0].String()
// 	value := new(big.Int)
// 	value.SetString(p[1].String(), 10)
// 	aux := p[2]
// 	witness := new(big.Int)
// 	witness.SetString(p[3].String(), 10)

// 	witness = globalACL.Update(perm, value, aux, witness)

// 	// 返回更新后的witness
// 	return js.ValueOf(witness.String())
// }

// func main() {
// 	// 注册全局函数
// 	js.Global().Set("AddUser", js.FuncOf(AddUser))
// 	js.Global().Set("VerifyUser", js.FuncOf(VerifyUser))

// 	// 阻塞等待
// 	// <-c
// 	select {}
// }
