package main

import (
	"encoding/gob"
	"fmt"
	"log"
	"math/big"
	"net"
	. "server/acc"
)

const (
	HOST = "localhost"
	PORT = "50058"
)

// serverReqHandlerV2 代表请求处理程序。
type serverReqHandlerV2 struct {
	conn   net.Conn
	server *ODXTServerV2
}

type message struct {
	Permission string
	Index      int
	FloatField float64
	BoolField  bool
	BigInt     *big.Int // value
	BigInt2    *big.Int // witness
	Addrint    *big.Int
	Val        []byte
	Alpha      *big.Int
	Beta       *big.Int
	Xtag       *big.Int
	UpCnt      int64
	Valueint   *big.Int
	Witint     *big.Int
	Stoken     []*big.Int
	Xtoken     [][]*big.Int
	BetaWit    *big.Int
}

func pow(base, exponent, modulus *big.Int) *big.Int {
	result := new(big.Int).Exp(base, exponent, modulus)
	return result
}

// handle 处理连接的请求。
func (h *serverReqHandlerV2) handle() {
	decoder := gob.NewDecoder(h.conn)
	var respTup message
	err := decoder.Decode(&respTup)
	if err != nil {
		log.Println("Error decoding:", err)
		return
	}
	//打印接收到的数据
	fmt.Printf("Received permission: %s\n", respTup.Permission)
	fmt.Printf("Received big integer: %s\n", respTup.BigInt.String())

	index := respTup.Index
	var data interface{}
	switch index {
	case 0: // for setup
		log.Println("setup started")
		fmt.Printf("Received big integer: %s\n", respTup.BigInt.String())
		p := respTup.BigInt
		h.server.Setup(p)
		data = 1
		log.Println("setup completed")
		encoder := gob.NewEncoder(h.conn)
		err = encoder.Encode(data)
		if err != nil {
			log.Println("Error encoding:", err)
		}
	case 1:
		h.server.Update(respTup.Addrint, respTup.Val, respTup.Alpha, respTup.Beta, respTup.Xtag, respTup.UpCnt)
		data = 1
		log.Println("update completed")
	case 2:
		data = h.server.Search(respTup.Stoken, respTup.Xtoken, respTup.Valueint, respTup.BetaWit)
		log.Println("search completed")
	case 3:
		iden := []*big.Int{}
		iden, _ = h.server.AccAdd(respTup.Permission)
		log.Println("accadd completed")
		encoder := gob.NewEncoder(h.conn)
		err = encoder.Encode(iden)
		if err != nil {
			log.Println("Error encoding:", err)
		}
	case 4:
		perm := respTup.Permission
		value := respTup.BigInt
		h.server.AccRevoke(perm, value)
		var result bool
		log.Println("accrevoke completed")
		encoder := gob.NewEncoder(h.conn)
		err = encoder.Encode(result)
		if err != nil {
			log.Println("Error encoding:", err)
		}
	case 5:
		var result bool
		perm := respTup.Permission
		value := respTup.BigInt
		witness := respTup.BigInt2
		result = h.server.AccCheck(perm, value, witness)
		log.Println("acccheck completed")
		encoder := gob.NewEncoder(h.conn)
		err = encoder.Encode(result)
		if err != nil {
			log.Println("Error encoding:", err)
		}
	}

	log.Println("handled")
}

// ODXTServerV2 代表服务器。
type ODXTServerV2 struct {
	TSet map[string][]*big.Int
	XSet map[string]*big.Int
	p    *big.Int
	acl  *ACL
}

// Setup 初始化服务器。
func (server *ODXTServerV2) Setup(p *big.Int) {
	log.Println("setuping")
	server.TSet = make(map[string][]*big.Int)
	server.XSet = make(map[string]*big.Int)
	server.p = p

}

// Update 处理更新请求。
func (server *ODXTServerV2) Update(addrintx *big.Int, valx []byte, alphax *big.Int, betax *big.Int, xtagx *big.Int, upCntx int64) {
	TSet := server.TSet
	XSet := server.XSet

	addr := addrintx
	val := valx
	alpha := addrintx
	xtag := xtagx
	beta := betax
	a, n := server.acl.GetAn("update")
	fmt.Println("公钥:", n)

	// 使用big.Int的方法进行乘法和取模运算
	mulResult := new(big.Int).Mul(addr, a)
	addrTBigInt := new(big.Int).Mod(mulResult, n)
	// 将大整数转换为字符串作为映射的键
	addrT := addrTBigInt.Text(10)
	valbigint := new(big.Int).SetBytes(val)
	TSet[addrT] = []*big.Int{valbigint, alpha, beta}
	// 将大整数转换为字符串作为映射的键
	xtagStr := xtag.Text(10)

	XSet[xtagStr] = big.NewInt(1)

	server.TSet = TSet
	server.XSet = XSet
}

// Search 处理搜索请求。
func (server *ODXTServerV2) Search(ST []*big.Int, XT [][]*big.Int, VT *big.Int, BT *big.Int) map[int][]*big.Int {
	TSet := server.TSet
	XSet := server.XSet

	stokenlist := ST
	xtokenlists := XT
	value := VT
	betawit := BT

	_, n := server.acl.GetAn("search") // 确保GetAn返回*big.Int类型的值
	length := len(stokenlist)
	sEOpList := make(map[int][]*big.Int)

	for j := 0; j < length; j++ {
		cntI := big.NewInt(1)
		cntJ := big.NewInt(0)
		// 以下几行代码进行了修改，以使用*big.Int类型和对应的方法
		addrT := new(big.Int).Mul(stokenlist[j], pow(betawit, value, n))
		addrT.Mod(addrT, n)
		addrTStr := addrT.Text(10) // 转为字符串作为键
		//判断TSet[addrTStr]是否存在
		svalAlphaBeta := TSet[addrTStr]
		sval := svalAlphaBeta[0]
		alpha := svalAlphaBeta[1] // alpha转为*big.Int
		beta := svalAlphaBeta[2]  // beta转为*big.Int

		for _, xt := range xtokenlists[j] {
			xtokenIj := xt
			xtagIj := pow(xtokenIj, alpha, server.p)
			xtagIjP := pow(xtagIj, beta, server.p)
			xtagIjStr := xtagIj.Text(10)   // 转为字符串作为键
			xtagIjPStr := xtagIjP.Text(10) // 转为字符串作为键
			if _, ok := XSet[xtagIjStr]; ok {
				cntI.Add(cntI, big.NewInt(1))
				if xtagIjPVal, ok := XSet[xtagIjPStr]; ok && XSet[xtagIjStr].Cmp(xtagIjPVal) < 0 {
					cntJ.Add(cntJ, big.NewInt(1))
				}
			}
		}
		//将j转成*big.Int类型
		index := big.NewInt(int64(j))
		sEOpList[j] = []*big.Int{index, sval, cntI, cntJ}
	}
	return sEOpList
}

// AccAdd 处理添加权限请求。
func (server *ODXTServerV2) AccAdd(perm string) ([]*big.Int, []interface{}) {
	iden, aux := server.acl.Add2(perm)
	return iden, aux
}

// AccRevoke 处理撤销权限请求。
func (server *ODXTServerV2) AccRevoke(perm string, value *big.Int) {
	log.Println("revoking permission")
	server.acl.Revoke(perm, value)
}

// AccCheck 处理检查权限请求。
func (server *ODXTServerV2) AccCheck(perm string, value, witness *big.Int) bool {

	return server.acl.CheckPermission(perm, value, witness)
}

func main() {
	listener, err := net.Listen("tcp", HOST+":"+PORT)
	if err != nil {
		log.Fatal("Error listening:", err)
	}
	defer listener.Close()
	log.Printf("Server started on %s:%s\n", HOST, PORT)

	server := &ODXTServerV2{
		TSet: make(map[string][]*big.Int),
		XSet: make(map[string]*big.Int),
		p:    big.NewInt(-1),
		acl:  NewACL(), // 假设NewACL是ACL的构造函数
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting:", err)
			continue
		}
		handler := &serverReqHandlerV2{
			conn:   conn,
			server: server,
		}
		go handler.handle()
	}
}
