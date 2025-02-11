package main

import (
	"bufio"
	. "client/util"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"math/big"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

var MAXINT = big.NewInt(0).Sub(big.NewInt(0).Exp(big.NewInt(2), big.NewInt(63), nil), big.NewInt(1))

type ODXTClientV2 struct {
	sk    [4]*big.Int
	st    map[string]*big.Int
	p     *big.Int
	g     *big.Int
	addr  string
	upCnt int64
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

func NewODXTClientV2(addr string) *ODXTClientV2 {
	return &ODXTClientV2{
		addr: addr,
		st:   make(map[string]*big.Int),
		p:    big.NewInt(-1),
		g:    big.NewInt(-1),
	}
}

func (client *ODXTClientV2) opConj(op string) string {
	if op == "add" {
		return "del"
	}
	if op == "del" {
		return "add"
	}
	return ""
}

// Setup initializes the client with the given λ parameter.
func (client *ODXTClientV2) Setup(λ int) error {
	fmt.Println("Setting up client...")
	s := "69445180235231407255137142482031499329548634082242122837872648805446522657159"
	i, ok := new(big.Int).SetString(s, 10)
	if !ok {
		fmt.Println("Failed to set big integer")
	}
	client.p = i
	client.g = big.NewInt(65537)
	//打印p,g
	fmt.Println("p:", client.p)
	fmt.Println("g:", client.g)
	bitsize := MAXBITS
	// Generate the keys using a placeholder function for gen_key_F.
	Kt := GenKeyF(client.p, bitsize)
	Kx := GenKeyF(client.p, bitsize)
	Ky := GenKeyF(client.p, bitsize)
	Kz := GenKeyF(client.p, bitsize)

	// Since GenKeyF returns a byte slice, we need to convert it to *big.Int
	client.sk[0] = new(big.Int).SetBytes(Kt)
	client.sk[1] = new(big.Int).SetBytes(Kx)
	client.sk[2] = new(big.Int).SetBytes(Ky)
	client.sk[3] = new(big.Int).SetBytes(Kz)
	UpdateCnt := make(map[string]*big.Int)
	client.st = UpdateCnt

	conn, err := net.Dial("tcp", client.addr)
	if err != nil {
		return fmt.Errorf("error connecting to server: %v", err)
	}
	defer conn.Close()

	// Send the data using gob encoder.
	encoder := gob.NewEncoder(conn)
	sendata := message{
		Index:  0,
		BigInt: i,
	}
	err = encoder.Encode(sendata)
	if err != nil {
		return fmt.Errorf("error encoding opcode: %v", err)
	}

	decoder := gob.NewDecoder(conn)
	var data interface{}
	err = decoder.Decode(&data)
	if err != nil {
		return fmt.Errorf("error decoding response: %v", err)
	}

	return nil
}

func (client *ODXTClientV2) Update(op string, idWTuple [2]string, value, wit *big.Int) error {
	valueInt := value

	witInt := wit

	client.upCnt++
	id, w := idWTuple[0], idWTuple[1]
	Kt, Kx, Ky, Kz := client.sk[0], client.sk[1], client.sk[2], client.sk[3]

	// Increment the state counter for w, or set to 0 if not present.
	cnt, ok := client.st[w]
	if !ok {
		cnt = big.NewInt(0)
	}
	cnt = cnt.Add(cnt, big.NewInt(1))
	client.st[w] = cnt

	wWc := w + cnt.String()
	addr := PrfF(Kt.Bytes(), []byte(wWc+"0"))
	addrInt := new(big.Int).SetBytes(addr)
	b1 := []byte(op + id)
	b2 := PrfF(Kt.Bytes(), []byte(wWc+"1"))
	b3 := []byte(client.opConj(op) + id)
	val := BytesXOR(b1, b2)
	A0 := PrfFp(Ky.Bytes(), b1, client.p, client.g)
	A := new(big.Int).SetBytes(A0)
	AInv := MulInv(A, new(big.Int).Sub(client.p, big.NewInt(1)))
	A1 := PrfFp(Ky.Bytes(), b3, client.p, client.g)
	AP := new(big.Int).SetBytes(A1)
	B0 := PrfFp(Kz.Bytes(), []byte(wWc), client.p, client.g)
	B := new(big.Int).SetBytes(B0)
	BInv := MulInv(B, new(big.Int).Sub(client.p, big.NewInt(1)))
	C0 := PrfFp(Kx.Bytes(), []byte(w), client.p, client.g)
	C := new(big.Int).SetBytes(C0)
	// if A == nil || BInv == nil {
	// 	fmt.Println("AInv or AP is nil")
	// }
	alpha := new(big.Int).Mul(A, BInv)
	beta := new(big.Int).Mul(AInv, AP)
	xtag := new(big.Int).Exp(client.g, new(big.Int).Mul(C, A), client.p)

	conn, err := net.Dial("tcp", client.addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	sendata := message{
		Index:    1,
		Addrint:  addrInt,
		Val:      val,
		Alpha:    alpha,
		Beta:     beta,
		Xtag:     xtag,
		UpCnt:    client.upCnt,
		Valueint: valueInt,
		Witint:   witInt,
	}
	encoder := gob.NewEncoder(conn)
	if err := encoder.Encode(sendata); err != nil {
		return err
	}

	decoder := gob.NewDecoder(conn)
	var data interface{}
	if err := decoder.Decode(&data); err != nil {
		return err
	}

	return nil
}

// Search performs a search on the encrypted data.
func (client *ODXTClientV2) Search(q []string, value, wit *big.Int) ([]int, error) {
	valueInt := value
	witInt := wit
	var n *big.Int
	fmt.Print("public key n: ")
	_, err := fmt.Scan(&n)
	if err != nil {
		return nil, err
	}

	BETA, err := rand.Int(rand.Reader, big.NewInt(1023))
	if err != nil {
		return nil, err
	}
	BETA.Add(BETA, big.NewInt(2)) // BETA is now in the range [2, 1024]
	BETA_1 := MulInv(BETA, n)

	length := len(q)
	Kt, Kx, Kz := client.sk[0], client.sk[1], client.sk[3]

	w1UC := MAXINT
	var w1 string
	for _, x := range q {
		if cnt, ok := client.st[x]; ok && cnt.Cmp(w1UC) < 0 {
			w1 = x
			w1UC.Set(cnt)
		}
	}

	stokenList := []*big.Int{}
	xtokenLists := [][]*big.Int{}

	if w1UC.Cmp(MAXINT) != 0 {
		for j := big.NewInt(0); j.Cmp(w1UC) < 0; j.Add(j, big.NewInt(1)) {
			w1j := fmt.Sprintf("%s%d0", w1, j)
			saddrJ := PrfF(Kt.Bytes(), []byte(w1j))
			saddrJInt := new(big.Int).SetBytes(saddrJ)
			saddrJInt.Mul(saddrJInt, new(big.Int).Exp(BETA_1, valueInt, n)).Mod(saddrJInt, n)
			stokenList = append(stokenList, saddrJInt)

			xtl := []*big.Int{}
			w1j = fmt.Sprintf("%s%d", w1, j)
			B0 := PrfFp(Kz.Bytes(), []byte(w1j), client.p, client.g)
			B := new(big.Int).SetBytes(B0)

			for _, xi := range q {
				if xi != w1 {
					A0 := PrfFp(Kx.Bytes(), []byte(xi), client.p, client.g)
					A := new(big.Int).SetBytes(A0)
					xtoken := new(big.Int).Exp(client.g, new(big.Int).Mul(A, B), client.p)
					xtl = append(xtl, xtoken)
				}
			}
			sort.Slice(xtl, func(i, j int) bool { return xtl[i].Cmp(xtl[j]) < 0 }) // Random shuffle is not cryptographically secure; you would need a secure shuffle algorithm.
			xtokenLists = append(xtokenLists, xtl)
		}
	}

	res := message{
		Index:    2,
		Stoken:   stokenList,
		Xtoken:   xtokenLists,
		Valueint: valueInt,
		BetaWit:  new(big.Int).Mul(BETA, witInt),
	}

	conn, err := net.Dial("tcp", client.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	encoder := gob.NewEncoder(conn)
	err = encoder.Encode(res)
	if err != nil {
		return nil, err
	}

	decoder := gob.NewDecoder(conn)
	// var respTup [2]interface{}
	respTup := make(map[int][]*big.Int)

	err = decoder.Decode(&respTup)
	if err != nil {
		return nil, err
	}

	sEOpList := respTup
	idList := make([]int, 0)
	for _, l := range sEOpList {
		j, sval, cntI, cntJ := l[0], l[1], l[2], l[3]
		//将cntI, cntJ转换为int64
		cntIint64 := cntI.Int64()
		cntJint64 := cntJ.Int64()
		X0 := PrfF(Kt.Bytes(), []byte(fmt.Sprintf("%s%d1", w1, j)))
		svalBytes := []byte(fmt.Sprintf("%d", sval))
		opID := BytesXOR(svalBytes, X0)
		opIDStr := string(opID) // Assuming opID is a string without null characters.
		if opIDStr[:3] == "add" && cntIint64 == int64(length) && cntJint64 == 0 {
			id, _ := strconv.Atoi(opIDStr[3:])
			idList = append(idList, id)
		} else if opIDStr[:3] == "del" && cntIint64 > 0 {
			id, _ := strconv.Atoi(opIDStr[3:])
			// Remove id from idList if it exists
			for i, v := range idList {
				if v == id {
					idList = append(idList[:i], idList[i+1:]...)
					break
				}
			}
		}
	}

	fmt.Println(idList)
	return idList, nil
}

const ADDR = "127.0.0.1:50058"

func checkOwner(username, password string) bool {
	return username == "admin" && password == "admin"
}

func delegate(perm string) {
	conn, err := net.Dial("tcp", ADDR)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer conn.Close()

	encoder := gob.NewEncoder(conn)
	sendata := message{
		Index:      3,
		Permission: perm,
	}
	err = encoder.Encode(sendata)
	if err != nil {
		fmt.Println("Error encoding message:", err)
		return
	}

	decoder := gob.NewDecoder(conn)
	data := []*big.Int{}
	err = decoder.Decode(&data)
	if err != nil {
		fmt.Println("Error decoding response:", err)
		return
	}

	fmt.Println("Delegate completed")
	fmt.Printf("your value is %v\n", data[0])
	fmt.Printf("your witness is %v\n", data[1])
}

// revoke sends a revocation request to the server.
func revoke(perm string, value *big.Int) {
	conn, err := net.Dial("tcp", ADDR)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer conn.Close()
	sendata := message{
		Index:      4,
		Permission: perm,
		BigInt:     value,
	}
	encoder := gob.NewEncoder(conn)
	err = encoder.Encode(sendata)
	if err != nil {
		fmt.Println("Error encoding message:", err)
		return
	}
	// err = encoder.Encode([]interface{}{perm, value})
	// if err != nil {
	// 	fmt.Println("Error encoding perm and value:", err)
	// 	return
	// }

	decoder := gob.NewDecoder(conn)
	var result bool
	err = decoder.Decode(&result)
	if err != nil {
		fmt.Println("Error decoding response:", err)
		return
	}
}

// check sends a check request to the server and returns the response.
func check(perm string, value *big.Int, witness *big.Int) interface{} {
	conn, err := net.Dial("tcp", ADDR)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return nil
	}
	defer conn.Close()
	sendata := message{
		Index:      5,
		Permission: perm,
		BigInt:     value,
		BigInt2:    witness,
	}
	encoder := gob.NewEncoder(conn)
	err = encoder.Encode(sendata)
	if err != nil {
		fmt.Println("Error encoding message:", err)
		return nil
	}

	decoder := gob.NewDecoder(conn)
	var result bool
	err = decoder.Decode(&result)
	if err != nil {
		fmt.Println("Error decoding response:", err)
		return nil
	}

	fmt.Println(result)
	return result
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	client_obj := NewODXTClientV2(ADDR)
	client_obj.Setup(100)
	//输入choice
	fmt.Println("Please input your choice")
	fmt.Print("choice:1.Admin 2.User\n")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)
	if choice == "1" {
		fmt.Println("Welcome admin!")
		for {
			fmt.Println("Please input your command")
			fmt.Print("command:1.Delegate 2.Revoke 3.Check 4.Quit\n")

			command, _ := reader.ReadString('\n')
			command = strings.TrimSpace(command)

			switch command {
			case "1":
				fmt.Print("perm: ")
				perm, _ := reader.ReadString('\n')
				perm = strings.TrimSpace(perm)
				delegate(perm)
			case "2":
				fmt.Print("perm: ")
				perm, _ := reader.ReadString('\n')
				perm = strings.TrimSpace(perm)
				fmt.Print("value: ")
				valueStr, _ := reader.ReadString('\n')
				valueStr = strings.TrimSpace(valueStr)
				value := new(big.Int)
				value.SetString(valueStr, 10)
				fmt.Printf("your value is %v\n", value)
				revoke(perm, value)
			case "3":
				fmt.Print("perm: ")
				perm, _ := reader.ReadString('\n')
				perm = strings.TrimSpace(perm)
				fmt.Print("value: ")
				valueStr, _ := reader.ReadString('\n')
				valueStr = strings.TrimSpace(valueStr)
				value := new(big.Int)
				value.SetString(valueStr, 10)
				fmt.Print("witness: ")
				witnessStr, _ := reader.ReadString('\n')
				witnessStr = strings.TrimSpace(witnessStr)
				witness := new(big.Int)
				witness.SetString(witnessStr, 10)
				check(perm, value, witness)
			case "4":
				return
			default:
				fmt.Println("Invalid command")
			}
		}
	} else {
		for {
			fmt.Println("Welcome user!")
			fmt.Println("Please input your command")
			fmt.Print("command:1.Search 2.Update 3.Quit \n")

			command, _ := reader.ReadString('\n')
			command = strings.TrimSpace(command)

			switch command {
			case "1":
				fmt.Println("Please input your information")
				perm := "search"
				fmt.Print("value: ")
				valueStr, _ := reader.ReadString('\n')
				value := new(big.Int)
				value.SetString(strings.TrimSpace(valueStr), 10)

				fmt.Print("witness: ")
				witnessStr, _ := reader.ReadString('\n')
				witness := new(big.Int)
				witness.SetString(strings.TrimSpace(witnessStr), 10)

				if check(perm, value, witness) == true {
					fmt.Println("Permission granted")
					fmt.Println("Please input your search list")
					fmt.Print("search_list: ")
					searchListStr, _ := reader.ReadString('\n')
					searchList := strings.Fields(strings.TrimSpace(searchListStr))
					client_obj.Search(searchList, value, witness)
				} else {
					fmt.Println("Permission denied")
				}
			case "2":
				fmt.Println("Please input your information")
				fmt.Print("id: ")
				idStr, _ := reader.ReadString('\n')

				perm := "update"
				fmt.Print("you want to: ")
				p, _ := reader.ReadString('\n')
				p = strings.TrimSpace(p)

				fmt.Print("value: ")
				valueStr, _ := reader.ReadString('\n')
				value := new(big.Int)
				value.SetString(strings.TrimSpace(valueStr), 10)

				fmt.Print("witness: ")
				witnessStr, _ := reader.ReadString('\n')
				witness := new(big.Int)
				witness.SetString(strings.TrimSpace(witnessStr), 10)

				if check(perm, value, witness) == true {
					fmt.Println("Permission granted")
					var contentStr string
					if p == "add" {
						fmt.Print("you want to add: ")
						contentStr, _ = reader.ReadString('\n')
					} else if p == "del" {
						fmt.Print("you want to delete: ")
						contentStr, _ = reader.ReadString('\n')
					}

					client_obj.Update(p, [2]string{idStr, contentStr}, value, witness)
				} else {
					fmt.Println("Permission denied")
				}
			case "3":
				return
			default:
				fmt.Println("Invalid command")
			}
		}
	}
}
