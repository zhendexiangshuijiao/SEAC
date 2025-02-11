import pickle
import socket
import random
import sys
from util.ODXTutil import *
import time
import numpy as np

MAXINT = sys.maxsize
HOST = 'localhost'
PORT = 50057
ADDR = (HOST, PORT)

class ODXTClientV2:
    def __init__(self, addr):
        self.sk: tuple = ()
        self.st: dict = None
        self.p: int = -1
        self.g: int = -1
        self.addr = addr
        self.upCnt = 0

    def opConj(self, op):
        if(op == 'add'):
            return 'del'
        if(op == 'del'):
            return 'add'

    def Setup(self, λ):
        # self.p = number.getPrime(16)
        # self.g = findPrimitive(self.p)

        # self.p = 14466107790023157743
        self.p = 69445180235231407255137142482031499329548634082242122837872648805446522657159
        # self.p = 14120496892714447199
        # self.p = 9803877828113247241079792513194491218341545278043756244841606553497839645277744524007466705683349057071449190848792221929552903517949301195746698367877099
        # self.p = 20963

        self.g = 65537

        Kt = gen_key_F(λ)
        Kx = gen_key_F(λ)
        Ky = gen_key_F(λ)
        Kz = gen_key_F(λ)
        UpdateCnt, Tset, XSet = dict(), dict(), dict()
        self.sk, self.st = (Kt, Kx, Ky, Kz), UpdateCnt
        EDB = (Tset, XSet)
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect(self.addr)
        conn.send(pickle.dumps((0, (EDB, self.p))))
        data = pickle.loads(conn.recv(4096))
        # if(data == (1,)):
        #     print("Setup completed")
        conn.close()

    def Update(self, op: str, id_w_tuple):
        #value = int(value)
        #wit = int(wit)
        self.upCnt += 1
        id, w = id_w_tuple
        Kt, Kx, Ky, Kz = self.sk
        if(not w in self.st):
            self.st[w] = 0
        self.st[w] += 1
        w_wc = str(w)+str(self.st[w])
        addr = prf_F(Kt, (w_wc+str(0)).encode())
        addr = int.from_bytes(addr, 'big')
        #print('update原', addr)
        b1 = (str(op)+str(id)).encode()
        b2 = prf_F(Kt, (w_wc+str(1)).encode())
        b3 = (str(self.opConj(op))+str(id)).encode()
        val = bytes_XOR(b1, b2)
        A0 = prf_Fp(Ky, b1, self.p, self.g)
        A = int.from_bytes(A0, 'little')
        A_inv = mul_inv(A, self.p-1)
        A1 = prf_Fp(Ky, b3, self.p, self.g)
        A_p = int.from_bytes(A1, 'little')
        B0 = prf_Fp(Kz, (w_wc).encode(), self.p, self.g)
        B = int.from_bytes(B0, 'little')
        B_inv = mul_inv(B, self.p-1)
        C0 = prf_Fp(Kx, str(w).encode(), self.p, self.g)
        C = int.from_bytes(C0, 'little')
        α = (A*B_inv)
        beta = (A_inv*A_p)
        xtag = pow(self.g, C*A, self.p)
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect(self.addr)
        conn.send(pickle.dumps((1, (addr, val, (α, beta), xtag, self.upCnt))))
        data = pickle.loads(conn.recv(1024))
        # if(data == (1,)):
        #     print("Update completed")
        conn.close()

    def Search(self, q, value, wit):
        value = int(value)
        wit = int(wit)
        n = int(input('public key n:'))
        start_time3 = time.perf_counter()

        time0 = time.perf_counter()
        BETA = random.randint(2, 1024 - 1)
        BETA_1 = mul_inv(BETA, n)
        length = len(q)
        time1 = time.perf_counter()

        Kt, Kx, Ky, Kz = self.sk
        w1_uc = MAXINT
        w1 = ""
        for x in q:
            if x in self.st and self.st[x] < w1_uc:
                w1 = x
                w1_uc = self.st[x]
        stokenlist = []
        xtokenlists = []
        time2 = time.perf_counter()
        if(w1 in self.st):
            for j in range(w1_uc):
                saddr_j = prf_F(
                    Kt, (str(w1)+str(j+1)+str(0)).encode())
                saddr_j = int.from_bytes(saddr_j, 'big')
                saddr_j = (saddr_j * pow(BETA_1, value))
                saddr_j = saddr_j % n
                stokenlist.append(saddr_j)
                xtl = []
                B0 = prf_Fp(
                    Kz, (str(w1)+str(j+1)).encode(), self.p, self.g)
                B = int.from_bytes(B0, 'little')
                for i in range(length):
                    if(q[i] != w1):
                        A0 = prf_Fp(
                            Kx, (str(q[i])).encode(), self.p, self.g)
                        A = int.from_bytes(A0, 'little')
                        xtoken = pow(self.g, A*B, self.p)
                        xtl.append(xtoken)
                random.shuffle(xtl)
                xtokenlists.append(xtl)
        time3 = time.perf_counter()
        res = (stokenlist, xtokenlists, value, BETA * wit)
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect(self.addr)
        conn.send(pickle.dumps((2, res)))

        #
        # SERVER WORK
        #

        resp_tup = pickle.loads(conn.recv(4096))
        sEOpList = resp_tup[0]
        IdList = []
        for l in sEOpList:
            j, sval, cnt_i, cnt_j = l
            X0 = prf_F(Kt, (str(w1)+str(j+1)+str(1)).encode())
            op_id = bytes_XOR(sval, X0)
            op_id = op_id.decode().rstrip('\x00')
            if(op_id[:3] == 'add' and cnt_i == length and cnt_j == 0):
                IdList.append(int(op_id[3:]))
            elif(op_id[:3] == 'del' and cnt_i > 0 and int(op_id[3:]) in IdList):
                IdList.remove(int(op_id[3:]))
        end_time = time.perf_counter()
        print("查询所需时间：", end_time - start_time3, "秒")
        print(list(set(IdList)))
        print(time1-time0)
        print(time2 - time1)
        print(time3 - time2)
        conn.close()
        return list(set(IdList))

    def close_server(self):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect(self.addr)
        conn.send(pickle.dumps(("q",)))
        conn.close()

def check_owner(username,password):
    if username == 'admin' and password == 'admin':
        return True
    else:
        return False

def delegate(perm):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(ADDR)
    conn.send(pickle.dumps((3,(perm))))
    data = pickle.loads(conn.recv(1024))
    value, aux = data
    print("Delegate completed")
    print("your value is",value[0])
    print("your witness is",value[1])
    #print("your sig is",sig)
    conn.close()


def revoke(perm,value):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(ADDR)
    conn.send(pickle.dumps((4,(perm,value))))
    data = pickle.loads(conn.recv(1024))
    if(data == (1,)):
        print("Revoke completed")
    conn.close()

def check(perm, value, witness):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(ADDR)
    conn.send(pickle.dumps((5,( perm, value, witness))))
    data = pickle.loads(conn.recv(1024))
    print(data)
    conn.close()
    return data

if __name__ == "__main__":
    # HOST = sys.argv[1]
    # PORT = int(sys.argv[2])
    # HOST = 'localhost'
    # PORT = 50060
    client_obj = ODXTClientV2((HOST, PORT))
    client_obj.Setup(100)
    # print(client_obj.sk,client_obj.st)


    print('Please input your username and password')
    username = input('username:')
    password = input('password:')
    # 判断是否是管理员
    if check_owner(username, password):
        print('Welcome admin!')
        while (1):
            print('Please input your command')
            command = input('command:1.Delegate 2.Revoke 3.Check 4.Quit 5.Initializtion \n')   #为什么这里Initializtion会搜不到的原因：重启客户端后st会丢失。
            if command == '1':
                # id = input('id:')
                # name = input('name:')
                perm = input('perm:')
                start_time = time.perf_counter()
                delegate(perm)
                end_time = time.perf_counter()
                # print("授权所需时间：",end_time-start_time , "秒")

            elif command == '2':
                # id = input('id:')
                perm = input('perm:')
                value = int(input('value:'))
                revoke(perm, value)
            elif command == '3':
                # id = input('id:')
                perm = input('perm:')
                value = int(input('value:'))
                witness = input('witness:')
                check(perm, value, witness)
            elif command == '4':
                break

            elif command == '5':
                data = np.genfromtxt("enron.txt", dtype='str')  # 将文件中数据加载到data数组里
                print(data)
                for row in data:
                    #id = row[0]
                    #content = row[1]
                    client_obj.Update('add', (str(row[0]), str(row[1])))

            else:
                print('Invalid command')
                continue

    else:
        while (1):

            print('Welcome user!')
            print('Please input your command')
            command = input('command:1.Search 2.Update 3.Quit 4.Initializtion \n')

            if command == '1':
                print('Please input your information')
                # id = input('id:')
                perm = 'search'
                value = input('value:')
                witness = input('witness:')
                # search_list = input('search_list:')
                # search_list = search_list.split(' ')
                # blinded_value, sig = wit(id,name,perm)
                start_time1 = time.perf_counter()

                # if (check(perm, value, witness)):#改
                if (1):
                    start_time2 = time.perf_counter()
                    print("验证所需时间：", start_time2 - start_time1, "秒")
                    print('Permission granted')
                    print('Please input your search list')
                    search_list = input('search_list:')
                    search_list = search_list.split(' ')
                    #start_time3 = time.perf_counter()
                    client_obj.Search(search_list, value, witness)
                    #end_time = time.perf_counter()
                    #print("查询所需时间：", end_time - start_time3, "秒")


                else:
                    print('Permission denied')




            elif command == '2':
                print('Please input your information')
                id = input('id:')
                perm = 'update'
                p = input('you want to:')
                # blinded_value, sig = wit(id, name, perm)
                value = input('value:')
                witness = input('witness:')
                if (check(perm, value, witness)):
                    print('Permission granted')
                    if p == 'add':
                        content = input('you want to add:')
                        start_time = time.perf_counter()
                        client_obj.Update('add', (id, content))
                        end_time = time.perf_counter()
                        print("更新所需时间：", end_time - start_time, "秒")
                    elif p == 'del':
                        content = input('you want to delete:')
                        start_time = time.perf_counter()
                        client_obj.Update('del', (id, content))
                        end_time = time.perf_counter()
                        print("更新所需时间：", end_time - start_time, "秒")
                else:
                    print('Permission denied')
            elif command == '3':
                break

            elif command == '4':
                data = np.genfromtxt("enron.txt", dtype='str')  # 将文件中数据加载到data数组里
                print(data)
                for row in data:
                    # id = row[0]
                    # content = row[1]
                    client_obj.Update('add', (str(row[0]), str(row[1])))

    # client_obj.Update('add', (2, "apple"))
    # client_obj.Update('add', (4, "apple"))
    # client_obj.Update('add', (5, "apple"))
    # client_obj.Update('add', (6, "apple"))
    # client_obj.Update('add', (7, "apple"))
    # client_obj.Update('add', (8, "apple"))
    # client_obj.Update('del', (7, "apple"))
    # # client_obj.Update('add', (7, "apple"))
    # client_obj.Update('add', (120, "test"))
    #
    #
    #
    #
    # client_obj.Update('add', (3, "banana"))
    # client_obj.Update('add', (4, "banana"))
    # client_obj.Update('add', (5, "banana"))
    # client_obj.Update('add', (6, "banana"))
    # client_obj.Update('add', (7, "banana"))
    # client_obj.Update('del', (4, "banana"))
    #
    # client_obj.Update('add', (3, "pincode"))
    # client_obj.Update('add', (4, "pincode"))
    # client_obj.Update('add', (5, "pincode"))
    # client_obj.Update('add', (6, "pincode"))
    # client_obj.Update('add', (7, "pincode"))
    # client_obj.Update('del', (3, "pincode"))
    #
    #
    #
    # print("Search for apple")
    # client_obj.Search(["apple"])
    # print("Search for banana")
    # client_obj.Search(["banana"])
    # print("Search for pincode")
    # client_obj.Search(["pincode"])
    # print("Search for apple and banana")
    # client_obj.Search(["apple", "banana"])
    # print("Search for apple and pincode")
    # client_obj.Search(["apple", "pincode"])
    # print("Search for banana and pincode")
    # client_obj.Search(["banana", "pincode"])
    # print("Search for apple and pincode and banana")
    # client_obj.Search(["apple", "pincode", "banana"])
    # print("Search for test")
    # client_obj.Search(["test"])