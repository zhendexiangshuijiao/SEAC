import sys
import socketserver
import pickle
import logging
import acc_acl

HOST = 'localhost'
PORT = 50057

class serverReqHandlerV2(socketserver.BaseRequestHandler):
    def __init__(self, request, addr, server):
        super().__init__(request, addr, server)

    def handle(self):
        resp_tup = pickle.loads(self.request.recv(4096))
        if(resp_tup[0] == 0):  # for setup
            self.server.Setup(resp_tup[1])
            data = (1,)
            logging.debug("setup completed")
        elif(resp_tup[0] == 1):
            self.server.Update(resp_tup[1])
            data = (1,)
            logging.debug("update completed")
        elif(resp_tup[0] == 2):
            data = self.server.Search(resp_tup[1])
            logging.debug("search completed")

        elif (resp_tup[0] == 3):
            data = self.server.AccAdd(resp_tup[1])
            logging.debug("accadd completed")
        elif (resp_tup[0] == 4):
            self.server.AccRevoke(resp_tup[1])
            data = (1,)
            logging.debug("accrevoke completed")
        elif (resp_tup[0] == 5):
            data = self.server.AccCheck(resp_tup[1])
            logging.debug("acccheck completed")

        self.request.sendall(pickle.dumps(data))
        logging.debug('handled')


class ODXTServerV2(socketserver.TCPServer):
    def __init__(self, addr, handler_class=serverReqHandlerV2) -> None:
        self.EDB = None
        self.p = -1
        super().__init__(addr, handler_class)
        self.acl = acc_acl.ACL()

    def Setup(self, res):
        self.EDB, self.p = res

    def Update(self, avax_tup):
        TSet, XSet = self.EDB
        #addr, val, α, xtag, upCnt, value, wit = avax_tup   wit和value没用到，或许可以把验证做在sever上？
        addr, val, α, xtag, upCnt = avax_tup
        a, n = self.acl.getan('update')
        #print('update时的a', a)
        print('公钥:', n)
        addr_t = (addr * a) % n
        TSet[addr_t] = (val, α)
        #print('update时的addr：',addr_t)
        XSet[xtag] = upCnt
        self.EDB = (TSet, XSet)

    def Search(self, tknlists):
        TSet, XSet = self.EDB
        stokenlist = tknlists[0]
        xtokenlists = tknlists[1]
        value = tknlists[2]
        betawit = tknlists[3]
        a, n = self.acl.getan('update')
        #print('search时的a', a)
        length = len(stokenlist)
        sEOpList = []
        for j in range(length):
            cnt_i = 1
            cnt_j = 0
            addr_t = (stokenlist[j] * pow(int(betawit), int(value))) % n
            #print('search时的addr：', addr_t)
            sval, α_beta = TSet[addr_t]
            α, beta = α_beta
            for xt in xtokenlists[j]:
                xtoken_ij = xt
                xtag_ij = pow(xtoken_ij, α, self.p)
                xtag_ij_p = pow(xtag_ij, beta, self.p)
                if(xtag_ij in XSet):
                    cnt_i += 1
                    if(xtag_ij_p in XSet and XSet[xtag_ij] < XSet[xtag_ij_p]):
                        cnt_j += 1
            sEOpList.append((j, sval, cnt_i, cnt_j))
        return (sEOpList,)

    def AccAdd(self, id_name_perm_tuple):
        perm = id_name_perm_tuple
        # print(self.acl.add2(item_id, perm))
        return (self.acl.add2(perm))

        # 权限操作----------撤销用户

    def AccRevoke(self, id_name_perm_tuple):
        perm, value = id_name_perm_tuple
        self.acl.revoke(perm, value)

    def AccCheck(self, id_name_perm_tuple):
        perm, value, witness = id_name_perm_tuple
        return(self.acl.check_permission(perm, int(value), int(witness)))



if __name__ == "__main__":
    # HOST = sys.argv[1]
    # PORT = int(sys.argv[2])
    server = ODXTServerV2((HOST, PORT), serverReqHandlerV2)
    server.serve_forever()
