/*
	对levelDB进行读取操作需要消除事件前后读写冲突
	对levelDB进行读取操作同一键对值必须一次读取一次写入，多次操作皆为无效操作
*/
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/peer"
)

type attrChaincode interface {
}

type AttrChaincode struct {
}

func (t *AttrChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	return shim.Success([]byte(nil))
}

func (t *AttrChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	// 获取用户意图
	req, args := stub.GetFunctionAndParameters()

	if req == "attrpolicy" { //上传文件信息及加密策略
		return t.attrPolicy(stub, args)
	} else if req == "attruser" { //上传用户信息及证书
		return t.addUser(stub, args)
	} else if req == "addattr" { //属性共享操作上连
		return t.addAttr(stub, args)
	} else if req == "getattr" { //获取用户文件信息
		return t.getAttr(stub, args)
	} else if req == "judgement" { //数据共享信息上链
		return t.judgement(stub, args)
	} else if req == "getrecord" { //获取用户文件信息
		return t.getRecord(stub, args)
	}
	return shim.Error("指定的函数名称错误")
}

func isKeyword(str string) bool {
	if str == "(" || str == ")" || str == "AND" || str == "OR" || str == "and" || str == "or" {
		return true
	}
	return false
}

func parseTokens(_expr string) []string {
	expr := []rune(_expr)
	tokens := make([]string, 0)
	temp := ""
	for i := 0; i < len(expr); i++ {
		if expr[i] == '(' || expr[i] == ')' || expr[i] == ' ' {
			if temp != "" {
				tokens = append(tokens, temp)
				temp = ""
			}
			if expr[i] != ' ' {
				tokens = append(tokens, string(expr[i]))
			}
		} else {
			temp += string(expr[i])
			if isKeyword(temp) {
				tokens = append(tokens, temp)
				temp = ""
			}
		}
	}
	if temp != "" {
		tokens = append(tokens, temp)
	}
	return tokens
}

type TreeNode struct {
	IsOP  bool
	Val   string
	Left  *TreeNode
	Right *TreeNode
}

func priority(op string) int {
	if op == "OR" {
		return 1
	} else if op == "AND" {
		return 2
	}
	return -1
}

func infixToExpressionTree(tokens []string) *TreeNode {
	exprstk := make([]*TreeNode, 0)
	opstk := make([]string, 0)

	for i := 0; i < len(tokens); i++ {
		element := tokens[i]
		if element == "and" {
			element = "AND"
		}
		if element == "or" {
			element = "OR"
		}
		if !isKeyword(element) {
			node := &TreeNode{
				Val: element,
			}
			exprstk = append(exprstk, node)
		} else if element == "(" {
			opstk = append(opstk, element)
		} else if element == ")" {
			for opstk[len(opstk)-1] != "(" {
				nr := exprstk[len(exprstk)-1]
				nl := exprstk[len(exprstk)-2]
				op := opstk[len(opstk)-1]
				node := &TreeNode{
					IsOP:  true,
					Val:   op,
					Left:  nl,
					Right: nr,
				}
				exprstk = exprstk[:len(exprstk)-2]
				opstk = opstk[:len(opstk)-1]
				exprstk = append(exprstk, node)
			}
			opstk = opstk[:len(opstk)-1]
		} else {
			if len(opstk) == 0 || opstk[len(opstk)-1] == "(" || priority(opstk[len(opstk)-1]) < priority(element) {
			} else {
				nr := exprstk[len(exprstk)-1]
				nl := exprstk[len(exprstk)-2]
				op := opstk[len(opstk)-1]
				node := &TreeNode{
					IsOP:  true,
					Val:   op,
					Left:  nl,
					Right: nr,
				}
				exprstk = exprstk[:len(exprstk)-2]
				opstk = opstk[:len(opstk)-1]
				exprstk = append(exprstk, node)
			}
			opstk = append(opstk, element)
		}

	}
	return exprstk[0]
}

var weight map[string]int

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func calc(root *TreeNode) int {
	if !root.IsOP {
		if _,ok := weight[root.Val];!ok{
			return 1
		}
		return weight[root.Val]
	} else if root.Val == "AND" {
		return calc(root.Left) + calc(root.Right)
	} else {
		return min(calc(root.Left), calc(root.Right))
	}
}

func policy_safety_level(policy string)int{
	expr := "(" + policy + ")"
	tokens := parseTokens(expr)
	root := infixToExpressionTree(tokens)
	return calc(root)
}


func main() {
	weight = map[string]int{
		"教务管理": 4,
		"学籍管理": 2,
		"学区管理": 3,
	  	"教材管理": 3,
	 	"铁路管理": 13,
	 	"教学管理": 11,
		"物流管理": 12,
	 	"公交管理": 5,
	 	"税务管理": 15,
	 	"职员": 5,
	 	"主任": 8,
	 	"处长": 10,
	 	"司长": 15,
	 	"部长": 20,
	 	"教育": 2,
	 	"交通": 4,
	 	"税务": 10,
	 	"环保": 1,
	 	"机密等级1": 5,
	 	"机密等级2": 10,
	 	"机密等级3": 15,
	 	"机密等级4": 20,
	}
	err := shim.Start(new(AttrChaincode))
	if err != nil {
		fmt.Printf("starting chaincode go wrong: %s", err)
	}
}
type Attr struct {
	Attr_prov    string            `json:"attr_prov"`   //策略中表示密文哈希，用户中表示证书
	UID          string            `json:"uid"`         //策略中表示密文标识，用户中表示用户标识
	ChannelID    string            `json:"channel_id"`  //链标识
	Attr_array   []string          `json:"attr_array"`  //策略中表示策略集，用户中表示属性集
	Safty_level  int               `json:"safty_level"` //策略中表示安全等级，等级越高安全系数越低
	Time         string            `json:"time"`        //时间戳
	BlockTxId    string            `json:"block_tx_id"` //区块事务号
	Othermessage map[string]string `json:othermessage`  //附加信息
}

type txRecord struct {
	TradeItems  string `json:"tradeitems"`  //数据密文hash
	SrcChain    string `json:"src_chain"`   //源链标识
	TradeSource string `json:"tradesource"` //共享数据 | 属性标识
	Target      string `json:"user"`        //目标用户
	DstChain    string `json:"dst_chain"`   //目标链标识
	ThisTxId    string `json:"this_tx_id"`  //本次事务号
	BlockTxId   string `json:"block_tx_id"` //区块事务号
	Time        string `json:"time"`        //时间戳
	Result      string `json:"result"`      //结果
}

type InfoColSys struct{
	Sys_num       string `json: "sys_num"`     //系统编号
	Timestamp     string `json: "timestamp"`   //时间戳
	State  		  string `json: "state"`       //系统状态
	ChannelID     string `json: "channelID"`   //链标识
}

//写入账本
func putAttr(stub shim.ChaincodeStubInterface, attr Attr) bool {
	b, err := json.Marshal(attr)
	if err != nil {
		return false
	}

	err = stub.PutState(attr.UID, b)
	if err != nil {
		return false
	}
	return true
}

func putRecord(stub shim.ChaincodeStubInterface, record txRecord) bool {
	b, err := json.Marshal(record)
	if err != nil {
		return false
	}

	err = stub.PutState(record.ThisTxId, b)
	if err != nil {
		return false
	}
	return true
}

//读取账本
func getAttr(stub shim.ChaincodeStubInterface, Iden string) (Attr, bool) {
	var attr Attr
	b, err := stub.GetState(Iden)
	if err != nil {
		return attr, false
	}
	if b == nil {
		return attr, false
	}

	err = json.Unmarshal(b, &attr)
	if err != nil {
		return attr, false
	}
	return attr, true
}

func getRecord(stub shim.ChaincodeStubInterface, Iden string) (txRecord, bool) {
	var record txRecord
	b, err := stub.GetState(Iden)
	if err != nil {
		return record, false
	}
	if b == nil {
		return record, false
	}

	err = json.Unmarshal(b, &record)
	if err != nil {
		return record, false
	}
	return record, true
}

//哈希计算
func sha256Str(str string) string {
	hash := sha256.New()
	hash.Write([]byte(str))
	sum := hash.Sum(nil)
	result := hex.EncodeToString(sum)
	return result
}

// 密文及策略记录
// args = {“密文哈希”，“密文标识”，channel_id, 附加信息，时间戳,“策略集”}
func (t *AttrChaincode) attrPolicy(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 3 {
		return shim.Error("error:args missing")
	}

	var pol Attr
	_, exist_bool := getAttr(stub, args[1])
	if exist_bool {
		return shim.Error("error:Privilege already exists")
	}
	//文件信息
	pol.Attr_prov = args[0]
	pol.UID = args[1]
	pol.ChannelID = args[2]
	pol.BlockTxId = stub.GetTxID()
	start_num := 3
	pol.Othermessage = make(map[string]string)
outloop:
	for x := start_num; x < len(args); x++ {
		if args[start_num][:5] == "trace" {
			pol.Othermessage["source"] = args[start_num][5:]
			start_num += 1
		} else if args[start_num][:5] == "&user" {
			pol.Othermessage["user"] = args[start_num][5:]
			start_num += 1
		} else {
			break outloop
		}
	}
	pol.Time = args[start_num]
	start_num += 1
	timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	str_cacu := pol.Attr_prov + pol.UID + pol.ChannelID + timestamp
	pol.Othermessage["txid"] = sha256Str(str_cacu)
	//策略录入
	pol.Attr_array = append(pol.Attr_array, args[start_num])
	//计算策略的安全等级 start
	weight := policy_safety_level(pol.Attr_array[0])
	pol.Safty_level = weight
	// pol.Safty_level = len(pol.Attr_array)
	//计算策略的安全等级 end
	put_bool := putAttr(stub, pol)
	if !put_bool {
		return shim.Error("error: put Policy")
	}
	fmt.Println("%v\n", start_num)
	temp := append([]string{}, args[start_num:]...)
	args = append(args[:start_num], pol.Othermessage["txid"])
	args = append(args, pol.BlockTxId)
	args = append(args, temp...)
	// args = append(args, pol.Othermessage["txid"])
	// args = append(args,pol.BlockTxId)
	bl, _ := json.Marshal(args)
	stub.SetEvent("attrpolicy", bl)
	res, _ := json.Marshal(pol)
	return shim.Success([]byte(res))
}

//添加用户，并设置初始化权限
func (t *AttrChaincode) addUser(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 3 {
		return shim.Error("error: args missing")
	}

	var user Attr
	user.Othermessage = make(map[string]string)
	_, exist_bool := getAttr(stub, args[1])
	if exist_bool {
		return shim.Error("error: user already exists")
	}

	user.Attr_prov = args[0]
	user.UID = args[1]
	user.ChannelID = args[2]
	user.BlockTxId = stub.GetTxID()
	user.Othermessage = make(map[string]string)
	flag := 0
	user.Time = args[3]
	attr_unity_user := args[4]
	attr_group := []string{}
	for i := 0; i < len(attr_unity_user)-7; i++ {
		if attr_unity_user[i:i+7] == " &fgf& " {
			attr_group = append(attr_group, attr_unity_user[flag:i])
			flag = i + 7
		}
	}
	attr_group = append(attr_group, attr_unity_user[flag:len(attr_unity_user)])

	user.Attr_array = attr_group
	sort.Strings(user.Attr_array)

	timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	str_cacu := user.Attr_prov + user.UID + user.ChannelID + timestamp
	tx_id := sha256Str(str_cacu)
	user.Othermessage["txid"] = tx_id
	user.Safty_level = 0
	put_bool := putAttr(stub, user)
	if !put_bool {
		return shim.Error("error:can not put user")
	}
	args = append(args, tx_id)
	args = append(args, user.BlockTxId)
	bl, _ := json.Marshal(args)
	stub.SetEvent("attruser", bl)
	data_bytes, _ := json.Marshal(user)
	return shim.Success([]byte(data_bytes))
}

//用户请求属性：
//args = {“fromUID”, "ToUID", "Attribute"}
func (t *AttrChaincode) addAttr(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	var record txRecord
	record.TradeSource = args[0]
	record.Target = args[1]
	record.TradeItems = args[2]
	record.Time = args[3]
	record.Result = args[4]
	record.BlockTxId = stub.GetTxID()

	timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	str_cacu := record.TradeSource + record.Target + record.TradeItems + timestamp
	tx_id := sha256Str(str_cacu)
	record.ThisTxId = tx_id
	put_bool := putRecord(stub, record)
	if !put_bool {
		return shim.Error("error:can not put record")
	}
	args = append(args, tx_id)
	args = append(args, record.BlockTxId)

	bl, _ := json.Marshal(args)
	stub.SetEvent("addattr", bl)
	byteRes, _ := json.Marshal(record)
	return shim.Success([]byte(byteRes))
}

//args = {hashdata,源链，用户，目标链，文件id，时间戳}
func (t *AttrChaincode) judgement(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	var req txRecord
	req.TradeItems = args[0]
	req.SrcChain = args[1]
	req.Target = args[2]
	req.DstChain = args[3]
	req.TradeSource = args[4]
	req.Time = args[5]
	req.Result = args[6]
	timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	str_cacu := req.TradeItems + req.SrcChain + req.Target + req.DstChain + req.TradeSource + timestamp
	req.ThisTxId = sha256Str(str_cacu)
	req.BlockTxId = stub.GetTxID()
	put_bool := putRecord(stub, req)
	if !put_bool {
		return shim.Error("error:can not put record")
	}
	args = append(args, req.ThisTxId)
	args = append(args, req.BlockTxId)
	bl, _ := json.Marshal(args)
	if req.SrcChain != req.DstChain {
		stub.SetEvent("CrossChannelJudgement", bl)
	} else {
		stub.SetEvent("CrossChannelJudgement", bl)
	}
	bl, _ = json.Marshal(req)
	return shim.Success([]byte(bl))
}

func (t *AttrChaincode) getRecord(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	json_get, _ := stub.GetState(args[0])
	return shim.Success([]byte(json_get))
}

func (t *AttrChaincode) getAttr(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	json_get, _ := stub.GetState(args[0])
	return shim.Success([]byte(json_get))
}

func (t *AttrChaincode) info_col_sys_write(stub shim.ChaincodeStubInterface, args []string) peer.Response{
	if len(args) < 4 {
		return shim.Error("error: args missing")
	}

	var infoColSys InfoColSys
	infoColSys.Sys_num = args[0]
	infoColSys.Timestamp = args[1]
	infoColSys.State = args[2]
	infoColSys.ChannelID = args[3]

	put_bool := putInfoColSys(stub, infoColSys)
	if !put_bool {
		return shim.Error("error:can not put infoColSys")
	}
	data_bytes, _ := json.Marshal(infoColSys)
	return shim.Success([]byte(data_bytes))
}

func (t *AttrChaincode) info_col_sys_read(stub shim.ChaincodeStubInterface, args []string) peer.Response{
	json_get, _ :=stub.GetState(args[0])
	return shim.Success([]byte(json_get))

}
//写入系统状态
func putInfoColSys(stub shim.ChaincodeStubInterface, infoColSys InfoColSys) bool {
	b, err := json.Marshal(infoColSys)
	if err != nil {
		return false
	}

	err = stub.PutState(infoColSys.Sys_num, b)
	if err != nil {
		return false
	}
	return true
}

