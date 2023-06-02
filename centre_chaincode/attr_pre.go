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
	} else if req == "getrecord" { //获取共享操作信息
		return t.getRecord(stub, args)
	}else if req == "httpList" { //获取共享操作信息
		return t.httpList(stub, args)
	}else if req == "smtpList" { //获取共享操作信息
		return t.smtpList(stub, args)
	}else if req == "ftpList" { //获取共享操作信息
		return t.ftpList(stub, args)
	}else if req == "info_col_sys_write"{//写入信息系统状态
		return t.info_col_sys_write(stub, args)
	}else if req == "info_col_sys_read"{//读取信息系统状态
		return t.info_col_sys_read(stub, args)
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
	temp := ""
	tokens := make([]string, 0)
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
		"税务": 5,
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

type FTPdata struct{
	FileMD5      string            `json:"datahash"`       //传输文件哈希
	SrcIP        string            `json:"src_ip"`         //源IP地址
	DstIP        string            `json:"dst_ip"`         //目的IP地址
	CltSrcPort   int               `json:"clt_src_port"`   //控制传输源端口
	CtlDstPort   int               `json:"clt_dst_port"`   //控制传输目的端口
	DataSrcPort  int               `json:"data_src_port"`  //数据传输源端口
	DataDstPort  int               `json:"data_dst_port"`  //数据传输目的端口
	FileName     string            `json:"file_name"`      //下载文件名
	FileType     string            `json:"file_type"`      //文件类型
	IsEncryption int               `json:"is_encryption"`  //是否加密:2-加密，1-未加密，0-未知
	DownloadTime string            `json:"download_time"`  //下载时间
	Timestamp    string            `json:"timestamp"`      //采集时间
	UserName     string            `json:"user_name"`      //用户名
	OperateType  int               `json:"operate_time"`   //上传下载行为:1-上传,2-下载
	KeyWord      string            `json:"key_word"`       //命中关键字
	BlockTxId    string            `json:"block_tx_id"`    //区块事务号
	ThisTxId     string            `json:"this_tx_id"`     //本次事务号
	SrcLocation  string            `json:"src_location"`   //源物理位置
	DstLocation  string            `json:"dst_location"`   //目标物理位置
}

type SMTPdata struct{
	FileMD5         string            `json:"datahash"`       //传输文件哈希
	SrcIP           string            `json:"src_ip"`         //源IP地址
	DstIP           string            `json:"dst_ip"`         //目的IP地址
	SrcPort         int               `json:"src_port"`       //传输源端口
	DstPort         int               `json:"dst_port"`       //传输目的端口
	EmailFrom       string            `json:"email_from"`     //邮件发件人
	EmailTo         string            `json:"email_to"`       //邮件收件人
	EmailSubject    string            `json:"email_subject"`  //邮件主题
	EmailMsg        string            `json:"email_msg"`      //邮件内容
	Attachment      string            `json:"attachment"`     //附件名称
	EmailAccessTime string            `json:"email_access_time"`  //邮件还原时间
	EmailSendTime   string            `json:"email_send_time"`    //邮件发送时间
	EmailCC         string            `json:"email_cc"`       //邮件抄送人
	MimeType        string            `json:"mime_type"`      //MIME类型
	MessageId       string            `json:"message_id"`     //邮件ID号
	ReturnPath      string            `json:"return_path"`    //退信地址
	References      string            `json:"references"`     //回复地址
	FileType        string            `json:"file_type"`      //文件类型
	IsEncryption    int               `json:"is_encryption"`  //是否加密:2-加密，1-未加密，0-未知
	Timestamp       string            `json:"timestamp"`      //采集时间
	KeyWord         string            `json:"key_word"`       //命中关键字
	BlockTxId       string            `json:"block_tx_id"`    //区块事务号
	ThisTxId        string            `json:"this_tx_id"`     //本次事务号
	SrcLocation     string            `json:"src_location"`   //源物理位置
	DstLocation     string            `json:"dst_location"`   //目标物理位置
}

type HTTPdata struct{
	deviceID         string            `json:"device_id"`         //设备ID
	FileMD5          string            `json:"datahash"`          //传输文件哈希
	ServreIP         string            `json:"server_ip"`         //HTTP服务器IP地址
	ClientIP         string            `json:"client_ip"`         //客户端IP地址
	ServrePort       int               `json:"server_port"`       //HTTP服务器端口
	ClientPort       int               `json:"client_port"`       //客户端端口
	Host             string            `json:"host"`              //请求地址（请求首部）
	ContentType      string            `json:"content_type"`      //报文主体类型（实体首部）
	ContentEncoding  string            `json:"content_encoding"`  //报文主体编码类型（实体首部）
	FileName         string            `json:"file_name"`         //文件名
	FileType         string            `json:"file_type"`         //文件类型
	IsEncryption     int               `json:"is_encryption"`     //是否加密:2-加密，1-未加密，0-未知
	Timestamp        string            `json:"timestamp"`         //采集时间
	KeyWord          string            `json:"key_word"`          //命中关键字
	BlockTxId        string            `json:"block_tx_id"`       //区块事务号
	ThisTxId         string            `json:"this_tx_id"`        //本次事务号
	SrcLocation      string            `json:"src_location"`      //源物理位置
	DstLocation      string            `json:"dst_location"`      //目标物理位置
}

type Attr struct {
	Attr_prov    string            `json:"attr_prov"`   //策略中表示密文哈希，用户中表示证书
	UID          string            `json:"uid"`         //策略中表示密文标识，用户中表示用户标识
	ChannelID    string            `json:"channel_id"`  //链标识
	Safty_level  int               `json:"safty_level"` //策略中表示安全等级，等级越高，安全系数越低
	Attr_array   []string          `json:"attr_array"`  //策略中表示策略集，用户中表示属性集
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
	pol.Othermessage = make(map[string]string)
	start_num := 3
	if args[start_num][:5] == "trace" {
		pol.Othermessage["source"] = args[start_num][5:]
		start_num = start_num + 1
	} else if args[start_num][:5] == "&user" {
		pol.Othermessage["user"] = args[start_num][5:]
		start_num = start_num + 1
	}
	pol.Time = args[start_num]
	start_num += 1
	pol.Othermessage["txid"] = args[start_num]
	start_num += 1
	pol.BlockTxId = args[start_num]
	start_num += 1
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
	user.Othermessage = make(map[string]string)
	flag := 0
	user.Time = args[3]
	attr_unity_user := args[4]
	user.Othermessage["txid"] = args[5]
	user.BlockTxId = args[6]
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
	user.Safty_level = 0
	put_bool := putAttr(stub, user)
	if !put_bool {
		return shim.Error("error:can not put user")
	}
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
	record.ThisTxId = args[5]
	record.BlockTxId = args[6]

	put_bool := putRecord(stub, record)
	if !put_bool {
		return shim.Error("error:can not put record")
	}

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
	req.ThisTxId = args[7]
	req.BlockTxId = args[8]
	put_bool := putRecord(stub, req)
	if !put_bool {
		return shim.Error("error:can not put record")
	}
	bl, _ := json.Marshal(args)
	stub.SetEvent("CrossChannelJudgement", bl)
	json_get, _ := json.Marshal(req)
	return shim.Success([]byte(json_get))
}

//ftp数据流上链
func (t *AttrChaincode) ftpList(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	var ftp FTPdata
	ftp.FileMD5 = args[0]
	ftp.SrcIP = args[1]
	ftp.DstIP = args[2]
	ftp.CltSrcPort, _ = strconv.Atoi(args[3])
	ftp.CtlDstPort, _ = strconv.Atoi(args[4])
	ftp.DataSrcPort, _ = strconv.Atoi(args[5])
	ftp.DataDstPort, _ = strconv.Atoi(args[6])
	ftp.FileName = args[7]
	ftp.FileType = args[8]
	ftp.IsEncryption, _ = strconv.Atoi(args[9])
	ftp.DownloadTime = args[10]
	ftp.Timestamp = args[11]
	ftp.UserName = args[12]
	ftp.OperateType, _ = strconv.Atoi(args[13])
	ftp.KeyWord = args[14]
	ftp.SrcLocation = args[15]
	ftp.DstLocation = args[16]
	caculateString := ftp.FileName + ftp.FileType  + ftp.UserName +ftp.Timestamp
	ftp.ThisTxId = sha256Str(caculateString)
	ftp.BlockTxId = stub.GetTxID()
	b, err := json.Marshal(ftp)
	if err != nil {
		return shim.Error("marshal error")
	}

	err = stub.PutState(ftp.ThisTxId, b)
	if err != nil {
		return shim.Error("putstate error")
	}
	stub.SetEvent("ftpList", b)
	return shim.Success([]byte(b))
}

//SMTP邮件数据流上链
func (t *AttrChaincode) smtpList(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	var smtp SMTPdata
	smtp.Timestamp = args[0]
	smtp.SrcIP = args[1]
	smtp.DstIP = args[2]
	smtp.SrcPort, _ = strconv.Atoi(args[3])
	smtp.DstPort, _ = strconv.Atoi(args[4])
	smtp.EmailFrom = args[5]
	smtp.EmailTo = args[6]
	smtp.EmailSubject = args[7]
	smtp.EmailMsg = args[8]
	smtp.Attachment = args[9]
	smtp.FileMD5 = args[10]
	smtp.EmailAccessTime = args[11]
	smtp.EmailSendTime = args[12]
	smtp.EmailCC = args[13]
	smtp.MimeType = args[14]
	smtp.MessageId  = args[15]
	smtp.ReturnPath  = args[16]  
	smtp.References  = args[17]
	smtp.FileType = args[18]
	smtp.IsEncryption, _ = strconv.Atoi(args[19])
	smtp.KeyWord = args[20]
	smtp.SrcLocation = args[21]
	smtp.DstLocation = args[22]
	caculateString:= smtp.EmailSubject + smtp.EmailMsg + smtp.EmailAccessTime + smtp.EmailSendTime + smtp.MessageId 
	smtp.ThisTxId = sha256Str(caculateString)
	smtp.BlockTxId = stub.GetTxID()
	b, err := json.Marshal(smtp)
	if err != nil {
		return shim.Error("marshal error")
	}

	err = stub.PutState(smtp.ThisTxId, b)
	if err != nil {
		return shim.Error("putstate error")
	}
	stub.SetEvent("smtpList", b)
	return shim.Success([]byte(b))
	
}

//HTTP数据流上链
func (t *AttrChaincode) httpList(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	var http HTTPdata
	http.Timestamp = args[0]
	http.ServreIP  = args[1]
	http.ClientIP = args[2]
	http.ServrePort, _ = strconv.Atoi(args[3])
	http.ClientPort, _ = strconv.Atoi(args[4])
	http.Host = args[5]
	http.ContentType = args[6]
	http.ContentEncoding = args[7]
	http.FileName = args[8]
	http.FileMD5 = args[9]
	http.FileType = args[10]
	http.IsEncryption, _ = strconv.Atoi(args[11])
	http.KeyWord = args[12]
	http.SrcLocation = args[13]
	http.DstLocation = args[14]
	http.BlockTxId = stub.GetTxID()
	caculateString := http.ContentType + http.ContentEncoding + http.FileName + http.FileType + http.KeyWord + http.Timestamp
	http.ThisTxId = sha256Str(caculateString)
	b, err := json.Marshal(http)
	if err != nil {
		return shim.Error("marshal error")
	}

	err = stub.PutState(http.ThisTxId, b)
	if err != nil {
		return shim.Error("putstate error")
	}
	stub.SetEvent("httpList", b)
	return shim.Success([]byte(b))
}

func (t *AttrChaincode) getRecord(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	json_get, _ := stub.GetState("attr")
	return shim.Success([]byte(json_get))
}

func (t *AttrChaincode) getAttr(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	json_get, _ := stub.GetState(args[0])
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