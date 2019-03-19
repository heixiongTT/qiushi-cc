package main

import (
	"encoding/json"
	"fmt"

	"github.com/thomasks/qiushi-cc/common"

	"log"

	"github.com/go-ini/ini"
	"github.com/thomasks/qiushi-cc/rsautils"
)

var testdata = `{"id":52235,"createTime":1530668028893,"merchant":{"id":1,"name":"上海源意酒店有限公司"},"indicator":{"id":10,"code":"YYRB_YSFJ","name":"夜审房金","level":2,"parentId":9},"demension":{"id":1,"code":"YYRB_Label_5_0","name":"发生代码"},"dataPacket":{"id":135,"filePath":"http://demo1.essintra.ejucloud.cn/fbcstore/1/20180704_093344_3861.xls","up2Chain":false},"beginDate":1517414400000,"endDate":1517500800000,"period":"d","value":"1001.0","indicatorIdAndBeginDate":1517414400010}`

var testcd = `[{"level":"GROUP","cryptoFields":["indicator"]}]`

func main() {
	cfg, err := ini.Load("conf/my.ini")
	if err != nil {
		log.Fatal(err)
	}
	pubPath := cfg.Section("Security").Key("public_key_path").String()
	privPath := cfg.Section("Security").Key("private_key_path").String()
	passwd := cfg.Section("Security").Key("ks_pwd").String()
	partner := cfg.Section("Merchant").Key("partner").String()

	// //读取配置文件
	// //获取公钥路径
	// msg := "helloworld"
	pubKey, _ := rsautils.DumpPublicKeyBase64(pubPath)
	fmt.Println(pubKey)
	fmt.Println("============================================")
	privKey, _ := rsautils.DumpKSBase64(privPath, passwd, partner)
	fmt.Println(privKey)
	fmt.Println("============================================")
	// fmt.Println(pubKey)
	// fmt.Println(privKey)
	// encryptData := rsautils.RSAEncrypt(pubKey, msg)
	// decryptData := rsautils.RSADecrypt(privKey, encryptData)
	// fmt.Println(decryptData)

	// sign := rsautils.RSASignature(privKey, msg)
	// verified := rsautils.RSAVerify(pubKey, msg, sign)
	// fmt.Println(verified)

	var cds []common.CryptoDescriptor
	if err := json.Unmarshal([]byte(testcd), &cds); err != nil {
		fmt.Printf("@@parseMultiSegData CryptoDescriptor mett error [%s]\n.", err.Error())
	}
	encryptDataMap, err := common.CryptoDataByDescriptor(testdata, cds, pubKey)
	if err != nil {
		fmt.Println(err)
	}
	encryptDataBytes, err := json.Marshal(encryptDataMap)
	if err != nil {
		fmt.Println(err)
	}
	encryptData := string(encryptDataBytes)
	fmt.Println(encryptData)
	fmt.Println("============================================")

	decryptDataMap, err := common.DecryptoDataByDescriptor(encryptData, cds, privKey)
	if err != nil {
		fmt.Println(err)
	}
	decryptDataBytes, err := json.Marshal(decryptDataMap)
	if err != nil {
		fmt.Println(err)
	}
	decryptData := string(decryptDataBytes)
	fmt.Println(decryptData)
	fmt.Println("============================================")

}
