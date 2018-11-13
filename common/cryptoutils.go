package common

import (
	"fmt"
	"log"

	rsautils "github.com/thomasks/qiushi-cc/rsautils"
	"github.com/tidwall/gjson"
)

//CryptoDescriptor comments
type CryptoDescriptor struct {
	Level        string   `json:"level"`
	CryptoFields []string `json:"cryptoFields"`
}

//CryptoDataByDescriptor export
func CryptoDataByDescriptor(jsonData string, cds []CryptoDescriptor, pubKey string) (map[string]interface{}, error) {
	rawData, ok := gjson.Parse(jsonData).Value().(map[string]interface{})
	if !ok {
		return rawData, fmt.Errorf("json is invalidate")
	}
	if len(cds) < 1 {
		return rawData, nil
	}
	for _, cd := range cds {
		keys := cd.CryptoFields
		for _, key := range keys {
			rawValue := gjson.Get(jsonData, key).String()
			log.Printf("@@CryptoDataByDescriptor execute begin key is [%s]\nvalue is [%v]\n", key, rawValue)
			encryptValue := rsautils.RSAEncrypt(pubKey, rawValue)

			log.Printf("@@CryptoDataByDescriptor encryptData sucess.[%s]\n", encryptValue)
			rawData[key] = encryptValue
		}
	}
	return rawData, nil
}

//DecryptoDataByDescriptor export
func DecryptoDataByDescriptor(encryptJSONData string, cds []CryptoDescriptor, privKey string) (map[string]interface{}, error) {
	rawData, ok := gjson.Parse(encryptJSONData).Value().(map[string]interface{})
	if !ok {
		return rawData, fmt.Errorf("json is invalidate")
	}
	if len(cds) < 1 {
		return rawData, nil
	}
	for _, cd := range cds {
		keys := cd.CryptoFields
		for _, key := range keys {
			rawValue := gjson.Get(encryptJSONData, key).String()
			log.Printf("@@DecryptoDataByDescriptor execute begin key is [%s]\nvalue is [%v]\n", key, rawValue)
			decryptValue := rsautils.RSADecrypt(privKey, rawValue)

			log.Printf("@@CryptoDataByDescriptor decryptValue sucess.[%s]\n", decryptValue)
			rawData[key] = decryptValue
		}
	}
	for _, cd := range cds {
		keys := cd.CryptoFields
		for _, key := range keys {
			rawData[key] = gjson.Parse(rawData[key].(string)).Value()
		}
	}

	return rawData, nil
}
