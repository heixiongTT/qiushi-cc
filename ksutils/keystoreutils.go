package ksutils

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/pavel-v-chernykh/keystore-go"
)

//ReadKeyStore
func ReadKeyStore(filename string, password []byte) keystore.KeyStore {
	f, err := os.Open(filename)
	defer f.Close()

	if err != nil {
		log.Fatal(err)
	}

	keyStore, err := keystore.Decode(f, password)
	if err != nil {
		log.Fatal(err)
	}
	return keyStore
}

//WriteKeyStore
func WriteKeyStore(keyStore keystore.KeyStore, filename string, password []byte) {
	o, err := os.Create(filename)
	defer o.Close()

	if err != nil {
		log.Fatal(err)
	}

	err = keystore.Encode(o, keyStore, password)

	if err != nil {
		log.Fatal(err)
	}
}

func zeroing(s []byte) {
	for i := 0; i < len(s); i++ {
		s[i] = 0
	}
}

func main() {
	pke, err := ioutil.ReadFile("./privkey.pem")
	if err != nil {
		log.Fatal(err)
	}
	p, _ := pem.Decode(pke)
	if p == nil {
		log.Fatal("Should have at least one pem block")
	}
	if p.Type != "PRIVATE KEY" {
		log.Fatal("Should be a rsa private key")
	}

	keyStore := keystore.KeyStore{
		"alias": &keystore.PrivateKeyEntry{
			Entry: keystore.Entry{
				CreationDate: time.Now(),
			},
			PrivKey: p.Bytes,
		},
	}

	password := []byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}

	defer zeroing(password)
	WriteKeyStore(keyStore, "keystore.jks", password)

	ks := ReadKeyStore("keystore.jks", password)

	entry := ks["alias"]
	privKeyEntry := entry.(*keystore.PrivateKeyEntry)

	key, err := x509.ParsePKCS8PrivateKey(privKeyEntry.PrivKey)

	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%v", key)

}
