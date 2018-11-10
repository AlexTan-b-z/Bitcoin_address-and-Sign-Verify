package main

import (
	"fmt"

	"./key"
)

func main() {
	gkey, err := key.MakeNewKey("201811102122ASDFZXsdpuyWQSvjsiqwsQWEo")
	if err != nil {
		fmt.Println(err)
		return
	}
	privKey := gkey.GetPrivKey()
	fmt.Println("My privateKey is :", key.ByteToString(privKey))
	pubKey := gkey.GetPubKey()
	fmt.Println("My publickKey is :", key.ByteToString(pubKey))
	address := gkey.GetAddress()
	fmt.Println("My address is:", address)
	text := []byte("hahahaha~!")
	signature, _ := gkey.Sign(text)
	fmt.Println("Signature is :", signature)
	isSuccess, _ := key.Verify(text, signature, &gkey.PublicKey)
	if isSuccess == true {
		fmt.Println("Verify success")
	}
}
