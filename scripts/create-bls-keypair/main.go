package main

import (
	"fmt"
	"log"

	"github.com/flashbots/go-boost-utils/bls"
)

func main() {
	sk, _, err := bls.GenerateNewKeypair()
	if err != nil {
		log.Fatal(err.Error())
	}

	blsPubkey, err := bls.PublicKeyFromSecretKey(sk)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Printf("secret key: 0x%x\n", bls.SecretKeyToBytes(sk))
	fmt.Printf("public key: 0x%x\n", bls.PublicKeyToBytes(blsPubkey))
}
