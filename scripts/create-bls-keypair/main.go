package main

import (
	"fmt"
	"log"

	"github.com/flashbots/go-boost-utils/bls"
)

func main() {
	sk, pk, err := bls.GenerateNewKeypair()
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Printf("secret key: 0x%x\n", bls.SecretKeyToBytes(sk))
	fmt.Printf("public key: 0x%x\n", bls.PublicKeyToBytes(pk))
}
