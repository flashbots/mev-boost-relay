package main

// See also https://github.com/dvush/bls-vanity for creating vanity BLS keys!

import (
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/bls"
)

func main() {
	sk := GenSecretKey()
	// sk := SecretKeyFromHexString("0x")

	// Convert secret key to public key
	blsPubkey, err := bls.PublicKeyFromSecretKey(sk)
	if err != nil {
		log.Fatal(err.Error())
	}

	// Print secret key and public key
	fmt.Printf("secret key: 0x%x\n", bls.SecretKeyToBytes(sk))
	fmt.Printf("public key: 0x%x\n", bls.PublicKeyToBytes(blsPubkey))
}

// GenSecretKey generates a random secret key
func GenSecretKey() *bls.SecretKey {
	sk, _, err := bls.GenerateNewKeypair()
	if err != nil {
		log.Fatal(err.Error())
	}
	return sk
}

// SecretKeyFromHexString converts a hex string to a BLS secret key
func SecretKeyFromHexString(secretKeyHex string) *bls.SecretKey {
	skBytes, err := hexutil.Decode(secretKeyHex)
	if err != nil {
		log.Fatal(err.Error())
	}

	blsSecretKey, err := bls.SecretKeyFromBytes(skBytes[:])
	if err != nil {
		log.Fatal(err.Error())
	}

	return blsSecretKey
}
