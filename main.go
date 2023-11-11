package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/mr-tron/base58"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/ethereum/go-ethereum/crypto"
)

type key struct {
	privateKey    string
	publicKey     string
	addressHex    string
	addressBase58 string
}

func main() {
	f, err := os.OpenFile("keys.csv", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	if err = writer.Write([]string{"private key", "address"}); err != nil {
		log.Fatal(err)
	}

	for {
		k, err := generateKey()
		if err != nil {
			log.Fatal(err)
		}
		if strings.HasPrefix(k.addressBase58, "TTT") {
			if err = writer.Write([]string{k.privateKey, k.addressBase58}); err != nil {
				log.Fatal(err)
			}
			break
		}
	}

	writer.Flush()
}

func generateKey() (*key, error) {
	var k key

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)
	k.privateKey = hexutil.Encode(privateKeyBytes)[2:]
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("error casting public key to ECDSA")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	k.publicKey = hexutil.Encode(publicKeyBytes)[2:]

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	address = "41" + address[2:]
	k.addressHex = address
	addb, _ := hex.DecodeString(address)
	hash1 := s256(s256(addb))
	secret := hash1[:4]
	addb = append(addb, secret...)
	k.addressBase58 = base58.Encode(addb)

	return &k, nil
}

func s256(s []byte) []byte {
	h := sha256.New()
	h.Write(s)
	bs := h.Sum(nil)
	return bs
}
