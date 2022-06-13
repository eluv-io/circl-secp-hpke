package hpke_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/hpke"
)

func Example() {
	// import "github.com/cloudflare/circl/hpke"
	// import "crypto/rand"

	// HPKE suite is a domain parameter.
	kemID := hpke.KEM_P384_HKDF_SHA384
	kdfID := hpke.KDF_HKDF_SHA384
	aeadID := hpke.AEAD_AES256GCM
	suite := hpke.NewSuite(kemID, kdfID, aeadID)
	info := []byte("public info string, known to both Alice and Bob")

	// Bob prepares to receive messages and announces his public key.
	publicBob, privateBob, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	Bob, err := suite.NewReceiver(privateBob, info)
	if err != nil {
		panic(err)
	}

	// Alice gets Bob's public key.
	Alice, err := suite.NewSender(publicBob, info)
	if err != nil {
		panic(err)
	}
	enc, sealer, err := Alice.Setup(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Alice encrypts some plaintext and sends the ciphertext to Bob.
	ptAlice := []byte("text encrypted to Bob's public key")
	aad := []byte("additional public data")
	ct, err := sealer.Seal(ptAlice, aad)
	if err != nil {
		panic(err)
	}

	// Bob decrypts the ciphertext.
	opener, err := Bob.Setup(enc)
	if err != nil {
		panic(err)
	}
	ptBob, err := opener.Open(ct, aad)
	if err != nil {
		panic(err)
	}

	// Plaintext was sent successfully.
	fmt.Println(bytes.Equal(ptAlice, ptBob))
	// Output: true
}

func TestWorks(t *testing.T) {
	// import "github.com/cloudflare/circl/hpke"
	// import "crypto/rand"

	// HPKE suite is a domain parameter.
	kemID := hpke.KEM_K256_HKDF_SHA256
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AES128GCM
	suite := hpke.NewSuite(kemID, kdfID, aeadID)
	info := []byte("public info string, known to both Alice and Bob")

	// Bob prepares to receive messages and announces his public key.
	publicBob, privateBob, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	Bob, err := suite.NewReceiver(privateBob, info)
	if err != nil {
		t.Fatal(err)
	}

	// Alice gets Bob's public key.
	Alice, err := suite.NewSender(publicBob, info)
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := Alice.Setup(rand.Reader)
	t.Log("encap", hex.EncodeToString(enc))
	if err != nil {
		t.Fatal(err)
	}

	// Alice encrypts some plaintext and sends the ciphertext to Bob.
	ptAlice := []byte("text encrypted to Bob's public key")
	aad := []byte("additional public data")
	ct, err := sealer.Seal(ptAlice, aad)
	t.Log("ct", hex.EncodeToString(ct))
	if err != nil {
		t.Fatal(err)
	}

	// Bob decrypts the ciphertext.
	opener, err := Bob.Setup(enc)
	if err != nil {
		t.Fatal(err)
	}
	ptBob, err := opener.Open(ct, aad)
	if err != nil {
		t.Fatal(err)
	}

	// Plaintext was sent successfully.
	if !bytes.Equal(ptAlice, ptBob) {
		t.Fatalf("Plaintext disagrees")
	}
	skBytes, _ := privateBob.MarshalBinary()
	t.Log("sk", hex.EncodeToString(skBytes))
	t.Fatal()
}
