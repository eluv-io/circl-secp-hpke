package frost

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
)

type vector struct {
	Config struct {
		MAXSIGNERS uint   `json:"MAX_SIGNERS,string"`
		NUMSIGNERS uint   `json:"NUM_SIGNERS,string"`
		MINSIGNERS uint   `json:"MIN_SIGNERS,string"`
		Name       string `json:"name"`
		Group      string `json:"group"`
		Hash       string `json:"hash"`
	} `json:"config"`
	Inputs struct {
		GroupSecretKey string `json:"group_secret_key"`
		GroupPublicKey string `json:"group_public_key"`
		Message        string `json:"message"`
		Signers        struct {
			Num1 struct {
				SignerShare string `json:"signer_share"`
			} `json:"1"`
			Num2 struct {
				SignerShare string `json:"signer_share"`
			} `json:"2"`
			Num3 struct {
				SignerShare string `json:"signer_share"`
			} `json:"3"`
		} `json:"signers"`
	} `json:"inputs"`
	RoundOneOutputs struct {
		Participants string `json:"participants"`
		Signers      struct {
			Num1 struct {
				HidingNonce            string `json:"hiding_nonce"`
				BindingNonce           string `json:"binding_nonce"`
				HidingNonceCommitment  string `json:"hiding_nonce_commitment"`
				BindingNonceCommitment string `json:"binding_nonce_commitment"`
				BindingFactorInput     string `json:"binding_factor_input"`
				BindingFactor          string `json:"binding_factor"`
			} `json:"1"`
			Num3 struct {
				HidingNonce            string `json:"hiding_nonce"`
				BindingNonce           string `json:"binding_nonce"`
				HidingNonceCommitment  string `json:"hiding_nonce_commitment"`
				BindingNonceCommitment string `json:"binding_nonce_commitment"`
				BindingFactorInput     string `json:"binding_factor_input"`
				BindingFactor          string `json:"binding_factor"`
			} `json:"3"`
		} `json:"signers"`
	} `json:"round_one_outputs"`
	RoundTwoOutputs struct {
		Participants string `json:"participants"`
		Signers      struct {
			Num1 struct {
				SigShare string `json:"sig_share"`
			} `json:"1"`
			Num3 struct {
				SigShare string `json:"sig_share"`
			} `json:"3"`
		} `json:"signers"`
	} `json:"round_two_outputs"`
	FinalOutput struct {
		Sig string `json:"sig"`
	} `json:"final_output"`
}

func fromHex(t *testing.T, s, errMsg string) []byte {
	t.Helper()
	bytes, err := hex.DecodeString(s)
	test.CheckNoErr(t, err, "decoding "+errMsg)

	return bytes
}

func toBytesScalar(t *testing.T, s group.Scalar) []byte {
	t.Helper()
	bytes, err := s.MarshalBinary()
	test.CheckNoErr(t, err, "decoding scalar")

	return bytes
}

func toBytesElt(t *testing.T, e group.Element) []byte {
	t.Helper()
	bytes, err := e.MarshalBinaryCompress()
	test.CheckNoErr(t, err, "decoding element")

	return bytes
}

func toScalar(t *testing.T, g group.Group, s, errMsg string) group.Scalar {
	t.Helper()
	r := g.NewScalar()
	rBytes := fromHex(t, s, errMsg)
	err := r.UnmarshalBinary(rBytes)
	test.CheckNoErr(t, err, errMsg)

	return r
}

func compareBytes(t *testing.T, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		test.ReportError(t, got, want)
	}
}

func (v *vector) test(t *testing.T, suite Suite) {
	privKey := &PrivateKey{suite, toScalar(t, suite.g, v.Inputs.GroupSecretKey, "bad private key"), nil}
	pubKeyGroup := privKey.Public()
	compareBytes(t, toBytesElt(t, pubKeyGroup.key), fromHex(t, v.Inputs.GroupPublicKey, "bad public key"))

	p1 := PeerSigner{suite, 1, toScalar(t, suite.g, v.Inputs.Signers.Num1.SignerShare, "signer share"), nil}
	// p2 := PeerSigner{suite, 2, toScalar(t, suite.g, v.Inputs.Signers.Num2.SignerShare, "signer share"), nil}
	p3 := PeerSigner{suite, 3, toScalar(t, suite.g, v.Inputs.Signers.Num3.SignerShare, "signer share"), nil}

	hn1 := toScalar(t, suite.g, v.RoundOneOutputs.Signers.Num1.HidingNonce, "hiding nonce")
	bn1 := toScalar(t, suite.g, v.RoundOneOutputs.Signers.Num1.BindingNonce, "binding nonce")
	nonce1, commit1, err := p1.commitWithNonce(hn1, bn1)
	test.CheckNoErr(t, err, "failed to commit")

	compareBytes(t, toBytesElt(t, commit1.hiding), fromHex(t, v.RoundOneOutputs.Signers.Num1.HidingNonceCommitment, "hiding nonce commit"))
	compareBytes(t, toBytesElt(t, commit1.binding), fromHex(t, v.RoundOneOutputs.Signers.Num1.BindingNonceCommitment, "binding nonce commit"))

	hn3 := toScalar(t, suite.g, v.RoundOneOutputs.Signers.Num3.HidingNonce, "hiding nonce")
	bn3 := toScalar(t, suite.g, v.RoundOneOutputs.Signers.Num3.BindingNonce, "binding nonce")
	nonce3, commit3, err := p3.commitWithNonce(hn3, bn3)
	test.CheckNoErr(t, err, "failed to commit")

	compareBytes(t, toBytesElt(t, commit3.hiding), fromHex(t, v.RoundOneOutputs.Signers.Num3.HidingNonceCommitment, "hiding nonce commit"))
	compareBytes(t, toBytesElt(t, commit3.binding), fromHex(t, v.RoundOneOutputs.Signers.Num3.BindingNonceCommitment, "binding nonce commit"))

	msg := fromHex(t, v.Inputs.Message, "bad msg")
	commits := []*Commitment{commit1, commit3}
	bindingFactors, err := suite.getBindingFactors(commits, msg)
	test.CheckNoErr(t, err, "failed to get binding factors")

	compareBytes(t, toBytesScalar(t, bindingFactors[0].factor), fromHex(t, v.RoundOneOutputs.Signers.Num1.BindingFactor, "binding factor"))
	compareBytes(t, toBytesScalar(t, bindingFactors[1].factor), fromHex(t, v.RoundOneOutputs.Signers.Num3.BindingFactor, "binding factor"))

	signShares1, err := p1.Sign(msg, pubKeyGroup, nonce1, commits)
	test.CheckNoErr(t, err, "failed to sign share")
	compareBytes(t, toBytesScalar(t, signShares1.share), fromHex(t, v.RoundTwoOutputs.Signers.Num1.SigShare, "sign share"))

	signShares3, err := p3.Sign(msg, pubKeyGroup, nonce3, commits)
	test.CheckNoErr(t, err, "failed to sign share")
	compareBytes(t, toBytesScalar(t, signShares3.share), fromHex(t, v.RoundTwoOutputs.Signers.Num3.SigShare, "sign share"))

	combiner, err := NewCombiner(suite, v.Config.MINSIGNERS-1, v.Config.MAXSIGNERS)
	test.CheckNoErr(t, err, "failed to create combiner")

	signShares := []*SignShare{signShares1, signShares3}
	signature, err := combiner.Sign(msg, commits, signShares)
	test.CheckNoErr(t, err, "failed to create signature")
	compareBytes(t, signature, fromHex(t, v.FinalOutput.Sig, "signature"))

	valid := Verify(suite, pubKeyGroup, msg, signature)
	test.CheckOk(valid == true, "invalid signature", t)
}

func readFile(t *testing.T, fileName string) *vector {
	t.Helper()
	jsonFile, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("File %v can not be opened. Error: %v", fileName, err)
	}
	defer jsonFile.Close()
	input, _ := ioutil.ReadAll(jsonFile)

	var v vector
	err = json.Unmarshal(input, &v)
	if err != nil {
		t.Fatalf("File %v can not be loaded. Error: %v", fileName, err)
	}

	return &v
}

func TestVectors(t *testing.T) {
	// Draft published at https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-frost-07
	// Test vectors at https://github.com/cfrg/draft-irtf-cfrg-frost
	// Version supported: v07
	suite, vector := P256, readFile(t, "testdata/frost_p256_sha256.json")
	t.Run(fmt.Sprintf("%v", suite), func(tt *testing.T) { vector.test(tt, suite) })

	suite, vector = Ristretto255, readFile(t, "testdata/frost_ristretto255_sha512.json")
	t.Run(fmt.Sprintf("%v", suite), func(tt *testing.T) { vector.test(tt, suite) })
}
