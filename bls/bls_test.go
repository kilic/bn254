package bls

import (
	"crypto/rand"
	"testing"

	"github.com/kilic/bn254"
)

func TestVerify(t *testing.T) {
	message := &Message{
		message: []byte{0x10, 0x11, 0x12, 0x13},
		domain:  []byte{0x00, 0x00, 0x00, 0x00},
	}
	secret, err := RandSecretKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := secret.public
	hasher := &HasherSHA256{}
	signer := NewBLSSigner(hasher)
	signature, err := signer.Sign(message, secret)
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewBLSVerifier(hasher)
	verified, err := verifier.Verify(message, signature, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatalf("signature is not verified")
	}
	message2 := &Message{
		message: []byte{0x10, 0x11, 0x12, 0x13},
		domain:  []byte{0x00, 0x00, 0x00, 0x01},
	}
	verified, err = verifier.Verify(message2, signature, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if verified {
		t.Fatalf("signature is verified with broken message")
	}
}

func TestVerifyAggregatedCommon(t *testing.T) {
	hasher := &HasherSHA256{}
	message := &Message{
		message: []byte{0x10, 0x11, 0x12, 0x13},
		domain:  []byte{0x00, 0x00, 0x00, 0x00},
	}
	signerSize := 1000
	publicKeys := make([]*PublicKey, signerSize)
	signatures := make([]*Signature, signerSize)
	for i := 0; i < signerSize; i++ {
		secret, err := RandSecretKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer := NewBLSSigner(hasher)
		publicKeys[i] = secret.public
		signature, err := signer.Sign(message, secret)
		if err != nil {
			t.Fatal(err)
		}
		signatures[i] = signature
	}
	verifier := NewBLSVerifier(hasher)
	aggregatedSignature := verifier.AggregateSignatures(signatures)
	verified, err := verifier.VerifyAggregateCommon(message, publicKeys, aggregatedSignature)
	if err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatalf("signature is not verified")
	}
	secret, err := RandSecretKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKeys[signerSize-1] = secret.public
	verified, err = verifier.VerifyAggregateCommon(message, publicKeys, aggregatedSignature)
	if err != nil {
		t.Fatal(err)
	}
	if verified {
		t.Fatalf("signature is verified with unrelated pubkey")
	}
}

func TestVerifyAggregated(t *testing.T) {
	hasher := &HasherSHA256{}
	domain := []byte{0x00, 0x00, 0x00, 0x00}
	signerSize := 1000
	publicKeys := make([]*PublicKey, signerSize)
	messages := make([]*Message, signerSize)
	signatures := make([]*Signature, signerSize)
	for i := 0; i < signerSize; i++ {
		text := make([]byte, 4)
		_, err := rand.Read(text)
		if err != nil {
			t.Fatal(err)
		}
		message := &Message{
			message: text,
			domain:  domain,
		}
		secret, err := RandSecretKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer := NewBLSSigner(hasher)

		signature, err := signer.Sign(message, secret)
		if err != nil {
			t.Fatal(err)
		}
		messages[i] = message
		publicKeys[i] = secret.public
		signatures[i] = signature
	}
	verifier := NewBLSVerifier(hasher)
	aggregatedSignature := verifier.AggregateSignatures(signatures)
	verified, err := verifier.VerifyAggregate(messages, publicKeys, aggregatedSignature)
	if err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatalf("signature is not verified")
	}
}

func BenchmarkVerifyAggregated24ByteMsgSHA256(t *testing.B) {
	hasher := &HasherSHA256{mapper: bn254.NewG1()}
	domain := []byte{0x00, 0x00, 0x00, 0x00}
	signerSize := 1000
	publicKeys := make([]*PublicKey, signerSize)
	messages := make([]*Message, signerSize)
	signatures := make([]*Signature, signerSize)
	for i := 0; i < signerSize; i++ {
		text := make([]byte, 20)
		_, err := rand.Read(text)
		if err != nil {
			t.Fatal(err)
		}
		message := &Message{
			message: text,
			domain:  domain,
		}
		secret, err := RandSecretKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer := NewBLSSigner(hasher)

		signature, err := signer.Sign(message, secret)
		if err != nil {
			t.Fatal(err)
		}
		messages[i] = message
		publicKeys[i] = secret.public
		signatures[i] = signature
	}
	verifier := NewBLSVerifier(hasher)
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		aggregatedSignature := verifier.AggregateSignatures(signatures)
		_, _ = verifier.VerifyAggregate(messages, publicKeys, aggregatedSignature)
	}
}

func BenchmarkVerifyAggregated24ByteMsgKeccak256(t *testing.B) {
	hasher := &HasherKeccak256{mapper: bn254.NewG1()}
	domain := []byte{0x00, 0x00, 0x00, 0x00}
	signerSize := 1000
	publicKeys := make([]*PublicKey, signerSize)
	messages := make([]*Message, signerSize)
	signatures := make([]*Signature, signerSize)
	for i := 0; i < signerSize; i++ {
		text := make([]byte, 20)
		_, err := rand.Read(text)
		if err != nil {
			t.Fatal(err)
		}
		message := &Message{
			message: text,
			domain:  domain,
		}
		secret, err := RandSecretKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer := NewBLSSigner(hasher)

		signature, err := signer.Sign(message, secret)
		if err != nil {
			t.Fatal(err)
		}
		messages[i] = message
		publicKeys[i] = secret.public
		signatures[i] = signature
	}
	verifier := NewBLSVerifier(hasher)
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		aggregatedSignature := verifier.AggregateSignatures(signatures)
		_, _ = verifier.VerifyAggregate(messages, publicKeys, aggregatedSignature)
	}
}
