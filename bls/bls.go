package bls

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/kilic/bn254"
)

var Order = bn254.Order

type PointG1 = bn254.PointG1 // 32 * 2 bytes -> signature
type PointG2 = bn254.PointG2 // 32 * 4 bytes -> pubkey

type PublicKey struct {
	point *PointG2
}

type SecretKey [32]byte

type Signature struct {
	point *PointG1
}

type AggregatedKey = PublicKey

type AggregatedSignature = Signature

type KeyPair struct {
	secret *SecretKey
	Public *PublicKey
}

type Message struct {
	Message []byte // tx data
	Domain  []byte // []bytes{}
}

type BLSSigner struct {
	hasher  Hasher
	Account *KeyPair
}

type BLSVerifier struct {
	hasher Hasher
	e      *bn254.Engine
}

func PublicKeyFromBytes(in []byte) (*PublicKey, error) {
	g := bn254.NewG2()
	publicKey, err := g.FromBytes(in)
	if err != nil {
		return nil, err
	}
	return &PublicKey{publicKey}, nil
}

func (p *PublicKey) ToBytes() []byte {
	g := bn254.NewG2()
	return g.ToBytes(p.point)
}

func SignatureKeyFromBytes(in []byte) (*Signature, error) {
	g := bn254.NewG1()
	signature, err := g.FromBytes(in)
	if err != nil {
		return nil, err
	}
	return &Signature{signature}, nil
}

func (p *Signature) ToBytes() []byte {
	g := bn254.NewG1()
	return g.ToBytes(p.point)
}

func NewBLSSigner(hasher Hasher, account *KeyPair) *BLSSigner {
	return &BLSSigner{hasher, account}
}

func NewBLSVerifier(hasher Hasher) *BLSVerifier {
	return &BLSVerifier{hasher, bn254.NewEngine()}
}

func NewKeyPair(r io.Reader) (*KeyPair, error) {
	s, err := rand.Int(r, Order)
	if err != nil {
		return nil, err
	}
	secret := &SecretKey{}
	copy(secret[32-len(s.Bytes()):], s.Bytes()[:])
	g2 := bn254.NewG2()
	public := g2.New()
	g2.MulScalar(public, g2.One(), s)
	return &KeyPair{secret, &PublicKey{public}}, nil
}

func NewKeyPairFromBytes(in []byte) (*KeyPair, error) {
	if len(in) != 128+32 {
		return nil, errors.New("160 byte input is required to recover")
	}
	g2 := bn254.NewG2()
	publicKey, err := g2.FromBytes(in[:128])
	if err != nil {
		return nil, err
	}
	secretKey := &SecretKey{}
	copy(secretKey[:], in[128:])
	return &KeyPair{secretKey, &PublicKey{publicKey}}, nil
}

func (e *KeyPair) ToBytes() []byte {
	out := make([]byte, 128+32)
	copy(out[:128], e.Public.ToBytes())
	copy(out[128:], e.secret[:])
	return out
}

func (signer *BLSSigner) Sign(message *Message) (*Signature, error) {
	g := bn254.NewG1()
	signature, err := signer.hasher.Hash(message)
	if err != nil {
		return nil, err
	}
	g.MulScalar(signature, signature, new(big.Int).SetBytes(signer.Account.secret[:]))
	return &Signature{signature}, nil
}

func (bls *BLSVerifier) AggregatePublicKeys(keys []*PublicKey) *AggregatedKey {
	g := bls.e.G2
	if len(keys) == 0 {
		return &AggregatedKey{g.Zero()}
	}
	aggregated := new(PointG2).Set(keys[0].point)
	for i := 1; i < len(keys); i++ {
		g.Add(aggregated, aggregated, keys[i].point)
	}
	return &AggregatedKey{aggregated}
}

func (bls *BLSVerifier) AggregateSignatures(signatures []*Signature) *AggregatedSignature {
	g := bls.e.G1
	if len(signatures) == 0 {
		return &AggregatedSignature{g.Zero()}
	}
	aggregated := new(PointG1).Set(signatures[0].point)
	for i := 1; i < len(signatures); i++ {
		g.Add(aggregated, aggregated, signatures[i].point)
	}
	return &AggregatedSignature{aggregated}
}

func (bls *BLSVerifier) Verify(message *Message, signature *Signature, publicKey *PublicKey) (bool, error) {
	M, err := bls.hasher.Hash(message)
	if err != nil {
		return false, err
	}
	G2 := bls.e.G2.One()
	bls.e.AddPair(M, publicKey.point)
	bls.e.AddPairInv(signature.point, G2)
	return bls.e.Check(), nil
}

func (bls *BLSVerifier) VerifyAggregateCommon(message *Message, publicKeys []*PublicKey, signature *AggregatedSignature) (bool, error) {
	if len(publicKeys) == 0 {
		return false, errors.New("public key size is zero")
	}
	M, err := bls.hasher.Hash(message)
	if err != nil {
		return false, err
	}
	aggregatedPublicKeys := bls.AggregatePublicKeys(publicKeys)
	G2 := bls.e.G2.One()
	bls.e.AddPair(M, aggregatedPublicKeys.point)
	bls.e.AddPairInv(signature.point, G2)
	return bls.e.Check(), nil
}

func (bls *BLSVerifier) VerifyAggregate(messages []*Message, publicKeys []*PublicKey, signature *AggregatedSignature) (bool, error) {
	if len(publicKeys) == 0 {
		return false, errors.New("public key size is zero")

	}
	if len(messages) != len(publicKeys) {
		return false, errors.New("message and key sizes must be equal")
	}
	G2 := bls.e.G2.One()
	bls.e.AddPairInv(signature.point, G2)

	for i := 0; i < len(messages); i++ {
		M, err := bls.hasher.Hash(messages[i])
		if err != nil {
			return false, err
		}
		bls.e.AddPair(M, publicKeys[i].point)
	}
	return bls.e.Check(), nil
}
