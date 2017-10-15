package torOnion

import (
	"testing"
	ma "github.com/multiformats/go-multiaddr"
	"crypto/rsa"
	"github.com/yawning/bulb/utils/pkcs1"
	"os"
	"encoding/pem"
	"crypto/rand"
	"path"
)

var key string

func TestMain(m *testing.M) {
	setup()
	retCode := m.Run()
	teardown()
	os.Exit(retCode)
}

func setup() {
	key, _ = createHiddenServiceKey()
}

func teardown() {
	os.RemoveAll(path.Join("./", key + ".onion_key"))
}

func TestIsValidOnionMultiAddr(t *testing.T) {
	// Test valid
	validAddr, err := ma.NewMultiaddr("/onion/erhkddypoy6qml6h:4003")
	if err != nil {
		t.Fatal(err)
	}
	valid := IsValidOnionMultiAddr(validAddr)
	if !valid {
		t.Fatal("IsValidMultiAddr failed")
	}

	// Test wrong protocol
	invalidAddr, err := ma.NewMultiaddr("/ip4/0.0.0.0/tcp/4001")
	if err != nil {
		t.Fatal(err)
	}
	valid = IsValidOnionMultiAddr(invalidAddr)
	if valid {
		t.Fatal("IsValidMultiAddr failed")
	}
}

func createHiddenServiceKey() (string, error){
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return "", err
	}
	id, err := pkcs1.OnionAddr(&priv.PublicKey)
	if err != nil {
		return "", err
	}

	f, err := os.Create(id+".onion_key")
	if err != nil {
		return "", err
	}
	defer f.Close()

	privKeyBytes, err := pkcs1.EncodePrivateKeyDER(priv)
	if err != nil {
		return "", err
	}

	block := pem.Block{Type: "RSA PRIVATE KEY", Bytes: privKeyBytes}
	err = pem.Encode(f, &block)
	if err != nil {
		return "", err
	}
	return id, nil
}
