package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

// Struct for the JSON payload
type Message struct {
    Message   string `json:"message"`
    Timestamp int64  `json:"timestamp"`
}

func main() {
    // Load the private key
    privateKey, err := readPrivateKey("private.key")
    if err != nil {
        log.Fatalf("Error read private key: %v", err)
    }

    // Prepare the message
    msg := Message{
        Message:   "Hello world!!!!!",
        Timestamp: 1481610623,
    }
    msgBytes, err := json.Marshal(msg)
		fmt.Println("msgBytes: ", string(msgBytes))
    if err != nil {
        log.Fatalf("Error marshaling message: %v", err)
    }

    // Sign the message
    signature, err := signMessage(msgBytes, privateKey)
    if err != nil {
        log.Fatalf("Error signing message: %v", err)
    }

    // Send the request
    sendRequest(msgBytes, signature)
}

// Public key encryption algorithms, digital signature algorithms, key exchange algorithms, symmetric encryption algorithms,
//  message digest algorithms, MAC algorithms, and methods for constructing and parsing ASN.1 objects are supported.
func readPrivateKey(path string) (crypto.PrivateKey, error) {
	keyFile, err := os.ReadFile(path)
	if err != nil {
			return nil, err
	}
	block, _ := pem.Decode(keyFile)
	fmt.Println("block: ", block)

	if block == nil {
			return nil, fmt.Errorf("no PEM data found in file")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	fmt.Println("privateKey: ", privateKey)
	if err != nil {
			return nil, err
	}
	return privateKey, nil
}


func signMessage(message []byte, privateKey crypto.PrivateKey) (string, error) {
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
			return "", fmt.Errorf("key is not RSA private key")
	}
	hasher := sha256.New()
	hasher.Write(message)
	hashed := hasher.Sum(nil)
	// Calculate hashed signatures
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hashed)
	if err != nil {
			return "", err
	}
	fmt.Println("signature: ", signature)
	fmt.Println("signature: ", base64.StdEncoding.EncodeToString(signature))
	return base64.StdEncoding.EncodeToString(signature), nil
}


func sendRequest(message []byte, signature string) {
    client := &http.Client{}
    req, err := http.NewRequest("POST", "http://localhost:8080/authentication", bytes.NewBuffer(message))
    if err != nil {
        log.Fatalf("Error creating request: %v", err)
    }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Signature", signature)

		// Send the request and read the response
    resp, err := client.Do(req)
    if err != nil {
        log.Fatalf("Error sending request: %v", err)
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Fatalf("Error reading response: %v", err)
    }
    log.Printf("Response: %s", body)
}
