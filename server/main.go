package main

import (
    "bufio"
    "crypto"
    "crypto/rsa"
    "crypto/x509"
    "encoding/base64"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"

    "github.com/unrolled/render"
)

func main() {
    http.HandleFunc("/authentication", handler)
    http.ListenAndServe("localhost:8080", nil)
}

func handler(w http.ResponseWriter, r *http.Request) {
    render := render.New()

		// read public key
    publicKeyStr, err := readPublicKey("public.key")
    if err != nil {
        log.Fatal(err)
    }

    // get signature
    signature := r.Header.Get("Signature")
		fmt.Println("signature: ", signature)

    // get body
    body, _ := ioutil.ReadAll(r.Body)
		// body:  {"message":"Hello world!!!!!","timestamp":1481610623}
		fmt.Println("body: ", string(body))


    // verify signature
    if err := verifySignature(string(body), publicKeyStr, signature); err != nil {
        fmt.Println("err: ", err)
        fmt.Println("deny")
        render.JSON(w, http.StatusForbidden, nil)
        return
    } else {
        fmt.Println("allow access !!!!")
    }
    render.JSON(w, http.StatusOK, "good job!")
    return
}

// readPublicKey reads the public key from the file
// the public key is generated from the private key
func readPublicKey(filepath string) (string, error) {
    s := ""
    fp, err := os.Open(filepath)
    if err != nil {
        return "", err
    }
    defer fp.Close()
    scanner := bufio.NewScanner(fp)
    for scanner.Scan() {
        text := scanner.Text()
        if text == "-----BEGIN PUBLIC KEY-----" || text == "-----END PUBLIC KEY-----" {
            continue
        }
        s = s + text
    }
    if err := scanner.Err(); err != nil {
        return "", err
    }
    return s, nil
}

func verifySignature(message string, keystr string, signature string) error {
    keyBytes, err := base64.StdEncoding.DecodeString(keystr)
		fmt.Println("keyBytes: ", keyBytes)
    if err != nil {
        return err
    }

    pub, err := x509.ParsePKIXPublicKey(keyBytes)
		fmt.Println("pub: ", pub)
    if err != nil {
        return err
    }

    signDataByte, err := base64.StdEncoding.DecodeString(signature)
    if err != nil {
        return err
    }

    h := crypto.Hash.New(crypto.SHA256)
    h.Write([]byte(message))
    hashed := h.Sum(nil)


		// VerifyPKCS1v15 verifies an RSA PKCS #1 v1.5 signature.
    err = rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, hashed, signDataByte)
    if err != nil {
        return err
    }
    return nil
}
