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

    // 署名文字列の取得
    signature := r.Header.Get("Signature")
		fmt.Println("signature: ", signature)

    // 署名対象の受信データ
    body, _ := ioutil.ReadAll(r.Body)

    // 署名の検証
    if err := verifySignature(string(body), publicKeyStr, signature); err != nil {
        fmt.Println("err: ", err)
        fmt.Println("拒否")
        render.JSON(w, http.StatusForbidden, nil)
        return
    } else {
        fmt.Println("承認")
    }
    render.JSON(w, http.StatusOK, nil)
    return
}

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
    if err != nil {
        return err
    }

    pub, err := x509.ParsePKIXPublicKey(keyBytes)
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

    err = rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, hashed, signDataByte)
    if err != nil {
        return err
    }
    return nil
}
