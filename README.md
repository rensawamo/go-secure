
##  Public Key Authentication Patterns with Golang

### First, create a sample public and private key
```sh
cd client  && openssl genrsa 2048 > private.key
$ openssl rsa -pubout < private.key > public.key
```

public.key drag and drop into server folder 

![alt text](image.png)



### Client 
- Private key reading: reads a private key file in PEM format using the readPrivateKey function. This function parses the private key in PKCS#8 format and returns it as crypto.

- Message preparation and signing: The Message structure is used to create the message to be sent and serialize it into JSON format. Then, use the signMessage function to sign the message with the RSA-SHA256 algorithm and generate the signature as a string in Base64 format.

- Sending HTTP request: The signed message is set to the body of the HTTP POST request and sent to the server using the sendRequest function. This function sets the content type and signature in the HTTP header and executes the request.

- Process response from server: Receives the response from the server, reads its content, and outputs it to the log.