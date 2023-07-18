# purpl: PURPose Limitation 
To use this Go module run:
```shell
go get -u github.com/louisloechel/purpl
```
and add this imprt statement to yout Go file:
``` go  
import (purposelimiter "github.com/louisloechel/purpl")
```

## Usage

The interceptor is called when starting a grpc Server & takes the path to the public key as an argument. 

The public key is used to verify the signature of the token. 

The token is expected to be a JWT in the metadata of the grpc request. 
```go
// path to public key
keyPath := "server/key.pem"

s := grpc.NewServer(
		grpc.UnaryInterceptor(purposelimiter.UnaryServerInterceptor(keyPath)), 
)
```