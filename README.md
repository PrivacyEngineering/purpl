<p align="center">
	<img src="purpl.png" width=50" />
</p>

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
## JWT generation

For JWT generation use the [purpl-jwt-go-rsa](https://github.com/PrivacyEngineering/purpl-jwt-go-rsa) or [purpl-jwt-go-ecdsa](https://github.com/PrivacyEngineering/purpl-jwt-go-ecdsa) libraries.

## Examples
For a simple example to quickly try out the interceptor, see [purpl-examples](https://github.com/PrivacyEngineering/purpl-examples).
For an example of a more complex use case using Google's Online Boutique microservice demo, see [purpl-pizza-boutique](https://github.com/PrivacyEngineering/purpl-pizza-boutique)