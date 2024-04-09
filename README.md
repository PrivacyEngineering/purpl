<p align="center">
	<img src="purpl.png" width=50" />
</p>

This Go module implements a server-side gRPC interceptor designed for purpose-limiting data minimization, ensuring that 
only the necessary data as dictated by a JWT policy is exposed to service consumers. It dynamically modifies the gRPC 
response based on the permissions and data handling rules (allowed, generalized, noised, reduced) specified in the JWT 
claims. This approach enhances privacy by applying differential privacy techniques, generalizing, reducing, or 
suppressing fields as required. The interceptor leverages RSA public keys for JWT validation, ensuring secure and 
trustworthy communication.

# Citation
To cite the [preprint version of the paper](https://arxiv.org/pdf/2404.05598.pdf) to appear in the Proceedings of the 24th International Conference on Web Engineering (ICWE 2024), use the following BibTeX entry:
```
@InProceedings{loechel2024hookin,
      author={Louis Loechel and Siar-Remzi Akbayin and Elias Grünewald and Jannis Kiesel and Inga Strelnikova and Thomas Janke and Frank Pallas},
      editor={Stefanidis, Kostas and Systa, Kari and Matera, Maristella and Heil, Sebastian and Kondylakis, Haridimos and Quintarelli, Elisa},
      title={{Hook-in Privacy Techniques for gRPC-based Microservice Communication}}, 
      year={2024},
      publisher="Springer Nature Switzerland",
      address="Cham",
      note={to appear in the Proceedings of the 24th International Conference on Web Engineering (ICWE 2024)},
      eprint={2404.05598},
      archivePrefix={arXiv},
      primaryClass={cs.CR},
}
```

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
- [**purpl-examples**](https://github.com/PrivacyEngineering/purpl-examples): A simple example to quickly try out the interceptor.

- [**purpl-pizza-boutique**](https://github.com/PrivacyEngineering/purpl-pizza-boutique): A more complex use case using Google's Online Boutique microservice demo.
