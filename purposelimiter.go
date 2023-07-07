// This file contains the interceptor function that is used to
// perform purpose limiting data minimization operations within
// a servide-side gRPC response interceptor.
//
//
// The interceptor function is called by the gRPC server like this:
// path to the JWT's public key file is passed as a parameter keyPath
// grpc.UnaryInterceptor(purposelimiter.UnaryServerInterceptor(keyPath))

package purposelimiter

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt"

	"github.com/google/differential-privacy/go/dpagg"
	"github.com/google/differential-privacy/go/noise"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// CustomClaims is our custom metadata
type CustomClaims struct {
	Policy struct {
		Allowed     map[string]string `json:"allowed"`
		Generalized map[string]string `json:"generalized"`
		Noised      map[string]string `json:"noised"`
		Reduced     map[string]string `json:"reduced"`
	} `json:"policy"`

	jwt.StandardClaims
}

func UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return interceptor
}

func interceptor(keyPath string) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {

		h, err := handler(ctx, req)
		if err != nil {
			return nil, err
		}

		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if token := md.Get("authorization"); len(token) > 0 {
				// assuming the public key is in a file called 'key.pem' in the same directory
				publicKey, err := loadPublicKey(keyPath)
				if err != nil {
					return nil, err
				}

				tkn, err := jwt.ParseWithClaims(token[0], &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
					// validate signing algorithm
					if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return publicKey, nil
				})

				// ----------------------
				// !	Validation		!
				// ----------------------

				if err != nil {
					return nil, err
				}

				if !tkn.Valid {
					return nil, fmt.Errorf("invalid token")
				}

				claims, ok := tkn.Claims.(*CustomClaims)

				if claims, ok := tkn.Claims.(jwt.MapClaims); ok {
					if claims.Valid() != nil {
						return nil, fmt.Errorf("token is expired")
					}
				}
				// ----------------------
				// !	Validation		!
				// ----------------------

				// Check if the response is a proto.Message
				msg, ok := h.(proto.Message)
				if !ok {
					return nil, fmt.Errorf("response is not a proto.Message")
				}

				// Invoke ProtoReflect() to get a protoreflect.Message
				reflectedMsg := msg.ProtoReflect()

				// Declare a slice to store field names
				var fieldNames []string

				reflectedMsg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
					// name, err := getLastPart(string(fd.FullName()))
					//name := reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(string(fd.FullName()))).TextName()
					name := fd.TextName()
					// fmt.Println("Name: ", name)

					fieldNames = append(fieldNames, name)
					// fmt.Printf("Appending field: %s\tValue: %v\n", &name, v)

					return true
				})

				// Iterate over the fields of the message
				for _, field := range fieldNames {
					// Check if the field is not in the allowed list
					// --> Pass if the field is allowed
					if !contains(claims.Policy.Allowed, field) {
						// Check if the field is in one of the minimized lists
						if contains(claims.Policy.Generalized, field) {
							// Generalize the field
							switch reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field)).Kind() {
							case protoreflect.Int32Kind:
								// reflectedMsg.Set(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field)), protoreflect.ValueOf(generalizeInt(reflectedMsg.Get(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field))).Int())))
								fmt.Print("Parameter: ", claims.Policy.Generalized[field][1])
								reflectedMsg.Set(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field)), protoreflect.ValueOf(generalizeIntParam(reflectedMsg.Get(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field))).Int(), claims.Policy.Generalized[field][1])))
							case protoreflect.StringKind:
								reflectedMsg.Set(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field)), protoreflect.ValueOf(generalizeStringParam(reflectedMsg.Get(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field))).String(), claims.Policy.Generalized[field][1])))
							}
						} else if contains(claims.Policy.Noised, field) {
							// Noise the field
							switch reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field)).Kind() {
							case protoreflect.Int32Kind:
								reflectedMsg.Set(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field)), protoreflect.ValueOf(noiseIntParam(reflectedMsg.Get(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field))).Int(), claims.Policy.Noised[field][1])))
							case protoreflect.StringKind:
								reflectedMsg.Set(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field)), protoreflect.ValueOf(noiseStringParam(reflectedMsg.Get(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field))).String(), claims.Policy.Noised[field][1])))
							}
						} else if contains(claims.Policy.Reduced, field) {
							// Reduce the field
							switch reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field)).Kind() {
							case protoreflect.Int32Kind:
								reflectedMsg.Set(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field)), protoreflect.ValueOf(reduceIntParam(reflectedMsg.Get(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field))).Int(), claims.Policy.Reduced[field][1])))
							case protoreflect.StringKind:
								reflectedMsg.Set(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field)), protoreflect.ValueOf(reduceStringParam(reflectedMsg.Get(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field))).String(), claims.Policy.Reduced[field][1])))
							}
						} else {
							//Suppress the field
							switch reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field)).Kind() {
							case protoreflect.Int32Kind:
								reflectedMsg.Set(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field)), protoreflect.ValueOf(suppressInt(reflectedMsg.Get(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field))).Int())))
							case protoreflect.StringKind:
								reflectedMsg.Set(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field)), protoreflect.ValueOf(suppressString(reflectedMsg.Get(reflectedMsg.Descriptor().Fields().ByName(protoreflect.Name(field))).String())))
							}
						}
					}
				}
			}
		}

		return h, nil
	}
}

// ------ minimzation functions ------

// Suppression functions
func suppressInt(number int64) int32 {
	// receives an integer (e.g., house number) and returns -1 as "none".
	return -1
}
func suppressString(text string) string {
	// receives a string (e.g., street name) and cuts it off after the 5th character.
	return ""
}

// Noising functions
// --> parametrized
func noiseIntParam(number int64, param string) int64 {
	// receives an int and returns noised version of it.
	// rand.Int63n returns a non-negative pseudo-random 63-bit integer
	// available noise functions:
	// - Gaussian
	// - Laplace
	// e.g. noiseIntParam(135, "Gaussian")

	// Gaussian noise
	var n noise.Noise
	epsilon := 1.0
	delta := 0.0

	switch param {
	case "Gaussian":
		delta = 0.01
		n = noise.Gaussian()
	case "Laplace":
		n = noise.Laplace()
	default:
		log.Fatalf("Error: Unknown noise function: %v", param)
		return -1
	}

	// Instantiate a new BoundedSum with the chosen noise mechanism.
	sumParams := &dpagg.BoundedSumInt64Options{
		Epsilon:                  epsilon,
		Delta:                    delta,
		Noise:                    n,
		MaxPartitionsContributed: 1,
		Lower:                    0,
		Upper:                    100,
	}
	sum := dpagg.NewBoundedSumInt64(sumParams)

	// Add our number to the sum
	sum.Add(number)

	// Calculate the result with noise
	result := sum.Result()

	// The result is a float64, so we'll convert it to int64
	return int64(math.Abs(float64(result)))
}
func noiseStringParam(string, param string) string {
	// currently not implemented
	// suppressing the field instead
	return suppressString(string)
}

// --> non-parametrized
func noiseInt(number int64) int64 {
	// receives a house number and returns noised version of it.
	// rand.Int31 returns a non-negative pseudo-random 31-bit integer as an int32 from the default Source.
	return number - rand.Int63n(number) + rand.Int63n(number)
}
func noiseString(string) string {
	// receives a string and returns noised version of it.
	return ""
}

// Generalization functions
// --> parametrized
func generalizeIntParam(number int64, param string) int64 {
	// receives an integer (e.g., house number) and returns its range of param's as the lower end of the interval specified by param..
	// e.g. generalizeIntParam(135, 10) -> 131

	intParam, err := strconv.ParseInt(param, 10, 64)
	if err != nil {
		log.Fatalf("Error on converting string to int: %v", err)
	}
	return number/intParam*intParam + 1
}
func generalizeStringParam(text string, param string) string {
	// receives a string (e.g., street name) and returns the first ncharacter(s), with n=param.
	intParam, err := strconv.ParseInt(param, 10, 64)
	if err != nil {
		log.Fatalf("Error on converting string to int: %v", err)
	}
	return text[0:intParam]
}

// --> non-parametrized
func generalizeInt(number int64) int64 {
	// receives an integer (e.g., house number) and returns its range of 10's as the lower end of the interval.
	// e.g. 135 -> 131
	return number/10*10 + 1
}
func generalizeString(text string) string {
	// receives a string (e.g., street name) and returns the first character.
	return text[0:1]
}

// Reduction functions
// --> parametrized
func reduceIntParam(number int64, param string) int64 {
	// receives an integer and divides it by the specified by param.
	// e.g. reduceIntParam(135, 10) -> 13,5

	intParam, err := strconv.ParseInt(param, 10, 64)
	if err != nil {
		log.Fatalf("Error on converting string to int: %v", err)
	}
	return number / intParam * intParam
}
func reduceStringParam(text string, param string) string {
	// receives a string (e.g., street name) and returns the first n character(s), with n=param.
	intParam, err := strconv.ParseInt(param, 10, 64)
	if err != nil {
		log.Fatalf("Error on converting string to int: %v", err)
	}
	return text[0:intParam]
}

// --> non-parametrized
func reduceInt(number int64) int64 {
	return number / 10
}
func reduceString(text string) string {
	// receives a string (e.g., street name) and returns the first 4 characters.
	return text[0:3]
}

// ------ utiliy functions ------

// contains checks if a field is present in a map
func contains(m map[string][]string, key string) bool {
	_, ok := m[key]
	return ok
}

// getLastPart returns the last part of a string separated by dots
// e.g., main.HelloReply.name --> name
func getLastPart(s string) (string, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 1 {
		return "", errors.New("input string is empty")
	}
	return parts[len(parts)-1], nil
}

// loadPublicKey loads a public key from a file
func loadPublicKey(path string) (*rsa.PublicKey, error) {
	pubPEMData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pubPEMData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not in RSA format")
	}

	return rsaPub, nil
}
