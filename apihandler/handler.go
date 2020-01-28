package apihandler

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	pb "github.com/transavro/AuthService/proto"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)


var (
	key = []byte("cloudwalkertransavro")
)

type Server struct {
	UserCollection *mongo.Collection
}

// CustomClaims is our custom metadata, which will be hashed
// and sent as the second segment in our JWT
type CustomClaims struct {
	User *pb.User
	jwt.StandardClaims
}

func (srv *Server) Auth(ctx context.Context, req *pb.User) (*pb.Token, error) {
	findResult := srv.UserCollection.FindOne(ctx, bson.D{{"emac", req.GetEmac()}})
	if findResult.Err() != nil {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("User not found: %s", findResult.Err()))
	}
	var user *pb.User
	err := findResult.Decode(&user)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Error while decoding userData: %s", err))
	}

	token, err := srv.Encode(user)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("error while generating token : %s", err))
	}

	return &pb.Token{Token:token}, nil

}

func (srv *Server) ValidateToken(ctx context.Context, req *pb.Token) (*pb.Token,error) {
	// Decode token
	claims, err := srv.Decode(req.Token)

	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Error while decoding token:  ", err))
	}
	if claims.User.GetEmac() == "" {
		return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("No emac found. "))
	}
	return &pb.Token{Valid:true}, nil
}

// Encode a claim into a JWT
func (srv *Server) Encode(user *pb.User) (string, error) {

	expireToken := time.Now().Add(time.Hour * 3).Unix()

	// Create the Claims
	claims := CustomClaims{
		user,
		jwt.StandardClaims{
			ExpiresAt: expireToken,
			Issuer:    "Cloudwalker.AuthService",
		},
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token and return
	return token.SignedString(key)
}

// Decode a token string into a token object
func (srv *Server) Decode(tokenString string) (*CustomClaims, error) {
	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	// Validate the token and return the custom claims
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}