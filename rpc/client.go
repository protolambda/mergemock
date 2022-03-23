package rpc

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/golang-jwt/jwt/v4"
)

type Client struct {
	inner  *rpc.Client
	secret []byte
}

func Dial(rawurl string, secret []byte) (*Client, error) {
	client, err := rpc.Dial(rawurl)
	if err != nil {
		return nil, err
	}
	return &Client{client, secret}, nil
}

func (c *Client) CallContext(ctx context.Context, result interface{}, method string, args ...interface{}) error {
	token, err := IssueJwtToken().SignedString(c.secret)
	if err != nil {
		return err
	}
	c.inner.SetHeader("Authorization", EncodeJwtAuthorization(token))
	return c.inner.CallContext(ctx, result, method, args...)
}

func (c *Client) Close() {
	c.inner.Close()
}

// IssueJwtToken creates a new token with IssuedAt set to time.Now().
func IssueJwtToken() *jwt.Token {
	claims := jwt.RegisteredClaims{IssuedAt: &jwt.NumericDate{time.Now()}}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
}

// EncodeJwtAuthorization encodes the raw token string into HTTP header value format.
func EncodeJwtAuthorization(strToken string) string {
	return fmt.Sprintf("Bearer %v", strToken)
}
