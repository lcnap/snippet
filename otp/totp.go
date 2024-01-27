package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"time"
)

type Totp struct {
	t0    int64
	param Parameters
}

func (t *Totp) Token() string {
	now := time.Now().Unix()
	value := (now - t.t0) / int64(t.param.Period)
	v := uint64(value)
	return calcOtp(t.param, v)
}

func (t *Totp) UriString() string {
	return t.param.UriString()
}

func NewDefaultTotp(label, issuer string) Service {
	key := randomKey()
	return &Totp{
		t0: 0,
		param: Parameters{
			Scheme:    "otpauth",
			Type:      "totp",
			Label:     label,
			Issuer:    issuer,
			Period:    30,
			algo:      hmac.New(sha1.New, key),
			Algorithm: "sha1",
			Digits:    6,
			Secret:    base32.StdEncoding.EncodeToString(key),
		},
	}

}

func NewTotp(p Parameters) (Service, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	key, err := base32.StdEncoding.DecodeString(p.Secret)
	if err != nil {
		return nil, fmt.Errorf("非法参数：%s,%#v", p.Secret, p.Secret)
	}

	switch p.Algorithm {
	case "sha2":
		p.algo = hmac.New(sha1.New, key)

	case "sha256":
		p.algo = hmac.New(sha256.New, key)

	case "sha512":
		p.algo = hmac.New(sha512.New, key)

	}

	return &Totp{
		t0:    0,
		param: p,
	}, nil
}
