package otp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
)

type Service interface {
	Token() string

	UriString() string
}

type Parameters struct {
	Scheme    string
	Type      string
	Label     string
	Issuer    string
	Secret    string
	Algorithm string
	algo      hash.Hash
	Digits    int
	Counter   int
	Period    int
}

func (p *Parameters) check() error {
	if p.Scheme != "otpauth" {
		return fmt.Errorf("非法参数：%s", p.Scheme)
	}
	if p.Type != "hotp" && p.Type != "totp" {
		return fmt.Errorf("非法参数：%s", p.Type)
	}
	if p.Digits < 6 || p.Digits > 8 {
		return fmt.Errorf("非法参数：%d", p.Digits)
	}

	if p.Period != 15 && p.Period != 30 && p.Period != 60 {
		return fmt.Errorf("非法参数：%d", p.Period)
	}

	if p.Algorithm != "sha1" && p.Algorithm != "sha256" && p.Algorithm != "sha512" {
		return fmt.Errorf("非法参数：%s", p.Algorithm)
	}

	if len(p.Secret) == 0 {
		return fmt.Errorf("非法参数：%s", p.Secret)
	}

	if len(p.Label) == 0 {
		return fmt.Errorf("非法参数：%s", p.Label)
	}

	return nil
}

func (p *Parameters) UriString() string {
	query := url.Values{}
	query.Add("secret", p.Secret)
	query.Add("issuer", p.Issuer)
	query.Add("algorithm", p.Algorithm)
	query.Add("digits", strconv.Itoa(p.Digits))
	query.Add("period", strconv.Itoa(p.Period))
	if p.Type == "hotp" {
		query.Add("counter", strconv.Itoa(p.Counter))
	}

	path := &url.URL{
		Scheme:   "otpauth",
		Host:     p.Type,
		Path:     p.Label,
		RawQuery: query.Encode(),
	}
	return path.String()
	//return fmt.Sprintf(
	//	"otpauth://%s/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&counter=%d&period=%d",
	//	p.Type, p.Label, p.Secret, p.Issuer, p.Algorithm, p.Digits, p.Counter, p.Period)
}

func Parse(rawUrl string) (*Parameters, error) {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}
	query := u.Query()

	digits, err := strconv.Atoi(query.Get("digits"))
	if err != nil {
		return nil, err
	}
	period, err := strconv.Atoi(query.Get("period"))
	if err != nil {
		return nil, err
	}

	param := Parameters{
		Scheme:    u.Scheme,
		Type:      u.Host,
		Algorithm: u.Query().Get("algorithm"),
		Digits:    digits,
		Period:    period,
		Label:     u.Path,
		Issuer:    query.Get("issuer"),
		Secret:    query.Get("secret"),
	}

	if err := param.check(); err != nil {
		return nil, err
	}

	return &param, nil

}

func calcOtp(p Parameters, value uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, value)

	p.algo.Reset()
	p.algo.Write(buf)
	hash := p.algo.Sum(nil)

	offset := int(hash[len(hash)-1] & 0xf)

	bin :=
		(int(hash[offset]&0x7f) << 24) |
			(int(hash[offset+1]&0xff) << 16) |
			(int(hash[offset+2]&0xff) << 8) |
			int(hash[offset+3]&0xff)

	otp := int(bin) % digitsPower[p.Digits]

	otpstr := strconv.Itoa(otp)
	for len(otpstr) < p.Digits {
		otpstr = "0" + otpstr
	}

	return otpstr

}

func randomKey() []byte {
	size := 20
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		fmt.Println("error:", err)
	}
	return key

}
