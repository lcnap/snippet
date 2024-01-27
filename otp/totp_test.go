package otp

import (
	"fmt"
	"net/url"
	"testing"
	"time"
)

func TestNewDefaultTotp(t *testing.T) {
	s := NewDefaultTotp("app", "lcanp")
	a := s.Token()
	fmt.Println(a, s.UriString())
	time.Sleep(500 * time.Millisecond)
	if b := s.Token(); a != b {
		t.Fatalf("a != b:%s,%s", a, b)
	}
}

func TestNewTotp(t *testing.T) {
	p := Parameters{
		Scheme:    "otpauth",
		Type:      "totp",
		Algorithm: "sha512",
		Digits:    8,
		Period:    15,
		Label:     "app:lcnap@qq.com",
		Issuer:    "lcnap@qq.com",
		Secret:    "PQTBLT4ARFSH5XVNH7SNLLYDN6S5CQRS",
	}
	s, err := NewTotp(p)
	if err != nil {
		t.Fatal(err)
	}
	a := s.Token()
	fmt.Println(a, s.UriString())
	time.Sleep(500 * time.Millisecond)
	if b := s.Token(); a != b {
		t.Fatal("a != b")
	}

	p.Algorithm = "sha256"
	ss, err := NewTotp(p)
	if err != nil {
		t.Fatal(err)
	}
	if c := ss.Token(); c == a {
		t.Fatalf("c != a : %s,%s", c, a)
	}
}

func TestTotp_UriString(t *testing.T) {
	p := Parameters{
		Scheme:    "otpauth",
		Type:      "totp",
		Algorithm: "sha512",
		Digits:    8,
		Period:    30,
		Label:     "app",
		Issuer:    "lcnap",
		Secret:    "PQTBLT4ARFSH5XVNH7SNLLYDN6S5CQRS",
	}
	s, err := NewTotp(p)
	if err != nil {
		t.Fatal(err)
	}
	str := s.UriString()
	fmt.Println(str)

	path, err := url.Parse(str)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(path)
	if path.String() != str {
		t.Fatalf("path != str: %s,%s", path, str)
	}
}

func TestTotp_UriToParameters(t *testing.T) {
	urlstr := "otpauth://totp/app?algorithm=sha512&digits=8&issuer=lcnap&period=30&secret=PQTBLT4ARFSH5XVNH7SNLLYDN6S5CQRS"

	np, err := Parse(urlstr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(np)
	if nu := np.UriString(); nu != urlstr {
		t.Fatal(nu)
	}

}
