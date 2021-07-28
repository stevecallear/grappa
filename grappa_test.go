package grappa_test

import (
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt"
	"google.golang.org/grpc/status"
)

func newNone(c jwt.MapClaims) string {
	t, err := jwt.NewWithClaims(jwt.SigningMethodNone, c).SignedString(nil)
	if err != nil {
		panic(err)
	}

	return t
}

func newRSA(k []byte, c jwt.MapClaims) string {
	pk, err := jwt.ParseRSAPrivateKeyFromPEM(k)
	if err != nil {
		panic(err)
	}

	t, err := jwt.NewWithClaims(jwt.SigningMethodRS256, c).SignedString(pk)
	if err != nil {
		panic(err)
	}

	return t
}

func newHMAC(k []byte, c jwt.MapClaims) string {
	t, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims(c)).SignedString(k)
	if err != nil {
		panic(err)
	}

	return t
}

func assertErrorExists(t *testing.T, act error, exp bool) {
	if act != nil && !exp {
		t.Errorf("got %v, expected nil", act)
	}

	if act == nil && exp {
		t.Error("got nil, expected an error")
	}
}

func assertErrorEqual(t *testing.T, act, exp error) {
	if act == exp {
		return
	}

	if ac, ec := status.Code(act), status.Code(exp); ac != ec {
		t.Errorf("got %v, expected %v", ac, ec)
	}
}

func assertDeepEqual(t *testing.T, act, exp interface{}) {
	if !reflect.DeepEqual(act, exp) {
		t.Errorf("got %v, expected %v", act, exp)
	}
}

const (
	rsaPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAzluOVwhb/fgP7RRcaBPIUEaTlV4FC75kfng4vQ6dS4mBCiB2
OzLPNG6+Vf5TfSpmBewsfINrSlc99fY+sgPCE+QIdS3byT3WRclcCyRAsieZs7Dy
kzL1d1wLykignAxn5izcXOkQbURMnofU1LPmiUkSFYySYharOELYpJvLV+hlvGN8
dOuPXEdGwboESQXVzWlywACmLdEgL+APgKV2OIvGAzynaX5fnicevcm8eQNV325G
2gjaekmrdDHmv0L6yFyh9yR1pafslpQX35zTKlmnhjIhZihOyfTb9cdkid4ButGx
TbkQhZR0eI+K3CqAf4Tk2HbKSaMjl+QXPDr7kwIDAQABAoIBAQCnjlPve0wm1aso
1+WIZLe75vKiz+rM9FVpE3kOmbVCxm3OqTkXLFRuwJUwAggMk8avfGtK1vLhNCGN
e9rAdKi7uebcLtZNezZnB+8C5PbbMaht7Xmp6DDEMCsqnvo6eyBKF5b+ogfCkTid
aLF53HGOe5SBhti9aKayUiTS0+Wyg/3FUmwvYY7/zxYjgg69WDb54CRCWtTc0TUT
Bw0LPu6DzBCvhvRD9l7gZLKeksUSnZtoCIQRmmdTglWn5dU7tGHpJQYHlXODqraB
JjVG72xyIp1NZheTgQEuj+p08DCgieGn0IDnATc+Z7yaZ9Q7UzeJGaevyVoJpnkT
BRC/UHSBAoGBAO53aAtpMdvXsfbv6aZ5aqDQbAv04jyBWIP8bgUJsl8GtpS06Gb4
+b9WcqHmo5E/g4fk4f1cAZ1Dur9A3A+xIGmpUBMAzY7qIuWyXYxkAsZCUbOZl+c8
4PZBeNvanqIy2qKnWAQDPrqTwQ4Fm59Zl4sYVTWvl1zrON1AlpePa9PhAoGBAN2H
xh8XL5UWippw+OkOfO0urf6SFjWai792dXTH9oRbZR5kWsHCESxgIGNip5ILD/4i
3NGbhBfc3je6eN3ZqTtMrfG+WrJPHN+AZ9CM3njaOBUZZMFzlT0JcjDw3CAxxAqj
lfX0f9QTN6bTdGSmL5y4TLVlqBXFBEOLKX7/7H3zAoGBAL6H4zayzyZzGXtOxyW+
/yYMQTfwak6jniCesR0PWVg5meoI/WNA7PMm1CJtkCT+VU5f3vy65YNM2Un0PZ/A
C0DBCfyU+KiGhGl4cOw6AEl+NZ9FSix05N19BF7NN1ArR6sL//P8z8LtSSO18ViJ
kd6OC48Ag/S28FE/SNNBwYqhAoGBAKxXWWmMlybsP24BH5PoAoZev1wB+KdBESEl
niD5A65aj+NB/V0phkS4j9nhwS2bz5hNNO8Yhn4uBO7j8e3dzItmjxg3l8WKSJMU
CS+0t8rbMbAwbjMVoW+3ro+mggnFzZbdRufui5fIT45IiQ9YPkg1FPA2Irq06ClH
1UOJBEnDAoGAQOfidq8W/ITrRaeBIXxLB9aAoIC7FPxPYdTOZilO6bNhTPQ5qY+c
g7TBOr7B7hC6kj7XSAYhcYmXPrYhzDdFia4O9ZJfKDgRLdmzuDxZGDK4hyBEraZz
JgzIE5E6gwiKHpiU+n7CwVGeeYT2vKWOSM+gluTmeD26zNhDY9udlGU=
-----END RSA PRIVATE KEY-----`

	rsaPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzluOVwhb/fgP7RRcaBPI
UEaTlV4FC75kfng4vQ6dS4mBCiB2OzLPNG6+Vf5TfSpmBewsfINrSlc99fY+sgPC
E+QIdS3byT3WRclcCyRAsieZs7DykzL1d1wLykignAxn5izcXOkQbURMnofU1LPm
iUkSFYySYharOELYpJvLV+hlvGN8dOuPXEdGwboESQXVzWlywACmLdEgL+APgKV2
OIvGAzynaX5fnicevcm8eQNV325G2gjaekmrdDHmv0L6yFyh9yR1pafslpQX35zT
KlmnhjIhZihOyfTb9cdkid4ButGxTbkQhZR0eI+K3CqAf4Tk2HbKSaMjl+QXPDr7
kwIDAQAB
-----END PUBLIC KEY-----`
)
