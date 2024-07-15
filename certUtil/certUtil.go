/*
go build -o verifying_digital_certificate verifying_the_Validity_Period_of_a_Digital_Certificate.go
./verifying_digital_certificate
*/

package certUtil

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// VerifyCertificateValidity 验证数字证书的有效期
func VerifyCertificateValidity(certPEM string) error {
	// 解析证书
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("无法解析证书 PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("无法解析证书: %v", err)
	}

	// 获取当前时间
	currentTime := time.Now()

	// 检查当前时间是否在证书的有效期内
	if currentTime.Before(cert.NotBefore) || currentTime.After(cert.NotAfter) {
		return fmt.Errorf("证书已过期")
	}

	return nil
}

//
//func main() {
//
//	err := VerifyCertificateValidity()
//	if err != nil {
//		fmt.Println(err)
//		os.Exit(1)
//	}
//
//	fmt.Println("证书有效")
//	 
//}
