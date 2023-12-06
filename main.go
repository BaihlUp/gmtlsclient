package main

import (
	"fmt"
	"github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/x509"
	"io/ioutil"
)

// 国密单向认证
func gmtlsClient() {
	// 1. 提供根证书链
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile("conf/certs/chain-ca.crt")
	if err != nil {
		panic(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	// 2. 构造HTTP客户端
	httpClient := NewHTTPSClient(certPool)
	// 3. 调用API访问HTTPS
	response, err := httpClient.Get("https://192.168.170.137:8443/")
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}
	fmt.Println(string(body))
}

// 国密双向认证
func gmtlsAuthClient() {

	// 1. 提供根证书链
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile("conf/certs/chain-ca.crt")
	if err != nil {
		panic(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	// 2. 提供客户端认证证书、密钥对。
	clientAuthCert, err := gmtls.LoadX509KeyPair("conf/certs/server_sign.crt", "conf/certs/server_sign.key")
	// 3. 构造HTTP客户端。
	httpClient := NewAuthHTTPSClient(certPool, &clientAuthCert)
	// 4. 调用API访问HTTPS。
	response, err := httpClient.Get("https://192.168.170.137:8443/")
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}
	fmt.Println(string(body))
}

func main() {
	//gmtlsClient()
	gmtlsAuthClient()
}

//package main
//
//import (
//"github.com/tjfoc/gmsm/gmtls"
//"github.com/tjfoc/gmsm/x509"
//"io/ioutil"
//"log"
//)
//
//func main() {
//	// 信任的根证书
//	certPool := x509.NewCertPool()
//	cacert, err := ioutil.ReadFile("root.cer")
//	if err != nil {
//		log.Fatal(err)
//	}
//	certPool.AppendCertsFromPEM(cacert)
//	cert, err := gmtls.LoadX509KeyPair("sm2_cli.cer", "sm2_cli.pem")
//
//	config := &gmtls.Config{
//		GMSupport:    &gmtls.GMSupport{},
//		RootCAs:      certPool,
//		Certificates: []gmtls.Certificate{cert},
//		// 设置GCM模式套件放在前面
//		CipherSuites: []uint16{gmtls.GMTLS_ECC_SM4_GCM_SM3, gmtls.GMTLS_ECC_SM4_CBC_SM3},
//	}
//
//	conn, err := gmtls.Dial("tcp", "localhost:50052", config)
//	if err != nil {
//		panic(err)
//	}
//	defer conn.Close()
//
//	// 对 conn 读取或写入
//}
