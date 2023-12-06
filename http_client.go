package main

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/x509"
)

// NewHTTPSClient 创建国密HTTPS客户端，只对服务端进行身份认证（验证服务端证书）。
// pool: 根证书链
func NewHTTPSClient(pool *x509.CertPool) *http.Client {
	return &http.Client{
		Transport: NewSimpleRoundTripper(&gmtls.Config{
			GMSupport: &gmtls.GMSupport{},
			RootCAs:   pool,
		}),
	}
}

// NewAuthHTTPSClient 创建双向身份认证国密HTTPS客户端
//
// pool: 根证书链
// clientAuthCert: 客户端认证密钥对和证书
func NewAuthHTTPSClient(pool *x509.CertPool, clientAuthCert *gmtls.Certificate) *http.Client {
	return &http.Client{
		Transport: NewSimpleRoundTripper(&gmtls.Config{
			GMSupport:    &gmtls.GMSupport{},
			RootCAs:      pool,
			Certificates: []gmtls.Certificate{*clientAuthCert},
		}),
	}
}

// NewCustomHTTPSClient 创建自定义国密HTTPS客户端
// 通过自定义TLS参数定制TLS实现细节，如进行双向身份认证等。
func NewCustomHTTPSClient(config *gmtls.Config) *http.Client {
	if config == nil {
		return &http.Client{}
	}

	return &http.Client{
		Transport: newDefaultGMHttpClientTransport(config),
	}
}

func newDefaultGMHttpClientTransport(tlsConfig *gmtls.Config) http.RoundTripper {
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {

			dialer := &net.Dialer{}

			conn, err := gmtls.DialWithDialer(dialer, network, addr, tlsConfig)
			if err != nil {
				return nil, err
			}

			return conn, nil
		},
		Dial: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 60 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     30 * time.Second,
	}
}
