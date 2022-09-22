package tlsdial

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"regexp"

	"go.k6.io/k6/js/modules"
)

// init ///////////////////////////////////////////////////////////////////////
func init() {
	modules.Register("k6/x/tlsdial", NewDial())
}

// factory stuff per Virtual User /////////////////////////////////////////////
type RootModule struct{}

type ModuleInstance struct {
	vu        modules.VU
	tlsdialer *TLSDial
}

var (
	_ modules.Instance = &ModuleInstance{}
	_ modules.Module   = &RootModule{}
)

func NewDial() *RootModule {
	return &RootModule{}
}

func (*RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	return &ModuleInstance{
		vu:        vu,
		tlsdialer: &TLSDial{vu: vu},
	}
}

func (mi *ModuleInstance) Exports() modules.Exports {
	return modules.Exports{Default: mi.tlsdialer}
}

// meat and potatoes //////////////////////////////////////////////////////////
type TLSConfig struct {
	CaCertificates     []string
	ClientCertificate  string
	ClientKey          string
	InsecureSkipVerify bool
}

func StripPemSpaces() func(string) string {
	mc := regexp.MustCompile(`\n *`)
	return func(pem string) string {
		return mc.ReplaceAllString(pem, "\n")
	}
}

type TLSDial struct {
	vu modules.VU
}

func (tlsdial *TLSDial) Dial(addr string, config TLSConfig) (*tls.Conn, error) {

	pemStrip := StripPemSpaces()

	// build a config struct
	newConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
	}

	// make a CA cert pool
	if len(config.CaCertificates) != 0 {
		caCerts := x509.NewCertPool()
		for _, val := range config.CaCertificates {
			caCerts.AppendCertsFromPEM([]byte(pemStrip(val)))
		}
		newConfig.RootCAs = caCerts
	}

	// create the client cert
	if (config.ClientKey != "") && (config.ClientCertificate != "") {

		cert := pemStrip(config.ClientCertificate)
		key := pemStrip(config.ClientKey)
		clientPki, err := tls.X509KeyPair([]byte(cert), []byte(key))
		if err != nil {
			log.Fatal(err)
		}
		newConfig.Certificates = []tls.Certificate{clientPki}
	}

	conn, err := tls.Dial("tcp", addr, newConfig)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (tlsdial *TLSDial) Write(conn *tls.Conn, data []byte) error {
	_, err := conn.Write(data)
	if err != nil {
		return err
	}

	return nil
}

func (tlsdial *TLSDial) Read(conn *tls.Conn, size int) ([]byte, error) {
	buf := make([]byte, size)
	_, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (tlsdial *TLSDial) Readstring(conn *tls.Conn) (string, error) {
	buf := make([]byte, 1024)
	_, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	for buf[len(buf)-1] == 0 {
		buf = buf[:len(buf)-1]
	}
	return string(buf), nil
}

func (tlsdial *TLSDial) WriteLn(conn *tls.Conn, data []byte) error {
	_, err := conn.Write(append(data, []byte("\n")...))
	if err != nil {
		return err
	}
	return nil
}

func (tlsdial *TLSDial) Close(conn *tls.Conn) error {
	err := conn.Close()
	if err != nil {
		return err
	}
	return nil
}
