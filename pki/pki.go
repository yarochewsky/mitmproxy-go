package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// CertificateAuthority is a certificate authority
type CertificateAuthority interface {
	// Sign signs a new cert for a CN
	Sign(commonName string) (*tls.Certificate, error)
	// SaveAuthority saves the CA's key and cert to disk
	SaveAuthority(keyFile, certFile string) error
}

type authority struct {
	// private key and root cert PEM-encoded
	key, cert *bytes.Buffer

	cfg *Config
}

// Config specifies the CA'S parameters
type Config struct {
	Organization string
	Country      string
	Locality     string
	StreetAddr   string
	PostalCode   string
}

func (a *authority) Sign(commonName string) (*tls.Certificate, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject:      *a.cfg.subjectFromConfig(),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	if ip := net.ParseIP(commonName); ip != nil {
		cert.IPAddresses = append(cert.IPAddresses, ip)
	} else {
		cert.DNSNames = append(cert.DNSNames, commonName)
	}

	rootCA, err := tls.X509KeyPair(a.cert.Bytes(), a.key.Bytes())
	if err != nil {
		return nil, err
	}

	if rootCA.Leaf, err = x509.ParseCertificate(rootCA.Certificate[0]); err != nil {
		return nil, err
	}
	cert.AuthorityKeyId = rootCA.Leaf.SubjectKeyId

	var priv *rsa.PrivateKey
	if priv, err = rsa.GenerateKey(rand.Reader, rsaBits); err != nil {
		return nil, err
	}
	cert.SubjectKeyId = bigIntHash(priv.N)

	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(rand.Reader, cert, rootCA.Leaf, &priv.PublicKey, rootCA.PrivateKey); err != nil {
		return nil, err
	}

	out := new(tls.Certificate)
	out.Certificate = append(out.Certificate, derBytes)
	out.PrivateKey = priv
	out.Leaf, _ = x509.ParseCertificate(derBytes)

	return out, nil
}

// LoadAuthorityFromDisk loads a CA from the key and cert files on disk
func LoadAuthorityFromDisk(keyFile, certFile string, cfg *Config) (CertificateAuthority, error) {
	key, err := load(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %v", err)
	}
	cert, err := load(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load cert: %v", err)
	}
	return &authority{
		key:  key,
		cert: cert,
		cfg:  cfg,
	}, nil
}

// SaveAuthority saves the CA's key and cert to disk
func (a *authority) SaveAuthority(keyFile, certFile string) error {
	if err := write(keyFile, a.key); err != nil {
		return fmt.Errorf("failed to write key: %v", err)
	}
	if err := write(certFile, a.cert); err != nil {
		return fmt.Errorf("failed to write cert: %v", err)
	}
	return nil
}

// CreateNewAuthority creates a new CA with a key and cert
func CreateNewAuthority(cfg *Config) (CertificateAuthority, error) {
	key, cert, err := newAuthority(cfg)
	if err != nil {
		return nil, err
	}

	return &authority{
		key:  key,
		cert: cert,
		cfg:  cfg,
	}, nil
}

// loads an already built cert or key file from disk
func load(filename string) (*bytes.Buffer, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b := &bytes.Buffer{}
	if _, err := b.ReadFrom(f); err != nil {
		return nil, err
	}

	return b, nil
}

// writes a key and cert to disk
func write(filename string, b *bytes.Buffer) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(b.Bytes())
	return err
}

func (c *Config) subjectFromConfig() *pkix.Name {
	return &pkix.Name{
		Organization:  []string{c.Organization},
		Country:       []string{c.Country},
		Province:      []string{""},
		Locality:      []string{c.Locality},
		StreetAddress: []string{c.StreetAddr},
		PostalCode:    []string{c.PostalCode},
	}
}

func newAuthority(cfg *Config) (key, cert *bytes.Buffer, err error) {
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               *cfg.subjectFromConfig(),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	return caPrivKeyPEM, caPEM, nil
}

const (
	rsaBits = 2048
)

func bigIntHash(n *big.Int) []byte {
	h := sha1.New()
	h.Write(n.Bytes())
	return h.Sum(nil)
}
