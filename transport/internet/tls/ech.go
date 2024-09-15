//go:build go1.23
// +build go1.23

package tls

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common/errors"
)

func ApplyECH(c *Config, config *tls.Config) error {
	var ECHConfig []byte
	var err error

	if len(c.EchConfig) > 0 {
		ECHConfig, err = base64.StdEncoding.DecodeString(c.EchConfig)
		if err != nil {
			return errors.New("invalid ECH config")
		}
	} else {
		if c.ServerName == "" {
			return errors.New("Using DOH for ECH needs serverName")
		}
		ECHRecord, err := QueryRecord(c.ServerName, c.Ech_DOHserver)
		if err != nil {
			return err
		}
		ECHConfig, _ = base64.StdEncoding.DecodeString(ECHRecord)
	}

	config.EncryptedClientHelloConfigList = ECHConfig
	return nil
}

type record struct {
	record string
	expire time.Time
}

var (
	dnsCache = make(map[string]record)
	mutex    sync.RWMutex
)

func QueryRecord(domain string, server string) (string, error) {
	mutex.RLock()
	defer mutex.RUnlock()
	rec, found := dnsCache[domain]
	if found && rec.expire.After(time.Now()) {
		return "", nil
	}
	record, err := dohQuery(server, domain)
	if err != nil {
		return "", err
	}
	rec.record = record
	rec.expire = time.Now().Add(time.Second * 600)
	return record, nil
}

func dohQuery(server string, domain string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	msg, err := m.Pack()
	if err != nil {
		return "", err
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("POST", server, bytes.NewReader(msg))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("query failed with response code:", resp.StatusCode)
	}
	respMsg := new(dns.Msg)
	err = respMsg.Unpack(respBody)
	if err != nil {
		return "", err
	}
	if len(respMsg.Answer) > 0 {
		re := regexp.MustCompile(`ech="([^"]+)"`)
		match := re.FindStringSubmatch(respMsg.Answer[0].String())
		if match[1] != "" {
			return match[1], nil
		}
	}
	return "", errors.New("no ech record found")
}
