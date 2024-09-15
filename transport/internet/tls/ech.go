//go:build go1.23
// +build go1.23

package tls

import (
	"context"
	"crypto/tls"
	"encoding/base64"

	"github.com/xtls/xray-core/common/errors"
)

func ApplyECH(c *Config, config *tls.Config) error {
	ECHConfig, err := base64.StdEncoding.DecodeString(c.EchConfig)
	if err != nil {
		errors.LogError(context.Background(), "invalid ECH config")
	}
	config.EncryptedClientHelloConfigList = ECHConfig
	return nil
}
