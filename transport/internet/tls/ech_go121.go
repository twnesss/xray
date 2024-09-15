//go:build !go1.23
// +build !go1.23

package tls

import (
	"crypto/tls"

	"github.com/xtls/xray-core/common/errors"
)

func ApplyECH(c *Config, config *tls.Config) error {
	return errors.New("Win7 does not support ECH")
}
