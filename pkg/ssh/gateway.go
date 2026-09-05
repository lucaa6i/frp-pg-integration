// Copyright 2023 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/pkg/util/log"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

type Gateway struct {
	bindPort int
	ln       net.Listener

	peerServerListener *netpkg.InternalListener

	sshConfig *ssh.ServerConfig
	authDB    *AuthorizedKeysDB

	heartbeatInterval time.Duration
	heartbeatCountMax int64
}

func NewGateway(
	cfg v1.SSHTunnelGateway, bindAddr string,
	peerServerListener *netpkg.InternalListener,
) (*Gateway, error) {
	sshConfig := &ssh.ServerConfig{}

	// privateKey
	var (
		privateKeyBytes []byte
		err             error
	)
	if cfg.PrivateKeyFile != "" {
		privateKeyBytes, err = os.ReadFile(cfg.PrivateKeyFile)
	} else {
		if cfg.AutoGenPrivateKeyPath != "" {
			privateKeyBytes, _ = os.ReadFile(cfg.AutoGenPrivateKeyPath)
		}
		if len(privateKeyBytes) == 0 {
			privateKeyBytes, err = transport.NewRandomPrivateKey()
			if err == nil && cfg.AutoGenPrivateKeyPath != "" {
				err = os.WriteFile(cfg.AutoGenPrivateKeyPath, privateKeyBytes, 0o600)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	sshConfig.AddHostKey(privateKey)

	dbConfigured := cfg.AuthorizedKeysDB != nil && cfg.AuthorizedKeysDB.DSN != ""
	sshConfig.NoClientAuth = !dbConfigured && cfg.AuthorizedKeysFile == ""

	var authDB *AuthorizedKeysDB
	if dbConfigured {
		authDB, err = NewAuthorizedKeysDB(context.Background(), *cfg.AuthorizedKeysDB)
		if err != nil {
			return nil, fmt.Errorf("init authorized keys db: %w", err)
		}
	}

	sshConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if authDB != nil {
			// Look up by the marshaled public key blob (BYTEA in Postgres).
			// Alternative: pass ssh.FingerprintSHA256(key) instead — the DB
			// then stores a "SHA256:..." string keyed column. Both work; raw
			// bytes is more direct, fingerprint is friendlier to log/audit.
			user, ok, err := authDB.LookupUser(context.Background(), key.Marshal())
			if err != nil {
				log.Errorf("authorized keys db lookup error: %v", err)
				return nil, fmt.Errorf("internal error")
			}
			if !ok {
				return nil, fmt.Errorf("unknown public key for remoteAddr %q", conn.RemoteAddr())
			}
			return &ssh.Permissions{
				Extensions: map[string]string{"user": user},
			}, nil
		}

		authorizedKeysMap, err := loadAuthorizedKeysFromFile(cfg.AuthorizedKeysFile)
		if err != nil {
			log.Errorf("load authorized keys file error: %v", err)
			return nil, fmt.Errorf("internal error")
		}

		user, ok := authorizedKeysMap[string(key.Marshal())]
		if !ok {
			return nil, fmt.Errorf("unknown public key for remoteAddr %q", conn.RemoteAddr())
		}
		return &ssh.Permissions{
			Extensions: map[string]string{
				"user": user,
			},
		}, nil
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(bindAddr, strconv.Itoa(cfg.BindPort)))
	if err != nil {
		if authDB != nil {
			authDB.Close()
		}
		return nil, err
	}
	return &Gateway{
		bindPort:           cfg.BindPort,
		ln:                 ln,
		peerServerListener: peerServerListener,
		sshConfig:          sshConfig,
		authDB:             authDB,
		heartbeatInterval:  time.Duration(cfg.HeartbeatInterval) * time.Second,
		heartbeatCountMax:  cfg.HeartbeatCountMax,
	}, nil
}

func (g *Gateway) Run() {
	for {
		conn, err := g.ln.Accept()
		if err != nil {
			return
		}
		go g.handleConn(conn)
	}
}

func (g *Gateway) Close() error {
	err := g.ln.Close()
	if g.authDB != nil {
		g.authDB.Close()
	}
	return err
}

func (g *Gateway) handleConn(conn net.Conn) {
	defer conn.Close()

	ts, err := NewTunnelServer(conn, g.sshConfig, g.peerServerListener, g.heartbeatInterval, g.heartbeatCountMax)
	if err != nil {
		return
	}
	if err := ts.Run(); err != nil {
		log.Errorf("ssh tunnel server run error: %v", err)
	}
}

func loadAuthorizedKeysFromFile(path string) (map[string]string, error) {
	authorizedKeysMap := make(map[string]string) // value is username
	authorizedKeysBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for len(authorizedKeysBytes) > 0 {
		pubKey, comment, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return nil, err
		}

		authorizedKeysMap[string(pubKey.Marshal())] = strings.TrimSpace(comment)
		authorizedKeysBytes = rest
	}
	return authorizedKeysMap, nil
}
