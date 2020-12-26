package epp

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/dzehv/epp-go/types"
)

// Client represents an EPP client.
type Client struct {
	// TLSConfig holds the TLS configuration that will be used when connecting
	// to an EPP server.
	TLSConfig    *tls.Config
	DialerConfig *net.Dialer
	// conn holds the TCP connection to the server.
	conn    net.Conn
	Timeout int
}

// Connect will connect to the server passed as argument.
func (c *Client) Connect(server string) ([]byte, error) {
	if c.TLSConfig == nil {
		c.TLSConfig = &tls.Config{}
	}

	if c.DialerConfig == nil {
		c.DialerConfig = &net.Dialer{}
	}

	conn, err := tls.DialWithDialer(c.DialerConfig, "tcp", server, c.TLSConfig)
	if err != nil {
		return nil, err
	}

	// Read the greeting.
	greeting, err := ReadMessage(conn, c.Timeout)
	if err != nil {
		return nil, err
	}

	c.conn = conn

	return greeting, nil
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

// Send will send data to the server.
func (c *Client) Send(data []byte) ([]byte, error) {
	err := WriteMessage(c.conn, c.Timeout, data)
	if err != nil {
		c.Close()
		return nil, err
	}

	if err := c.conn.SetReadDeadline(time.Now().Add(time.Duration(c.Timeout) * time.Second)); err != nil {
		c.Close()
		return nil, err
	}

	msg, err := ReadMessage(c.conn, c.Timeout)
	if err != nil {
		c.Close()
		return nil, err
	}

	return msg, nil
}

// Login will perform a login to an EPP server.
func (c *Client) Login(username, password string) ([]byte, error) {
	login := types.Login{
		ClientID: username,
		Password: password,
		Options: types.LoginOptions{
			Version:  "1.0",
			Language: "en",
		},
		Services: types.LoginServices{
			ObjectURI: []string{
				"urn:ietf:params:xml:ns:domain-1.0",
				"urn:ietf:params:xml:ns:contact-1.0",
				"urn:ietf:params:xml:ns:host-1.0",
			},
			ServiceExtension: types.LoginServiceExtension{
				ExtensionURI: []string{
					"urn:ietf:params:xml:ns:secDNS-1.0",
					"urn:ietf:params:xml:ns:secDNS-1.1",
				},
			},
		},
	}

	encoded, err := Encode(login, ClientXMLAttributes())
	if err != nil {
		return nil, err
	}

	return c.Send(encoded)
}
