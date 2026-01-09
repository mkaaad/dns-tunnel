package client

import (
	"encoding/base32"
	"errors"
	"fmt"
	"net"
)

type ClientConfig struct {
	MaxLength       uint // Maximum length of single DNS record(0 < x <=253)
	MaxLabelLength  uint //Maximum length of single Label(0 < x <= 63)
	BaseDomain      string
	Key             []byte
	MessageIDLength uint
}
type Client struct {
	maxLength       int
	maxLabelLength  int
	baseDomain      string
	key             []byte
	availableLength int
	maxTotalChars   int
	dnsReqModel     string
	messageIDLength int
}

func NewClientWithConfig(config *ClientConfig) *Client {
	if config.BaseDomain == "" {
		panic("baseDomain can not be empty string")
	}
	if len(config.Key) != 32 {
		panic("the length of key must be 32")
	}

	var c Client
	if config.MaxLength > 253 || config.MaxLength == 0 {
		c.maxLength = 253
	} else {
		c.maxLength = int(config.MaxLength)
	}
	if config.MaxLabelLength > 63 || config.MaxLabelLength == 0 {
		c.maxLabelLength = 63
	} else {
		c.maxLabelLength = int(config.MaxLabelLength)
	}
	if config.MessageIDLength == 0 {
		c.messageIDLength = 4
	} else {
		c.messageIDLength = int(config.MessageIDLength)
	}
	c.baseDomain = config.BaseDomain
	c.key = config.Key
	availableLength := 253 - len(config.BaseDomain) - int(config.MessageIDLength) - 4
	if availableLength <= 0 {
		panic("fixed string is too long")
	}
	c.availableLength = availableLength
	c.dnsReqModel = `%s.%d.%s.%s`
	c.maxTotalChars = calcMaxTotalChars(c.maxLabelLength, c.availableLength)
	return &c
}
func NewClient(baseDomain string, key []byte) *Client {
	if baseDomain == "" {
		panic("baseDomain or clientName can not be empty string")
	}
	if len(key) != 32 {
		panic("the length of key must be 32")
	}
	availableLength := 253 - len(baseDomain) - 4 - 4
	return &Client{
		maxLength:       253,
		maxLabelLength:  63,
		baseDomain:      baseDomain,
		key:             key,
		availableLength: availableLength,
		messageIDLength: 4,
		maxTotalChars:   calcMaxTotalChars(63, availableLength),
		// availableLength.clientID.baseDomain
		// data.finishFlag.clientID.baseDomain
		dnsReqModel: `%s.%d.%s.%s`,
	}
}
func (c *Client) Do(msg string) error {
	var err error
	var messageID string

	data, err := encrypt(c.key, []byte(msg))
	if err != nil {
		return err
	}
	base32Enc := base32.StdEncoding.EncodeToString(data)
	base32Enc = removeTrailingPad(base32Enc)
	for {
		messageID, err = randString(c.messageIDLength)
		if err != nil {
			return err
		}
		req := "2" + "." + messageID + "." + c.baseDomain

		r, err := net.LookupTXT(string(req))
		if err != nil {
			return err
		}
		if len(r) == 0 {
			return errors.New("failed to get response")
		}
		if r[0] == "exists" {
			continue
		}
		if r[0] == "ok" {
			break
		}
		return errors.New("server response wrong message: " + r[0])
	}
	var i, j int
	for j, _ = range base32Enc {
		// base32Enc[i,j+1].finishFlag.clientName.baseDomain
		// availableLength=len(base32Enc[i:j+1])+len(count)+1
		if j+1-i == c.maxTotalChars {
			data := split(base32Enc[i:j+1], c.maxLabelLength)
			req := fmt.Sprintf(c.dnsReqModel, data, 0, messageID, c.baseDomain)
			i = j + 1
			r, err := net.LookupTXT(string(req))
			if err != nil {
				return err
			}
			if len(r) == 0 {
				return errors.New("failed to get response")
			}
			if r[0] != "ok" {
				return errors.New("server response wrong message: " + r[0])
			}
		}
	}
	if i != len(base32Enc) {
		data := split(base32Enc[i:j+1], c.maxLabelLength)
		req := fmt.Sprintf(c.dnsReqModel, data, 1, messageID, c.baseDomain)

		r, err := net.LookupTXT(req)

		if err != nil {
			return err
		}
		if len(r) == 0 {
			return errors.New("failed to get response")
		}
		if r[0] != "ok" {
			return errors.New("server response wrong message: " + r[0])
		}
	}
	return nil
}
