package client

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
)

type ClientConfig struct {
	MaxLength       uint // Maximum length of single DNS record(0 < x <=253)
	MaxLabelLength  uint //Maximum length of single Label(0 < x <= 63)
	BaseDomain      string
	MessageIDLength uint
}
type Client struct {
	maxLength       int
	maxLabelLength  int
	baseDomain      string
	availableLength int
	maxTotalChars   int
	dnsReqModel     string

	messageIDLength int
}

func NewClientWithConfig(config *ClientConfig) *Client {
	if config.BaseDomain == "" {
		panic("baseDomain can not be empty string")
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
	availableLength := 253 - len(config.BaseDomain) - int(config.MessageIDLength) - 4
	if availableLength <= 0 {
		panic("fixed string is too long")
	}
	c.availableLength = availableLength
	c.dnsReqModel = `%s.%d.%s.%s`
	c.maxTotalChars = calcMaxTotalChars(c.maxLabelLength, c.availableLength)
	return &c
}
func NewClient(baseDomain string) *Client {
	if baseDomain == "" {
		panic("baseDomain or clientName can not be empty string")
	}
	availableLength := 253 - len(baseDomain) - 4 - 4
	return &Client{
		maxLength:       253,
		maxLabelLength:  63,
		baseDomain:      baseDomain,
		availableLength: availableLength,
		messageIDLength: 4,
		maxTotalChars:   calcMaxTotalChars(63, availableLength),
		// availableLength.clientID.baseDomain
		// data.finishFlag.clientID.baseDomain
		dnsReqModel: `%s.%d.%s.%s`,
	}
}
func (c *Client) Do(data string) error {
	base32Enc := base32.StdEncoding.EncodeToString([]byte(data))
	base32Enc = removeTrailingPad(base32Enc)
	var messageID string
	var err error
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

// calcMaxTotalChars 计算包含分隔符在内，最多能容纳的原始字符数
// maxLabelLength: 单个标签的最大长度
// availableLength: 总长度上限（包含分隔符）
func calcMaxTotalChars(maxLabelLength, availableLength int) int {
	// 边界条件校验
	if maxLabelLength <= 0 || availableLength <= 0 {
		return 0
	}

	// 二分查找范围：1 ~ availableLength（最多不可能超过总长度上限）
	left := 1
	right := availableLength
	maxN := 0 // 最终能容纳的最大原始字符数

	for left <= right {
		mid := (left + right) / 2 // 尝试的原始字符数

		// 计算分割段数（向上取整）
		segments := (mid + maxLabelLength - 1) / maxLabelLength
		// 计算包含分隔符的总长度
		totalLength := mid + (segments - 1)

		if totalLength <= availableLength {
			// 当前mid满足条件，尝试更大的值
			maxN = mid
			left = mid + 1
		} else {
			// 当前mid超限，尝试更小的值
			right = mid - 1
		}
	}
	return maxN
}

const charset = "abcdefghijklmnopqrstuvwxyz0123456789"

func randString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := 0; i < n; i++ {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}

func removeTrailingPad(str string) string {
	n := len(str)
	for n > 0 && str[n-1] == '=' {
		n--
	}
	return str[:n]
}
func split(str string, length int) string {
	if length <= 0 || len(str) == 0 {
		return str
	}

	// 计算最终结果所需的内存空间
	partsCount := (len(str) + length - 1) / length
	// 预先分配内存
	parts := make([]byte, 0, len(str)+partsCount)

	count := 0
	for i := 0; i < len(str); i++ {
		parts = append(parts, str[i])
		count++

		if count == length {
			parts = append(parts, '.')
			count = 0
		}
	}

	// 去掉最后一个多余的分隔符
	if len(parts) > 0 && parts[len(parts)-1] == '.' {
		parts = parts[:len(parts)-1]
	}

	return string(parts)
}
