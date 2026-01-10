package client

import (
	"crypto/rand"

	"golang.org/x/crypto/chacha20poly1305"
)

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
func split(s string, length int) []string {
	var result []string
	// 检查边界条件
	if length <= 0 {
		return nil // 如果长度小于等于0，返回空切片
	}

	for i := 0; i < len(s); i += length {
		end := i + length
		if end > len(s) {
			end = len(s) // 确保最后一部分不超出字符串长度
		}
		result = append(result, s[i:end])
	}

	return result
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// 创建随机 nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// 加密数据
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// 拼接 nonce 和 ciphertext
	result := append(nonce, ciphertext...)
	return result, nil
}
