package webchat

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/things-go/tpo/errcode"
)

// error defined
var (
	ErrInvalidIvSize       = errors.New("iv length must equal block size")
	ErrUnPaddingOutOfRange = errors.New("unPadding out of range")
)

const miniProgramCode2Session = "https://api.weixin.qq.com/sns/jscode2session"

type MiniProgramCode2SessionResponse struct {
	Unionid    string `json:"unionid"`     // 用户统一标识。针对一个微信开放平台帐号下的应用，同一用户的unionid是唯一的。
	Openid     string `json:"openid"`      // 普通用户的标识，对当前开发者帐号唯一
	SessionKey string `json:"session_key"` // 会话key
	ErrCode    int    `json:"errcode"`     // 错误码
	ErrMsg     string `json:"errmsg"`      // 错误消息
}

func (sf *Client) MiniProgramCode2Session(ctx context.Context, code string) (*MiniProgramCode2SessionResponse, error) {
	resp, err := sf.R().
		SetContext(ctx).
		SetQueryParams(map[string]string{
			"appid":      sf.ClientID,
			"secret":     sf.ClientSecret,
			"js_code":    code,
			"grant_type": "authorization_code",
		}).
		Get(miniProgramCode2Session)
	if err != nil {
		return nil, err
	}
	if statusCode := resp.StatusCode(); statusCode < 200 || statusCode > 299 {
		return nil, &errcode.ErrCode{Status: statusCode}
	}
	result := &MiniProgramCode2SessionResponse{}
	if err = json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}
	if result.ErrCode != 0 {
		return nil, &errcode.ErrCode{Status: resp.StatusCode(), Code: result.ErrCode, Msg: result.ErrMsg}
	}
	return result, err
}

func MiniProgramVerifySign(sessionKey, rawData, signature string) bool {
	vv := sha1.Sum([]byte(rawData + sessionKey))
	return signature == hex.EncodeToString(vv[:])
}

func MiniProgramDecrypt(sessionKey, encryptedData, biv string) ([]byte, error) {
	sk, err := base64.StdEncoding.DecodeString(sessionKey)
	if err != nil {
		return nil, err
	}
	cipherText, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}
	iv, err := base64.StdEncoding.DecodeString(biv)
	if err != nil {
		return nil, err
	}
	cip, err := aes.NewCipher(sk)
	if err != nil {
		return nil, err
	}
	if len(iv) != cip.BlockSize() {
		return nil, ErrInvalidIvSize
	}
	cipher.NewCBCDecrypter(cip, iv).CryptBlocks(cipherText, cipherText)
	return PCKSUnPadding(cipherText)
}

// PCKSUnPadding PKCS#5和PKCS#7 解填充
func PCKSUnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	if length == 0 {
		return nil, ErrUnPaddingOutOfRange
	}
	unPadSize := int(origData[length-1])
	if unPadSize > length {
		return nil, ErrUnPaddingOutOfRange
	}
	return origData[:(length - unPadSize)], nil
}
