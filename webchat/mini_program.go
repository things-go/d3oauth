package webchat

import (
	"context"
	"encoding/json"

	"github.com/things-go/tpoauth/errcode"
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
