package webchat

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-resty/resty/v2"

	"github.com/things-go/tpoauth/errcode"
)

const (
	host               = "https://api.weixin.qq.com"
	urlSnsAuthCode     = "https://open.weixin.qq.com/connect/qrconnect"
	urlSnsAccessToken  = host + "/sns/oauth2/access_token"
	urlSnsRefreshToken = host + "/sns/oauth2/refresh_token"
	urlSnsAuth         = host + "/sns/auth"
	urlSnsUserInfo     = host + "/sns/userinfo"
)

type Token struct {
	AccessToken  string `json:"access_token"`  // 接口调用凭证
	ExpiresIn    int    `json:"expires_in"`    // 超时时间,单位: s
	RefreshToken string `json:"refresh_token"` // 用户刷新refresh token
	Openid       string `json:"openid"`        // 授权用户唯一标识
	Scope        string `json:"scope"`         // 用户授权的作用域，使用逗号（,）分隔
}

type UserInfoResponse struct {
	Unionid    string   `json:"unionid"`    // 用户统一标识。针对一个微信开放平台帐号下的应用，同一用户的unionid是唯一的。
	Openid     string   `json:"openid"`     // 普通用户的标识，对当前开发者帐号唯一
	Nickname   string   `json:"nickname"`   // 昵称
	Sex        int      `json:"sex"`        // 性别, 1:男 2: 女
	Province   string   `json:"province"`   // 省
	City       string   `json:"city"`       // 市
	Country    string   `json:"country"`    // 国家, 中国为CN
	Headimgurl string   `json:"headimgurl"` // 用户头像，最后一个数值代表正方形头像大小（有0、46、64、96、132数值可选，0代表640*640正方形头像），用户没有头像时该项为空
	Privilege  []string `json:"privilege"`  // 用户特权信息，json数组，如微信沃卡用户为（chinaunicom）
}

type ErrResponse struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// ClientSecret is the application's secret.
	ClientSecret string

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string
}

// AuthCodeURL 获取授权登录地址
func (c *Config) AuthCodeURL(state string) string {
	var buf bytes.Buffer
	buf.WriteString(urlSnsAuthCode)
	v := url.Values{
		"response_type": {"code"},
		"appid":         {c.ClientID},
	}
	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}

	v.Set("scope", "snsapi_login")
	if state != "" {
		// TODO(light): Docs say never to omit state; don't allow empty.
		v.Set("state", state)
	}
	if strings.Contains(urlSnsAuthCode, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}

type Client struct {
	*Config
	*resty.Client
}

var rxErrCode = regexp.MustCompile("errcode")

func New(c Config) *Client {
	return &Client{
		&c,
		resty.New(),
	}
}

func NewWithClient(c Config, hc *http.Client) *Client {
	return &Client{
		&c,
		resty.NewWithClient(hc),
	}
}

func (sf *Client) Exchange(ctx context.Context, code string) (*Token, error) {
	resp, err := sf.R().
		SetContext(ctx).
		SetQueryParams(map[string]string{
			"appid":      sf.ClientID,
			"secret":     sf.ClientSecret,
			"grant_type": "authorization_code",
			"code":       code,
		}).
		Get(urlSnsAccessToken)
	if err != nil {
		return nil, err
	}
	if statusCode := resp.StatusCode(); statusCode < 200 || statusCode > 299 {
		return nil, &errcode.ErrCode{Status: statusCode}
	}
	if isMatch := rxErrCode.MatchString(resp.String()); isMatch {
		return nil, parseErrResponse2Err(resp.Body())
	}
	result := &Token{}
	err = json.Unmarshal(resp.Body(), &result)
	if err != nil {
		return nil, err
	}
	return result, err
}

func (sf *Client) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	resp, err := sf.R().
		SetContext(ctx).
		SetQueryParams(map[string]string{
			"appid":         sf.ClientID,
			"grant_type":    "refresh_token",
			"refresh_token": refreshToken,
		}).
		Get(urlSnsRefreshToken)
	if err != nil {
		return nil, err
	}
	if statusCode := resp.StatusCode(); statusCode < 200 || statusCode > 299 {
		return nil, &errcode.ErrCode{Status: statusCode}
	}
	if isMatch := rxErrCode.MatchString(resp.String()); isMatch {
		return nil, parseErrResponse2Err(resp.Body())
	}
	result := &Token{}
	if err = json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}
	return result, err
}

func (sf *Client) VerifyAuthToken(ctx context.Context, accessToken string) error {
	resp, err := sf.R().
		SetContext(ctx).
		SetQueryParams(map[string]string{
			"appid":        sf.ClientID,
			"access_token": accessToken,
		}).
		Get(urlSnsAuth)
	if err != nil {
		return err
	}
	if statusCode := resp.StatusCode(); statusCode < 200 || statusCode > 299 {
		return &errcode.ErrCode{Status: statusCode}
	}
	return parseErrResponse2Err(resp.Body())
}

func (sf *Client) GetUserInfo(ctx context.Context, accessToken, openid string) (*UserInfoResponse, error) {
	resp, err := sf.R().
		SetContext(ctx).
		SetQueryParam("access_token", accessToken).
		// SetQueryParam("lang", "zh-CN"). // 默认zh-CN
		SetQueryParam("openid", openid).
		Get(urlSnsUserInfo)
	if err != nil {
		return nil, err
	}
	if statusCode := resp.StatusCode(); statusCode < 200 || statusCode > 299 {
		return nil, &errcode.ErrCode{Status: statusCode}
	}
	if isMatch := rxErrCode.MatchString(resp.String()); isMatch {
		return nil, parseErrResponse2Err(resp.Body())
	}
	result := &UserInfoResponse{}
	if err = json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}
	return result, err
}

func parseErrResponse2Err(body []byte) error {
	result := &ErrResponse{}
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}
	if result.ErrCode == 0 {
		return nil
	}
	return &errcode.ErrCode{Status: http.StatusOK, Code: result.ErrCode, Msg: result.ErrMsg}
}
