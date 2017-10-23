package salesforce

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/bradberger/context"
	"github.com/bradberger/rest"
	"google.golang.org/appengine/urlfetch"
)

var (
	DefaultAPIVersion = "41.0"

	ErrExpiredToken = errors.New("salesforce api error: expired token")
)

type Token struct {
	ID           string `json:"id"`
	IssuedAt     int64  `json:"issued_at,string"`
	RefreshToken string `json:"refresh_token"`
	InstanceURL  string `json:"instance_url"`
	Signature    string `json:"signature"`
	AccessToken  string `json:"access_token"`
}

type RefreshToken struct {
	ID          string `json:"id"`
	IssuedAt    int64  `json:"issued_at,string"`
	Signature   string `json:"signature"`
	AccessToken string `json:"access_token"`
	InstanceURL string `json:"instance_url"`
}

func New(clientID, clientSecret string) *Client {
	return &Client{ClientID: clientID, ClientSecret: clientSecret}
}

type Client struct {
	AccessToken  string
	ClientID     string
	ClientSecret string
	APIVersion   string
	InstanceURL  string
}

func (c *Client) GetAPIVersion() string {
	if c.APIVersion == "" {
		return DefaultAPIVersion
	}
	return c.APIVersion
}

func (c *Client) Token(ctx context.Context, code, redirectUrl string) (*Token, error) {
	urlStr := "https://login.salesforce.com/services/oauth2/token"
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
		"redirect_uri":  {redirectUrl},
	}
	var t Token
	client := urlfetch.Client(ctx)
	resp, err := client.PostForm(urlStr, form)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		var e Error
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		if err := json.Unmarshal(bodyBytes, &e); err == nil {
			return nil, e
		}
		return nil, fmt.Errorf("salesforce api error: %s", resp.Status)
	}

	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (c *Client) AuthURL(ctx context.Context, redirectUrl string) string {
	form := url.Values{
		"response_type": {"code"},
		"client_id":     {c.ClientID},
		"redirect_uri":  {redirectUrl},
		"scope":         {"api"},
	}
	return "https://login.salesforce.com/services/oauth2/authorize?" + form.Encode()
}

func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*RefreshToken, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
	}

	var t RefreshToken
	client := urlfetch.Client(ctx)
	resp, err := client.PostForm("https://login.salesforce.com/services/oauth2/token", form)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("error: resp.Status")
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, err
	}
	c.AccessToken = t.AccessToken
	if c.InstanceURL != "" {
		c.InstanceURL = t.InstanceURL
	}
	return &t, nil
}

func (c *Client) Versions(ctx context.Context) (versions []APIVersion, err error) {
	urlStr := c.makeURL("/services/data/")
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return
	}
	if _, err = c.Do(ctx, req, &versions); err != nil {
		rest.Errorf(ctx, "Could not find profile by email address: %v", err)
		return versions, err
	}
	rest.Debugf(ctx, "%+v", versions)
	return
}

func (c *Client) makeURL(urlStr string) string {
	if !strings.HasPrefix(urlStr, "https://") {
		urlStr = c.InstanceURL + urlStr
	}
	urlStr = strings.Replace(urlStr, "~", c.GetAPIVersion(), -1)
	return urlStr
}

// do sends the HTTP request to the Salesforce API, adding the Bearer token
func (c *Client) Do(ctx context.Context, req *http.Request, dstVal interface{}) (*http.Response, error) {
	if c.AccessToken != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}
	req.Header.Set("Accept", "application/json")
	client := urlfetch.Client(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	if resp.StatusCode >= 400 {
		var e Error
		if err := json.Unmarshal(bodyBytes, &e); err == nil {
			switch e.Description {
			case "expired access/refresh token":
				return resp, ErrExpiredToken
			default:
				return resp, e
			}
		}
		return resp, fmt.Errorf("salesforce api error: %s", string(bodyBytes))
	}
	if dstVal != nil {
		if json.Unmarshal(bodyBytes, dstVal); err != nil {
			return resp, err
		}
	}
	return resp, nil
}

func (c *Client) Query(ctx context.Context, query string, dstVal interface{}) error {
	urlStr := c.makeURL("/services/data/~/query?q=" + query)
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(ctx, req, &dstVal)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(dstVal)
}

type APIVersion struct {
	Label   string `json:"label"`
	URL     string `json:"url"`
	Version string `json:"version"`
}

type Error struct {
	ErrorMsg    string `json:"error"`
	Description string `json:"error_description"`
}

func (e Error) Error() string {
	return e.Description
}
