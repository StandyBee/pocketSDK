package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	pocketGetRquestTokenUrl = "https://getpocket.com/v3/oauth/request"
	authorizeUrl            = "https://getpocket.com/auth/authorize?request_token=%s&redirect_uri=%s"
	endpointAuth            = "https://getpocket.com/v3/oauth/authorize"
	endpointAdd             = "https://getpocket.com/v3/add"
)

type TokenRequest struct {
	ConsumerKey string `json:"consumer_key"`
	RedirectUri string `json:"redirect_uri"`
	State       string `json:"state"`
}

type AuthorizeRequest struct {
	ConsumerKey  string `json:"consumer_key"`
	RequestToken string `json:"code"`
}

type AddItemRequest struct {
	Url         string   `json:"url"`
	Title       string   `json:"title,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	ConsumerKey string   `json:"consumer_key"`
	AccessToken string   `json:"access_token"`
}

type AuthorizeResponse struct {
	AccessToken string `json:"access_token"`
	Username    string `json:"username"`
}

type Client struct {
	client      *http.Client
	consumerKey string
}

func NewClient(consumerKey string) (*Client, error) {
	if consumerKey == "" {
		return nil, errors.New("consumerKey is required")
	}

	client := Client{
		client:      &http.Client{},
		consumerKey: consumerKey,
	}

	return &client, nil
}

func (c *Client) GetRequestToken(ctx context.Context, redirectUri string) (string, error) {
	request := TokenRequest{
		ConsumerKey: c.consumerKey,
		RedirectUri: redirectUri,
		State:       "",
	}

	body, err := json.Marshal(request)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", pocketGetRquestTokenUrl, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}

	defer req.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	values, err := url.ParseQuery(string(respBody))
	if err != nil {
		return "", err
	}

	code := values.Get("code")
	if code == "" {
		return "", errors.New("code is empty in response")
	}

	return code, nil
}

func (c *Client) GetRedirectUrl(requestToken, redirectUrl string) (string, error) {
	if requestToken == "" || redirectUrl == "" {
		return "", errors.New("requestToken or redirectUrl is empty")
	}

	return fmt.Sprintf(authorizeUrl, requestToken, redirectUrl), nil
}

func (c *Client) Authorize(ctx context.Context, requestToken string) (*AuthorizeResponse, error) {
	if requestToken == "" {
		return nil, errors.New("requestToken is empty")
	}

	request := &AuthorizeRequest{
		ConsumerKey:  c.consumerKey,
		RequestToken: requestToken,
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpointAuth, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	values, err := url.ParseQuery(string(respBody))
	if err != nil {
		return nil, err
	}
	accessToken := values.Get("access_token")
	if accessToken == "" {
		return nil, errors.New("access_token is empty")
	}
	username := values.Get("username")

	response := &AuthorizeResponse{
		AccessToken: accessToken,
		Username:    username,
	}

	return response, nil
}

func (c *Client) Add(ctx context.Context, req *AddItemRequest) error {
	if req.Url == "" {
		return errors.New("url is empty")
	}

	if len(req.Tags) > 0 {
		req.Tags = []string{strings.Join(req.Tags, ",")}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, "POST", endpointAdd, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}

	return nil
}
