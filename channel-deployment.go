package gomirth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// The channels/_deploy & channels/_undeploy returns a 500 on every Mirth server I've tried
// Not implementing... yet

func (a *api) RedeployAllChannels(returnErrors *bool) error {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "channels/_redeployAll")

	headers := http.Header{}
	headers.Add("Content-Type", "application/xml")
	headers.Add("Accept", "application/xml")

	var queryParams = make(url.Values)
	if returnErrors != nil {
		queryParams.Add("returnErrors", fmt.Sprintf("%t", returnErrors))
	}

	resp, err := a.MirthApiPoster(apiUrl, headers, queryParams)
	if err != nil {
		return err
	}

	if resp.Code != 204 {
		return errors.New(fmt.Sprintf("issue redeploying all mirth channels, status code returned = %d", resp.Code))
	}

	return nil

}

func (a *api) DeployChannel(channelId string, returnErrors bool) error {
	apiUrl := fmt.Sprintf("https://%s:%d%schannels/%s/_deploy", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, channelId)

	headers := http.Header{}
	headers.Add("Content-Type", "application/xml")
	headers.Add("Accept", "application/xml")

	var queryParams = make(url.Values)
	queryParams.Add("returnErrors", fmt.Sprintf("%t", returnErrors))

	resp, err := a.MirthApiPoster(apiUrl, headers, queryParams)
	if err != nil {
		return err
	}

	if resp.Code != 204 {
		return errors.New(fmt.Sprintf("issue deploying mirth channel with id '%s', status code returned = %d", channelId, resp.Code))
	}

	return nil
}

func (a *api) UndeployChannel(channelId string, returnErrors bool) error {
	apiUrl := fmt.Sprintf("https://%s:%d%schannels/%s/_undeploy", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, channelId)

	headers := http.Header{}
	headers.Add("Content-Type", "application/xml")
	headers.Add("Accept", "application/xml")

	var queryParams = make(url.Values)
	queryParams.Add("returnErrors", fmt.Sprintf("%t", returnErrors))

	resp, err := a.MirthApiPoster(apiUrl, headers, queryParams)
	if err != nil {
		return err
	}

	if resp.Code != 204 {
		return errors.New(fmt.Sprintf("issue undeploying mirth channel with id '%s', status code returned = %d", channelId, resp.Code))
	}

	return nil
}
