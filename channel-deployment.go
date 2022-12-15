package gomirth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

func (a *api) RedeployAllChanels(returnErrors *bool) error {
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

func (a *api) UndeployChannel(channelIds []string, returnErrors *bool) error {
	return nil
}
