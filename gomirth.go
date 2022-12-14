package gomirth

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
)

type QueryParams struct {
	Key   string
	Value string
}

type MirthApiConfig struct {
	Host       string
	Port       int
	BaseUrl    string
	IgnoreCert bool
	//MirthVersion string
}

type MirthSession struct {
	Success    bool
	Status     string `xml:"status"`
	Message    string `xml:"message"`
	JsessionId http.Cookie
}

// MirthTime TODO add function to convert the Time from epoch to "something"
type MirthTime struct {
	Time     string `xml:"time"`
	TimeZone string `xml:"timezone"`
}

type MirthApiResponse struct {
	Code int
	Body []byte
}

type api struct {
	Configuration MirthApiConfig
	Session       MirthSession
}

func Api(host string, port int, baseUrl string, ignoreCert bool) api {
	return api{
		Configuration: MirthApiConfig{
			Host:       host,
			Port:       port,
			BaseUrl:    baseUrl,
			IgnoreCert: ignoreCert,
		},
	}
}

func (a *api) MirthApiPutter(apiUrl string, headers http.Header, toPut []byte) (MirthApiResponse, error) {

	req, err := http.NewRequest("PUT", apiUrl, bytes.NewReader(toPut))
	if err != nil {
		return MirthApiResponse{}, err
	}

	req.Header = headers
	req.AddCookie(&a.Session.JsessionId)

	c := &http.Client{}
	if a.Configuration.IgnoreCert == true {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		c = &http.Client{Transport: tr}
	}

	resp, err := c.Do(req)
	if err != nil {
		return MirthApiResponse{}, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return MirthApiResponse{}, err
	}

	err = resp.Body.Close()
	if err != nil {
		return MirthApiResponse{}, err
	}

	return MirthApiResponse{Code: resp.StatusCode, Body: data}, nil
}

func (a *api) MirthApiPoster(apiUrl string, headers http.Header) (MirthApiResponse, error) {
	req, err := http.NewRequest("POST", apiUrl, nil)
	if err != nil {
		return MirthApiResponse{}, err
	}

	if len(headers) == 0 {
		req.Header.Add("Accept", "application/xml")
		req.Header.Add("Content-Type", "application/xml")
	} else {
		req.Header = headers
	}
	req.AddCookie(&a.Session.JsessionId)

	c := &http.Client{}
	if a.Configuration.IgnoreCert == true {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		c = &http.Client{Transport: tr}
	}

	resp, err := c.Do(req)
	if err != nil {
		return MirthApiResponse{}, err
	}

	return MirthApiResponse{Code: resp.StatusCode, Body: nil}, nil
}

func (a *api) MirthApiGetter(apiUrl string, headers http.Header, queryParams url.Values) (MirthApiResponse, error) {

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return MirthApiResponse{}, err
	}

	if len(headers) == 0 {
		req.Header.Add("Accept", "application/xml")
		req.Header.Add("Content-Type", "application/xml")
	} else {
		req.Header = headers
	}
	req.AddCookie(&a.Session.JsessionId)

	if len(queryParams) > 0 {
		req.URL.RawQuery = queryParams.Encode()
	}

	c := &http.Client{}
	if a.Configuration.IgnoreCert == true {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		c = &http.Client{Transport: tr}
	}

	resp, err := c.Do(req)
	if err != nil {
		return MirthApiResponse{}, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return MirthApiResponse{}, err
	}

	err = resp.Body.Close()
	if err != nil {
		return MirthApiResponse{}, err
	}

	return MirthApiResponse{Code: resp.StatusCode, Body: data}, nil

}
