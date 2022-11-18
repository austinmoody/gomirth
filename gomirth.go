package gomirth

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
)

type MirthApiConfig struct {
	Host         string
	Port         int
	BaseUrl      string
	IgnoreCert   bool
	MirthVersion string
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

func MirthApiPutter(apiConfig MirthApiConfig, mirthSession MirthSession, apiUrl string, headers http.Header, toPut []byte) (MirthApiResponse, error) {

	req, err := http.NewRequest("PUT", apiUrl, bytes.NewReader(toPut))
	if err != nil {
		return MirthApiResponse{}, err
	}

	req.Header = headers
	req.AddCookie(&mirthSession.JsessionId)

	c := &http.Client{}
	if apiConfig.IgnoreCert == true {
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

func MirthApiGetter(apiConfig MirthApiConfig, mirthSession MirthSession, apiUrl string, headers http.Header) (MirthApiResponse, error) {

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
	req.AddCookie(&mirthSession.JsessionId)

	c := &http.Client{}
	if apiConfig.IgnoreCert == true {
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
