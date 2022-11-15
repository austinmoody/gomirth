package mirth_server

import (
	"crypto/tls"
	"fmt"
	"github.com/austinmoody/gomirth"
	"io"
	"net/http"
)

func GenerateGuid(apiConfig gomirth.MirthApiConfig, jsessionId http.Cookie) (string, error) {
	guid := ""

	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/_generateGUID")

	req, err := http.NewRequest("POST", apiUrl, nil)
	if err != nil {
		return guid, err
	}

	req.Header.Add("Accept", "text/plain")
	req.Header.Add("Content-Type", "application/xml")
	req.AddCookie(&jsessionId)

	c := &http.Client{}
	if apiConfig.IgnoreCert == true {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		c = &http.Client{Transport: tr}
	}

	resp, err := c.Do(req)
	if err != nil {
		return guid, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return guid, err
	}

	err = resp.Body.Close()
	if err != nil {
		return guid, err
	}

	return string(data), nil
}
