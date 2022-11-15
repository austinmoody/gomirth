package mirthapi_users

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/austinmoody/gomirth"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type MirthLoginStatus struct {
	Success    bool
	Status     string `xml:"status"`
	Message    string `xml:"message"`
	JsessionId string
}

func Login(apiConfig gomirth.MirthApiConfig, username string, password string) (MirthLoginStatus, error) {

	loginStatus := MirthLoginStatus{Success: false}

	// Login to Mirth API
	// Response Code 401 when bad user/pass
	// Response Code 200 when good user/pass
	// Response Code 500 if just a bad request
	userLoginUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "users/_login")

	userInfo := url.Values{}
	userInfo.Set("username", username)
	userInfo.Set("password", password)
	userInfoEncoded := userInfo.Encode()

	req, err := http.NewRequest("POST", userLoginUrl, strings.NewReader(userInfoEncoded))
	if err != nil {
		return loginStatus, err
	}

	req.Header.Add("Accept", "application/xml")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	c := &http.Client{}
	if apiConfig.IgnoreCert == true {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		c = &http.Client{Transport: tr}
	}

	resp, err := c.Do(req)
	if err != nil {
		return loginStatus, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return loginStatus, err
	}

	err = resp.Body.Close()
	if err != nil {
		return loginStatus, err
	}

	err = xml.Unmarshal(data, &loginStatus)
	if err != nil {
		return loginStatus, err
	}

	if resp.StatusCode == 200 && loginStatus.Status == "SUCCESS" {
		loginStatus.Success = true
		// We have successfully logged in, get JSESSIONID needed for future calls
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "JSESSIONID" {
				loginStatus.JsessionId = cookie.Value
			}
		}
	}

	return loginStatus, nil
}

func Logout(apiConfig gomirth.MirthApiConfig, jsessionId string) (bool, error) {
	// Mirth API Logout
	// 204 = successful, logout returns no message
	// 401 = attempt to logout when weren't logged in
	logoutUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "users/_logout")

	req, err := http.NewRequest("POST", logoutUrl, nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Accept", "application/xml")
	req.Header.Add("Content-Type", "application/xml")
	req.Header.Add("JSESSIONID", jsessionId)

	c := &http.Client{}
	if apiConfig.IgnoreCert == true {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		c = &http.Client{Transport: tr}
	}

	resp, err := c.Do(req)
	if err != nil {
		return false, err
	}

	if resp.StatusCode == 204 {
		return true, nil
	} else {
		return false, errors.New("Mirth API Logout Failure: Not Authenticated?")
	}

}
