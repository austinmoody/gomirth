package mirth_user

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
	JsessionId http.Cookie
}

type MirthUsers struct {
	Users []MirthUser `xml:"user"`
}

type MirthUser struct {
	Id               string            `xml:"id"`
	Username         string            `xml:"username"`
	Email            string            `xml:"email"`
	FirstName        string            `xml:"firstName"`
	LastName         string            `xml:"lastName"`
	Organization     string            `xml:"organization"`
	Description      string            `xml:"description"`
	PhoneNumber      string            `xml:"phoneNumber"`
	Industry         string            `xml:"industry"`
	LastLogin        gomirth.MirthTime `xml:"lastLogin"`
	StrikeCount      int               `xml:"strikeCount"`
	GracePeriodStart gomirth.MirthTime `xml:"gracePeriodStart"`
	LastStrike       gomirth.MirthTime `xml:"lastStrikeTime"`
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
				loginStatus.JsessionId = *cookie
			}
		}
	}

	return loginStatus, nil
}

func Logout(apiConfig gomirth.MirthApiConfig, jsessionId http.Cookie) (bool, error) {
	// Mirth API Logout
	// 204 = successful, logout returns no message
	// 401 = attempt to log out when weren't logged in
	logoutUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "users/_logout")

	req, err := http.NewRequest("POST", logoutUrl, nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Accept", "application/xml")
	req.Header.Add("Content-Type", "application/xml")
	req.AddCookie(&jsessionId)

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
		return false, errors.New("mirth api logout failure: not authenticated")
	}

}

func GetUsers(apiConfig gomirth.MirthApiConfig, jsessionId http.Cookie) (MirthUsers, error) {

	mirthUsers := MirthUsers{}

	usersUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "users")

	req, err := http.NewRequest("GET", usersUrl, nil)
	if err != nil {
		return mirthUsers, err
	}

	req.Header.Add("Accept", "application/xml")
	req.AddCookie(&jsessionId)

	c := &http.Client{}
	if apiConfig.IgnoreCert == true {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		c = &http.Client{Transport: tr}
	}

	resp, err := c.Do(req)
	if err != nil {
		return mirthUsers, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return mirthUsers, err
	}

	err = resp.Body.Close()
	if err != nil {
		return mirthUsers, err
	}

	err = xml.Unmarshal(data, &mirthUsers)
	if err != nil {
		return mirthUsers, err
	}

	return mirthUsers, nil
}
