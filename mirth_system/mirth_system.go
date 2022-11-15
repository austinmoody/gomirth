package mirth_system

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"github.com/austinmoody/gomirth"
	"io"
	"net/http"
)

type MirthSystemInfo struct {
	JvmVersion      string `xml:"jvmVersion"`
	OsName          string `xml:"osName"`
	OsVersion       string `xml:"osVersion"`
	OsArchitecture  string `xml:"osArchitecture"`
	DatabaseName    string `xml:"dbName"`
	DatabaseVersion string `xml:"dbVersion"`
}

type MirthSystemStats struct {
	TimeStamp            gomirth.MirthTime `xml:"timestamp"`
	CpuUsagePercentage   float32           `xml:"cpuUsagePct"`
	AllocatedMemoryBytes int               `xml:"allocatedMemoryBytes"`
	FreeMemoryBytes      int               `xml:"freeMemoryBytes"`
	MaxMemoryBytes       int               `xml:"maxMemoryBytes"`
	DiskFreeBytes        int               `xml:"diskFreeBytes"`
	DiskTotalBytes       int               `xml:"diskTotalBytes"`
}

func GetSystemInfo(apiConfig gomirth.MirthApiConfig, jsessionId http.Cookie) (MirthSystemInfo, error) {

	mirthSystemInfo := MirthSystemInfo{}

	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "system/info")

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return mirthSystemInfo, err
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
		return mirthSystemInfo, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return mirthSystemInfo, err
	}

	err = resp.Body.Close()
	if err != nil {
		return mirthSystemInfo, err
	}

	err = xml.Unmarshal(data, &mirthSystemInfo)
	if err != nil {
		return mirthSystemInfo, err
	}

	return mirthSystemInfo, nil
}

func GetSystemStats(apiConfig gomirth.MirthApiConfig, jsessionId http.Cookie) (MirthSystemStats, error) {
	mirthSystemStats := MirthSystemStats{}

	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "system/stats")

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return mirthSystemStats, err
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
		return mirthSystemStats, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return mirthSystemStats, err
	}

	err = resp.Body.Close()
	if err != nil {
		return mirthSystemStats, err
	}

	err = xml.Unmarshal(data, &mirthSystemStats)
	if err != nil {
		return mirthSystemStats, err
	}

	return mirthSystemStats, nil
}
