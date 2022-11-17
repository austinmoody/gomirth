package mirth_server

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/austinmoody/gomirth"
	"io"
	"net/http"
	"strings"
	"time"
)

type ChannelDependencies struct {
	XMLName      struct{}            `xml:"set"`
	Dependencies []ChannelDependency `xml:"channelDependency"`
}

type ChannelDependency struct {
	DependentId  string `xml:"dependentId"`
	DependencyId string `xml:"dependencyId"`
}

type MetadataList struct {
	XMLName struct{}        `xml:"map"`
	List    []MetadataEntry `xml:"entry"`
}

type MetadataEntry struct {
	XMLName   struct{} `xml:"entry"`
	ChannelId string   `xml:"string"`
	Metadata  Metadata `xml:"com.mirth.connect.model.ChannelMetadata"`
}

type Metadata struct {
	XMLName         struct{}                `xml:"com.mirth.connect.model.ChannelMetadata"`
	Enabled         bool                    `xml:"enabled"`
	LastModified    gomirth.MirthTime       `xml:"lastModified"`
	PruningSettings MetadataPruningSettings `xml:"pruningSettings"`
}

type MetadataPruningSettings struct {
	XMLName           struct{} `xml:"pruningSettings"`
	ArchiveEnabled    bool     `xml:"archiveEnabled"`
	PruneMetaDataDays int      `xml:"pruneMetaDataDays,omitempty"`
	PruneContentDays  int      `xml:"pruneContentDays,omitempty"`
}

type ChannelTags struct {
	XMLName struct{}     `xml:"set"`
	Tags    []ChannelTag `xml:"channelTag"`
}

type ChannelTag struct {
	XMLName         struct{}        `xml:"channelTag"`
	Id              string          `xml:"id"`
	Name            string          `xml:"name"`
	Channels        []string        `xml:"channelIds>string"`
	BackgroundColor BackgroundColor `xml:"backgroundColor"`
}

type BackgroundColor struct {
	XMLName struct{} `xml:"backgroundColor"`
	Red     int      `xml:"red"`
	Green   int      `xml:"green"`
	Blue    int      `xml:"blue"`
	Alpha   int      `xml:"alpha"`
}

func GenerateGuid(apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) (string, error) {
	guid := ""

	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/_generateGUID")

	req, err := http.NewRequest("POST", apiUrl, nil)
	if err != nil {
		return guid, err
	}

	req.Header.Add("Accept", "text/plain")
	req.Header.Add("Content-Type", "application/xml")
	req.AddCookie(&mirthSession.JsessionId)

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

func BuildDate(apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) (time.Time, error) {

	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/buildDate")

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return time.Time{}, err
	}

	req.Header.Add("Accept", "text/plain")
	req.AddCookie(&mirthSession.JsessionId)

	c := &http.Client{}
	if apiConfig.IgnoreCert == true {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		c = &http.Client{Transport: tr}
	}

	resp, err := c.Do(req)
	if err != nil {
		return time.Time{}, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return time.Time{}, err
	}

	err = resp.Body.Close()
	if err != nil {
		return time.Time{}, err
	}

	buildDate, err := time.Parse("Jan 02, 2006", string(data))
	if err != nil {
		return time.Time{}, err
	}

	return buildDate, nil
}

func GetChannelDependencies(apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) (ChannelDependencies, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/channelDependencies")

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return ChannelDependencies{}, err
	}

	req.Header.Add("Accept", "application/xml")
	req.AddCookie(&mirthSession.JsessionId)

	c := &http.Client{}
	if apiConfig.IgnoreCert == true {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		c = &http.Client{Transport: tr}
	}

	resp, err := c.Do(req)
	if err != nil {
		return ChannelDependencies{}, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return ChannelDependencies{}, err
	}

	err = resp.Body.Close()
	if err != nil {
		return ChannelDependencies{}, err
	}

	channelDependencies := ChannelDependencies{}
	err = xml.Unmarshal(data, &channelDependencies)
	if err != nil {
		return ChannelDependencies{}, err
	}

	return channelDependencies, nil
}

func UpdateChannelDependencies(channelDependencies ChannelDependencies, apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) error {

	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/channelDependencies")

	channelDepsXml, err := xml.Marshal(channelDependencies)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", apiUrl, strings.NewReader(string(channelDepsXml)))
	if err != nil {
		return err
	}

	req.Header.Add("Accept", "application/xml")
	req.Header.Add("Content-Type", "application/xml")
	req.AddCookie(&mirthSession.JsessionId)

	c := &http.Client{}
	if apiConfig.IgnoreCert == true {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		c = &http.Client{Transport: tr}
	}

	resp, err := c.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode == 204 {
		return nil
	} else {
		return errors.New("issue updating mirth channel dependencies")
	}
}

func GetChannelMetadata(apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) (MetadataList, error) {

	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/channelMetadata")

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return MetadataList{}, err
	}

	req.Header.Add("Accept", "application/xml")
	req.AddCookie(&mirthSession.JsessionId)

	c := &http.Client{}
	if apiConfig.IgnoreCert == true {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		c = &http.Client{Transport: tr}
	}

	resp, err := c.Do(req)
	if err != nil {
		return MetadataList{}, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return MetadataList{}, err
	}

	err = resp.Body.Close()
	if err != nil {
		return MetadataList{}, err
	}

	metaDataList := MetadataList{}
	err = xml.Unmarshal(data, &metaDataList)
	if err != nil {
		return MetadataList{}, err
	}

	return metaDataList, nil

}

func UpdateChannelMetadata(channelMetadata MetadataList, apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) error {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/channelMetadata")

	metadataXml, err := xml.Marshal(channelMetadata)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", apiUrl, strings.NewReader(string(metadataXml)))
	if err != nil {
		return err
	}

	req.Header.Add("Accept", "application/xml")
	req.Header.Add("Content-Type", "application/xml")
	req.AddCookie(&mirthSession.JsessionId)

	c := &http.Client{}
	if apiConfig.IgnoreCert == true {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		c = &http.Client{Transport: tr}
	}

	resp, err := c.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode == 204 {
		return nil
	} else {
		return errors.New("issue updating mirth channel metadata")
	}
}

func GetChannelTags(apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) (ChannelTags, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/channelTags")

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return ChannelTags{}, err
	}

	req.Header.Add("Accept", "application/xml")
	req.AddCookie(&mirthSession.JsessionId)

	c := &http.Client{}
	if apiConfig.IgnoreCert == true {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		c = &http.Client{Transport: tr}
	}

	resp, err := c.Do(req)
	if err != nil {
		return ChannelTags{}, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return ChannelTags{}, err
	}

	err = resp.Body.Close()
	if err != nil {
		return ChannelTags{}, err
	}

	channelTags := ChannelTags{}
	err = xml.Unmarshal(data, &channelTags)
	if err != nil {
		return ChannelTags{}, err
	}

	return channelTags, nil
}

func UpdateChannelTags(channelTags ChannelTags, apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) error {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/channelTags")

	tagsUpdate, err := xml.Marshal(channelTags)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", apiUrl, strings.NewReader(string(tagsUpdate)))
	if err != nil {
		return err
	}

	req.Header.Add("Accept", "application/xml")
	req.Header.Add("Content-Type", "application/xml")
	req.AddCookie(&mirthSession.JsessionId)

	c := &http.Client{}
	if apiConfig.IgnoreCert == true {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		c = &http.Client{Transport: tr}
	}

	resp, err := c.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode == 204 {
		return nil
	} else {
		return errors.New("issue updating mirth channel tags")
	}
}
