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

type CharacterSets struct {
	XMLName      struct{} `xml:"list"`
	CharacterSet []string `xml:"string"`
}

type ConfigurationMap struct {
	XMLName struct{}                `xml:"map"`
	Entries []ConfigurationMapEntry `xml:"entry"`
}

type ConfigurationMapEntry struct {
	XMLName struct{} `xml:"entry"`
	Key     string   `xml:"string"`
	Value   string   `xml:"com.mirth.connect.util.ConfigurationProperty>value"`
}

type DatabaseDrivers struct {
	XMLName struct{}             `xml:"list"`
	Drivers []DatabaseDriverInfo `xml:"driverInfo"`
}

type DatabaseDriverInfo struct {
	XMLName               struct{} `xml:"driverInfo"'`
	ClassName             string   `xml:"className,omitempty"`
	Name                  string   `xml:"name,omitempty"`
	Template              string   `xml:"template,omitempty"`
	SelectLimit           string   `xml:"selectLimit,omitempty"`
	AlternativeClassNames []string `xml:"alternativeClassNames>string"`
}

type EncryptionSettings struct {
	XMLName             struct{} `xml:"com.mirth.connect.model.EncryptionSettings"`
	EncryptExport       bool     `xml:"encryptExport,omitempty"`
	EncryptProperties   bool     `xml:"encryptProperties,omitempty"`
	EncryptionAlgorithm string   `xml:"encryptionAlgorithm,omitempty"`
	EncryptionKeyLength int      `xml:"encryptionKeyLength,omitempty"`
	DigestAlgorithm     string   `xml:"digestAlgorithm,omitempty"`
	SecurityProvider    string   `xml:"securityProvider,omitempty"`
	SecretKey           string   `xml:"secretKey,omitempty"`
}

type GlobalScripts struct {
	XMLName struct{}       `xml:"map"`
	Scripts []GlobalScript `xml:"entry"`
}

type GlobalScript struct {
	XMLName  struct{} `xml:"entry"`
	Contents []string `xml:"string"`
}

func (gs *GlobalScripts) getScriptCode(scriptType string) string {
	scriptCode := ""
	for _, script := range gs.Scripts {
		if script.Contents[0] == scriptType {
			scriptCode = script.Contents[1]
		}
	}

	return scriptCode
}

func (gs *GlobalScripts) setScriptCode(scriptType string, scriptCode string) {
	for _, script := range gs.Scripts {
		if script.Contents[0] == scriptType {
			script.Contents[1] = scriptCode
		}
	}
}

func (gs *GlobalScripts) GetDeployScript() string {
	return gs.getScriptCode("Deploy")
}

func (gs *GlobalScripts) SetDeployScript(scriptCode string) {
	gs.setScriptCode("Deploy", scriptCode)
}

func (gs *GlobalScripts) GetUndeployScript() string {
	return gs.getScriptCode("Undeploy")
}

func (gs *GlobalScripts) SetUndeployScript(scriptCode string) {
	gs.setScriptCode("Undeploy", scriptCode)
}

func (gs *GlobalScripts) GetPostprocessorScript() string {
	return gs.getScriptCode("Postprocessor")
}

func (gs *GlobalScripts) SetPostprocessorScript(scriptCode string) {
	gs.setScriptCode("Postprocessor", scriptCode)
}

func (gs *GlobalScripts) GetPreprocessorScript() string {
	return gs.getScriptCode("Preprocessor")
}

func (gs *GlobalScripts) SetPreprocessorScript(scriptCode string) {
	gs.setScriptCode("Preprocessor", scriptCode)
}

type PasswordRequirements struct {
	XMLName        struct{} `xml:"passwordRequirements"`
	MinimumLength  int      `xml:"minLength"`
	MinimumUpper   int      `xml:"minUpper"`
	MinimumLower   int      `xml:"minLower"`
	MinimumNumeric int      `xml:"minNumeric"`
	MinimumSpecial int      `xml:"minSpecial"`
	RetryLimit     int      `xml:"retryLimit"`
	LockoutPeriod  int      `xml:"lockoutPeriod"`
	Expiration     int      `xml:"expiration"`
	GracePeriod    int      `xml:"gracePeriod"`
	ReusePeriod    int      `xml:"reusePeriod"`
	ReuseLimit     int      `xml:"reuseLimit"`
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

	headers := http.Header{}
	headers.Add("Accept", "text/plain")

	resp, err := gomirth.MirthApiGetter(apiConfig, mirthSession, apiUrl, headers)
	if err != nil {
		return time.Time{}, err
	}

	buildDate, err := time.Parse("Jan 02, 2006", string(resp.Body))
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

func GetCharacterSets(apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) (CharacterSets, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/charsets")

	resp, err := gomirth.MirthApiGetter(apiConfig, mirthSession, apiUrl, http.Header{})
	if err != nil {
		return CharacterSets{}, err
	}

	characterSets := CharacterSets{}
	err = xml.Unmarshal(resp.Body, &characterSets)
	if err != nil {
		return CharacterSets{}, err
	}

	return characterSets, nil
}

func GetConfigurationMap(apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) (ConfigurationMap, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/configurationMap")

	resp, err := gomirth.MirthApiGetter(apiConfig, mirthSession, apiUrl, http.Header{})
	if err != nil {
		return ConfigurationMap{}, err
	}

	configMap := ConfigurationMap{}
	err = xml.Unmarshal(resp.Body, &configMap)
	if err != nil {
		return ConfigurationMap{}, err
	}

	return configMap, nil
}

func UpdateConfigurationMap(configurationMap ConfigurationMap, apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) error {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/configurationMap")

	// Convert ConfigurationMap to XML to []byte
	mapXml, err := xml.Marshal(configurationMap)
	if err != nil {
		return err
	}

	headers := http.Header{}
	headers.Add("Content-Type", "application/xml")
	headers.Add("Accept", "application/xml")

	resp, err := gomirth.MirthApiPutter(apiConfig, mirthSession, apiUrl, headers, mapXml)
	if err != nil {
		return err
	}

	if resp.Code != 204 {
		return errors.New(fmt.Sprintf("issue updating configuration map, status code returned = %d", resp.Code))
	}

	return nil
}

func GetDatabaseDrivers(apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) (DatabaseDrivers, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/databaseDrivers")

	resp, err := gomirth.MirthApiGetter(apiConfig, mirthSession, apiUrl, http.Header{})
	if err != nil {
		return DatabaseDrivers{}, err
	}

	drivers := DatabaseDrivers{}
	err = xml.Unmarshal(resp.Body, &drivers)
	if err != nil {
		return DatabaseDrivers{}, err
	}

	return drivers, nil
}

func UpdateDatabaseDrivers(databaseDrivers DatabaseDrivers, apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) error {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/databaseDrivers")

	// Convert DatabaseDrivers to XML to []byte
	mapXml, err := xml.Marshal(databaseDrivers)
	if err != nil {
		return err
	}

	headers := http.Header{}
	headers.Add("Content-Type", "application/xml")
	headers.Add("Accept", "application/xml")

	resp, err := gomirth.MirthApiPutter(apiConfig, mirthSession, apiUrl, headers, mapXml)
	if err != nil {
		return err
	}

	if resp.Code != 204 {
		return errors.New(fmt.Sprintf("issue updating database drivers, status code returned = %d", resp.Code))
	}

	return nil
}

func GetEncryptionSettings(apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) (EncryptionSettings, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/encryption")

	resp, err := gomirth.MirthApiGetter(apiConfig, mirthSession, apiUrl, http.Header{})
	if err != nil {
		return EncryptionSettings{}, err
	}

	encryptionSettings := EncryptionSettings{}
	err = xml.Unmarshal(resp.Body, &encryptionSettings)
	if err != nil {
		return EncryptionSettings{}, err
	}

	return encryptionSettings, nil
}

func GetGlobalScripts(apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) (GlobalScripts, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/globalScripts")

	resp, err := gomirth.MirthApiGetter(apiConfig, mirthSession, apiUrl, http.Header{})
	if err != nil {
		return GlobalScripts{}, err
	}

	gs := GlobalScripts{}
	err = xml.Unmarshal(resp.Body, &gs)
	if err != nil {
		return GlobalScripts{}, err
	}

	return gs, nil
}

func UpdateGlobalScripts(globalScripts GlobalScripts, apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) error {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/globalScripts")

	// Convert DatabaseDrivers to XML to []byte
	mapXml, err := xml.Marshal(globalScripts)
	if err != nil {
		return err
	}

	headers := http.Header{}
	headers.Add("Content-Type", "application/xml")
	headers.Add("Accept", "application/xml")

	resp, err := gomirth.MirthApiPutter(apiConfig, mirthSession, apiUrl, headers, mapXml)
	if err != nil {
		return err
	}

	if resp.Code != 204 {
		return errors.New(fmt.Sprintf("issue updating global scripts, status code returned = %d", resp.Code))
	}

	return nil
}

func GetServerId(apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) (string, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/id")

	header := http.Header{}
	header.Add("Accept", "text/plain")
	resp, err := gomirth.MirthApiGetter(apiConfig, mirthSession, apiUrl, header)
	if err != nil {
		return "", err
	}

	return string(resp.Body), nil
}

func GetJvmName(apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) (string, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/jvm")

	header := http.Header{}
	header.Add("Accept", "text/plain")
	resp, err := gomirth.MirthApiGetter(apiConfig, mirthSession, apiUrl, header)
	if err != nil {
		return "", err
	}

	return string(resp.Body), nil
}

func GetPasswordRequirements(apiConfig gomirth.MirthApiConfig, mirthSession gomirth.MirthSession) (PasswordRequirements, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", apiConfig.Host, apiConfig.Port, apiConfig.BaseUrl, "server/passwordRequirements")

	resp, err := gomirth.MirthApiGetter(apiConfig, mirthSession, apiUrl, http.Header{})
	if err != nil {
		return PasswordRequirements{}, err
	}

	pwd := PasswordRequirements{}
	err = xml.Unmarshal(resp.Body, &pwd)
	if err != nil {
		return PasswordRequirements{}, err
	}

	return pwd, nil
}
