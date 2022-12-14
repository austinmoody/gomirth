package gomirth

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
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
	LastModified    MirthTime               `xml:"lastModified"`
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
	//XMLName struct{} `xml:"backgroundColor"`
	Red   int `xml:"red"`
	Green int `xml:"green"`
	Blue  int `xml:"blue"`
	Alpha int `xml:"alpha"`
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
	XMLName               struct{} `xml:"driverInfo"`
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

type ProtocolsAndCiphers struct {
	XMLName struct{}                `xml:"map"`
	Entries []ProtocolOrCipherEntry `xml:"entry"`
}

type ProtocolOrCipherEntry struct {
	XMLName       struct{} `xml:"entry"`
	EntryType     string   `xml:"string"`
	EntryContents []string `xml:"string-array>string"`
}

func (pc *ProtocolsAndCiphers) getEntryContents(entryType string) []string {
	var returnVal []string

	for _, entry := range pc.Entries {
		if entry.EntryType == entryType {
			returnVal = entry.EntryContents
		}
	}

	return returnVal
}

func (pc *ProtocolsAndCiphers) GetEnabledCipherSuites() []string {
	return pc.getEntryContents("enabledCipherSuites")
}

func (pc *ProtocolsAndCiphers) GetEnabledClientProtocols() []string {
	return pc.getEntryContents("enabledClientProtocols")
}

func (pc *ProtocolsAndCiphers) GetSupportedCipherSuites() []string {
	return pc.getEntryContents("supportedCipherSuites")
}

func (pc *ProtocolsAndCiphers) GetSupportedProtocols() []string {
	return pc.getEntryContents("supportedProtocols")
}

func (pc *ProtocolsAndCiphers) GetEnabledServerProtocols() []string {
	return pc.getEntryContents("enabledServerProtocols")
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

type Resources struct {
	XMLName struct{}   `xml:"list"`
	Entries []Resource `xml:"com.mirth.connect.plugins.directoryresource.DirectoryResourceProperties"`
}

type Resource struct {
	XMLName                  struct{} `xml:"com.mirth.connect.plugins.directoryresource.DirectoryResourceProperties"`
	PluginPointName          string   `xml:"pluginPointName"`
	Type                     string   `xml:"type"`
	Id                       string   `xml:"id"`
	Name                     string   `xml:"name"`
	Description              string   `xml:"description"`
	IncludeWithGlobalScripts bool     `xml:"includeWithGlobalScripts"`
	Directory                string   `xml:"directory"`
	DirectoryRecursion       bool     `xml:"directoryRecursion"`
}

func (r *Resource) DefaultType() string {
	return "Directory"
}

func (r *Resource) DefaultPluginPointName() string {
	return "Directory Resource"
}

type ServerSettings struct {
	XMLName                struct{}         `xml:"serverSettings"`
	EnvironmentName        string           `xml:"environmentName,omitempty"`
	ServerName             string           `xml:"serverName,omitempty"`
	ClearGlobalMap         bool             `xml:"clearGlobalMap,omitempty"`
	QueueBufferSize        int              `xml:"queueBufferSize,omitempty"`
	SmtpHost               string           `xml:"smtpHost,omitempty"`
	SmtpPort               string           `xml:"smtpPort,omitempty"`
	SmtpTimeout            string           `xml:"smtpTimeout,omitempty"`
	SmtpFrom               string           `xml:"smtpFrom,omitempty"`
	SmtpSecure             string           `xml:"smtpSecure,omitempty"`
	SmtpAuth               bool             `xml:"smtpAuth,omitempty"`
	SmtpUsername           string           `xml:"smtpUsername,omitempty"`
	SmtpPassword           string           `xml:"smtpPassword,omitempty"`
	DefaultBackgroundColor BackgroundColor  `xml:"defaultAdministratorBackgroundColor"`
	DefaultMetaDataColumns []MetaDataColumn `xml:"defaultMetaDataColumns>metaDataColumn"`
}

type MetaDataColumn struct {
	XMLName     struct{} `xml:"metaDataColumn"`
	Name        string   `xml:"name,omitempty"`
	Type        string   `xml:"type,omitempty"`
	MappingName string   `xml:"mappingName,omitempty"`
}

func (a *api) GenerateGuid() (string, error) {
	guid := ""

	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/_generateGUID")

	req, err := http.NewRequest("POST", apiUrl, nil)
	if err != nil {
		return guid, err
	}

	req.Header.Add("Accept", "text/plain")
	req.Header.Add("Content-Type", "application/xml")
	req.AddCookie(&a.Session.JsessionId)

	c := &http.Client{}
	if a.Configuration.IgnoreCert == true {
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

func (a *api) BuildDate() (time.Time, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/buildDate")

	headers := http.Header{}
	headers.Add("Accept", "text/plain")

	resp, err := a.MirthApiGetter(apiUrl, headers, nil)
	if err != nil {
		return time.Time{}, err
	}

	buildDate, err := time.Parse("Jan 02, 2006", string(resp.Body))
	if err != nil {
		return time.Time{}, err
	}

	return buildDate, nil

}

func (a *api) GetChannelDependencies() (ChannelDependencies, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/channelDependencies")

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return ChannelDependencies{}, err
	}

	req.Header.Add("Accept", "application/xml")
	req.AddCookie(&a.Session.JsessionId)

	c := &http.Client{}
	if a.Configuration.IgnoreCert == true {
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

func (a *api) UpdateChannelDependencies(channelDependencies ChannelDependencies) error {

	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/channelDependencies")

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
	req.AddCookie(&a.Session.JsessionId)

	c := &http.Client{}
	if a.Configuration.IgnoreCert == true {
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

func (a *api) GetChannelMetadata() (MetadataList, error) {

	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/channelMetadata")

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return MetadataList{}, err
	}

	req.Header.Add("Accept", "application/xml")
	req.AddCookie(&a.Session.JsessionId)

	c := &http.Client{}
	if a.Configuration.IgnoreCert == true {
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

func (a *api) UpdateChannelMetadata(channelMetadata MetadataList) error {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/channelMetadata")

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
	req.AddCookie(&a.Session.JsessionId)

	c := &http.Client{}
	if a.Configuration.IgnoreCert == true {
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

func (a *api) GetChannelTags() (ChannelTags, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/channelTags")

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return ChannelTags{}, err
	}

	req.Header.Add("Accept", "application/xml")
	req.AddCookie(&a.Session.JsessionId)

	c := &http.Client{}
	if a.Configuration.IgnoreCert == true {
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

func (a *api) UpdateChannelTags(channelTags ChannelTags) error {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/channelTags")

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
	req.AddCookie(&a.Session.JsessionId)

	c := &http.Client{}
	if a.Configuration.IgnoreCert == true {
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

func (a *api) GetCharacterSets() (CharacterSets, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/charsets")

	resp, err := a.MirthApiGetter(apiUrl, http.Header{}, nil)
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

func (a *api) GetConfigurationMap() (ConfigurationMap, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/configurationMap")

	resp, err := a.MirthApiGetter(apiUrl, http.Header{}, nil)
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

func (a *api) UpdateConfigurationMap(configurationMap ConfigurationMap) error {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/configurationMap")

	// Convert ConfigurationMap to XML to []byte
	mapXml, err := xml.Marshal(configurationMap)
	if err != nil {
		return err
	}

	headers := http.Header{}
	headers.Add("Content-Type", "application/xml")
	headers.Add("Accept", "application/xml")

	resp, err := a.MirthApiPutter(apiUrl, headers, mapXml)
	if err != nil {
		return err
	}

	if resp.Code != 204 {
		return errors.New(fmt.Sprintf("issue updating configuration map, status code returned = %d", resp.Code))
	}

	return nil
}

func (a *api) GetDatabaseDrivers() (DatabaseDrivers, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/databaseDrivers")

	resp, err := a.MirthApiGetter(apiUrl, http.Header{}, nil)
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

func (a *api) UpdateDatabaseDrivers(databaseDrivers DatabaseDrivers) error {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/databaseDrivers")

	// Convert DatabaseDrivers to XML to []byte
	mapXml, err := xml.Marshal(databaseDrivers)
	if err != nil {
		return err
	}

	headers := http.Header{}
	headers.Add("Content-Type", "application/xml")
	headers.Add("Accept", "application/xml")

	resp, err := a.MirthApiPutter(apiUrl, headers, mapXml)
	if err != nil {
		return err
	}

	if resp.Code != 204 {
		return errors.New(fmt.Sprintf("issue updating database drivers, status code returned = %d", resp.Code))
	}

	return nil
}

func (a *api) GetEncryptionSettings() (EncryptionSettings, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/encryption")

	resp, err := a.MirthApiGetter(apiUrl, http.Header{}, nil)
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

func (a *api) GetGlobalScripts() (GlobalScripts, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/globalScripts")

	resp, err := a.MirthApiGetter(apiUrl, http.Header{}, nil)
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

func (a *api) UpdateGlobalScripts(globalScripts GlobalScripts) error {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/globalScripts")

	// Convert DatabaseDrivers to XML to []byte
	mapXml, err := xml.Marshal(globalScripts)
	if err != nil {
		return err
	}

	headers := http.Header{}
	headers.Add("Content-Type", "application/xml")
	headers.Add("Accept", "application/xml")

	resp, err := a.MirthApiPutter(apiUrl, headers, mapXml)
	if err != nil {
		return err
	}

	if resp.Code != 204 {
		return errors.New(fmt.Sprintf("issue updating global scripts, status code returned = %d", resp.Code))
	}

	return nil
}

func (a *api) GetServerId() (string, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/id")

	header := http.Header{}
	header.Add("Accept", "text/plain")
	resp, err := a.MirthApiGetter(apiUrl, header, nil)
	if err != nil {
		return "", err
	}

	return string(resp.Body), nil
}

func (a *api) GetJvmName() (string, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/jvm")

	header := http.Header{}
	header.Add("Accept", "text/plain")
	resp, err := a.MirthApiGetter(apiUrl, header, nil)
	if err != nil {
		return "", err
	}

	return string(resp.Body), nil
}

func (a *api) GetPasswordRequirements() (PasswordRequirements, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/passwordRequirements")

	resp, err := a.MirthApiGetter(apiUrl, http.Header{}, nil)
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

func (a *api) GetProtocolsAndCiphers() (ProtocolsAndCiphers, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/protocolsAndCipherSuites")

	header := http.Header{}
	header.Add("Accept", "application/xml")
	resp, err := a.MirthApiGetter(apiUrl, header, nil)
	if err != nil {
		return ProtocolsAndCiphers{}, err
	}

	pAndC := ProtocolsAndCiphers{}
	err = xml.Unmarshal(resp.Body, &pAndC)
	if err != nil {
		return ProtocolsAndCiphers{}, err
	}

	return pAndC, nil
}

func (a *api) GetResources() (Resources, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/resources")

	header := http.Header{}
	header.Add("Accept", "application/xml")
	resp, err := a.MirthApiGetter(apiUrl, header, nil)
	if err != nil {
		return Resources{}, err
	}

	resources := Resources{}
	err = xml.Unmarshal(resp.Body, &resources)
	if err != nil {
		return Resources{}, err
	}

	return resources, nil
}

func (a *api) UpdateResources(resources Resources) error {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/resources")

	for _, resource := range resources.Entries {
		// Id, PluginPointName, and Type must not be blank
		// Typically PluginPointName = "Directory Resource"
		// Typically Type = "Directory"
		// However not defaulting these.
		if resource.Id == "" {
			return errors.New("invalid Resource found, missing Id")
		}

		if resource.Type == "" {
			return errors.New("invalid Resource found, missing Type")
		}

		if resource.PluginPointName == "" {
			return errors.New("invalid Resource found, missing PluginPointName")
		}
	}

	mapXml, err := xml.Marshal(resources)
	if err != nil {
		return err
	}

	headers := http.Header{}
	headers.Add("Content-Type", "application/xml")
	headers.Add("Accept", "application/xml")

	resp, err := a.MirthApiPutter(apiUrl, headers, mapXml)
	if err != nil {
		return err
	}

	if resp.Code != 204 {
		return errors.New(fmt.Sprintf("issue updating server resources, status code returned = %d", resp.Code))
	}

	return nil
}

func (a *api) ReloadResource(resourceId string) error {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s/%s/_reload", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/resources", resourceId)

	headers := http.Header{}
	headers.Add("Content-Type", "application/xml")
	headers.Add("Accept", "application/xml")

	resp, err := a.MirthApiPoster(apiUrl, headers, nil)
	if err != nil {
		return err
	}

	if resp.Code != 204 {
		return errors.New(fmt.Sprintf("issue reloading server resources for id %s, status code returned = %d", resourceId, resp.Code))
	}

	return nil
}

func (a *api) GetServerSettings() (ServerSettings, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/settings")

	header := http.Header{}
	header.Add("Accept", "application/xml")
	resp, err := a.MirthApiGetter(apiUrl, header, nil)
	if err != nil {
		return ServerSettings{}, err
	}

	ss := ServerSettings{}
	err = xml.Unmarshal(resp.Body, &ss)
	if err != nil {
		return ServerSettings{}, err
	}

	return ss, nil
}

func (a *api) UpdateServerSettings(serverSettings ServerSettings) error {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/settings")

	// Mirth Server Settings - Only 3 specific values available for MetaData columns
	/*
		NAME	TYPE	MAPPINGNAME
		SOURCE	STRING	mirth_source
		VERSION	STRING	mirth_version
		TYPE	STRING	mirth_type
	*/
	for _, mdc := range serverSettings.DefaultMetaDataColumns {
		switch mdc {
		case MetaDataColumn{Name: "SOURCE", Type: "STRING", MappingName: "mirth_source"}:
		case MetaDataColumn{Name: "VERSION", Type: "STRING", MappingName: "mirth_version"}:
		case MetaDataColumn{Name: "TYPE", Type: "STRING", MappingName: "mirth_type"}:
		default:
			return errors.New(fmt.Sprintf("invalid MetaData column - Name: %s Type: %s MappingName: %s", mdc.Name, mdc.Type, mdc.MappingName))
		}
	}
	mapXml, err := xml.Marshal(serverSettings)
	if err != nil {
		return err
	}

	headers := http.Header{}
	headers.Add("Content-Type", "application/xml")
	headers.Add("Accept", "application/xml")

	resp, err := a.MirthApiPutter(apiUrl, headers, mapXml)
	if err != nil {
		return err
	}

	if resp.Code != 204 {
		return errors.New(fmt.Sprintf("issue updating server settings, status code returned = %d", resp.Code))
	}

	return nil
}

func (a *api) GetRhinoLanguageVersion() (string, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/rhinoLanguageVersion")

	header := http.Header{}
	header.Add("Accept", "application/xml")
	resp, err := a.MirthApiGetter(apiUrl, header, nil)
	if err != nil {
		return "", err
	}

	rhinoVersion := ""

	err = xml.Unmarshal(resp.Body, &rhinoVersion)
	if err != nil {
		return "", err
	}

	return rhinoVersion, nil
}

func (a *api) GetServerStatus() (string, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/status")

	header := http.Header{}
	header.Add("Accept", "application/xml")
	resp, err := a.MirthApiGetter(apiUrl, header, nil)
	if err != nil {
		return "", err
	}

	serverStatus := ""

	err = xml.Unmarshal(resp.Body, &serverStatus)
	if err != nil {
		return "", err
	}

	return serverStatus, nil
}

func (a *api) GetServerTime() (MirthTime, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/time")

	header := http.Header{}
	header.Add("Accept", "application/xml")
	resp, err := a.MirthApiGetter(apiUrl, header, nil)
	if err != nil {
		return MirthTime{}, err
	}

	serverTime := MirthTime{}

	err = xml.Unmarshal(resp.Body, &serverTime)
	if err != nil {
		return MirthTime{}, err
	}

	return serverTime, nil
}
