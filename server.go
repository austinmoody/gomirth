package gomirth

/*
func (a *api) GetRhinoLanguageVersion() (string, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "server/rhinoLanguageVersion")

	header := http.Header{}
	header.Add("Accept", "application/xml")
	resp, err := MirthApiGetter(a.Configuration, mirthSession, apiUrl, header)
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
*/
