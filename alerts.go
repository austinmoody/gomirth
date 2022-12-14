package gomirth

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
)

type Alerts struct {
	XMLName struct{} `xml:"list"`
	Alerts  []Alert  `xml:"alertModel"`
}

type Alert struct {
	XMLName     struct{}         `xml:"alertModel"`
	Id          string           `xml:"id"`
	Name        string           `xml:"name"`
	Enabled     bool             `xml:"enabled"`
	Trigger     AlertTrigger     `xml:"trigger"`
	ActionGroup AlertActionGroup `xml:"actionGroups>alertActionGroup"`
}

type AlertTrigger struct {
	XMLName               struct{}              `xml:"trigger"`
	Class                 string                `xml:"class,attr"`
	NewChannelSource      bool                  `xml:"alertChannels>newChannelSource"`
	NewChannelDestination bool                  `xml:"alertChannels>newChannelDestination"`
	EnabledChannels       []string              `xml:"alertChannels>enabledChannels>string"`
	DisabledChannels      []string              `xml:"alertChannels>disabledChannels>string"`
	PartialChannels       []AlertPartialChannel `xml:"alertChannels>partialChannels>entry"`
	ErrorEventTypes       []string              `xml:"errorEventTypes>errorEventType"`
	Regex                 string                `xml:"regex"`
}

type AlertPartialChannel struct {
	XMLName                struct{} `xml:"entry"`
	ChannelId              string   `xml:"string"`
	EnabledConnectors      []int    `xml:"alertConnectors>enabledConnectors>int"`
	NewDestinationEnabled  *bool    `xml:"alertConnectors>enabledConnectors>null"`
	DisabledConnectors     []int    `xml:"alertConnectors>disabledConnectors>int"`
	NewDestinationDisabled *bool    `xml:"alertConnectors>disabledConnectors>null"`
}

type AlertActionGroup struct {
	Subject  string        `xml:"subject"`
	Template string        `xml:"template"`
	Actions  []AlertAction `xml:"actions>alertAction"`
}

type AlertAction struct {
	Protocol  string `xml:"protocol"`
	Recipient string `xml:"recipient"`
}

func (a *api) GetAlerts(alertIds []string) (Alerts, error) {
	apiUrl := fmt.Sprintf("https://%s:%d%s%s", a.Configuration.Host, a.Configuration.Port, a.Configuration.BaseUrl, "alerts")

	var queryParams = make(url.Values)
	//queryParams := []QueryParams{}
	if alertIds != nil {
		for _, alertId := range alertIds {
			//queryParams = append(queryParams, QueryParams{Key: "alertId", Value: alertId})
			queryParams.Add("alertId", alertId)
		}
	}

	headers := http.Header{}
	headers.Add("Accept", "application/xml")

	resp, err := a.MirthApiGetter(apiUrl, headers, queryParams)
	if err != nil {
		return Alerts{}, err
	}

	alerts := Alerts{}
	err = xml.Unmarshal(resp.Body, &alerts)
	if err != nil {
		return Alerts{}, err
	}

	return alerts, nil
}
