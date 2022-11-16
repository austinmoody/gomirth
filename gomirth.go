package gomirth

import "net/http"

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
