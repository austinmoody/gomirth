package gomirth

type MirthApiConfig struct {
	Host         string
	Port         int
	BaseUrl      string
	IgnoreCert   bool
	MirthVersion string
}

// MirthTime TODO add function to convert the Time from epoch to "something"
type MirthTime struct {
	Time     string `xml:"time"`
	TimeZone string `xml:"timezone"`
}
