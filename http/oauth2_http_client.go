package authhttp

import (
	"net/http"
	"time"
)

const oauth2OutboundTimeout = 30 * time.Second

var oauth2OutboundHTTPClient = &http.Client{Timeout: oauth2OutboundTimeout}
