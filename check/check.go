package check

import (
	"net/http"
)

func Checking(req * http.Request) (string, error){
	if req.Method == http.MethodGet {
		req.RequestURI = req.RequestURI + "'"

		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return "", err
		}

		if resp.StatusCode == http.StatusInternalServerError {
			return "Found sql injection in GET parameter" + req.RequestURI, nil
		}
	}
	if req.Method == http.MethodPost {
		req.RequestURI = req.RequestURI + "'"
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return "", err
		}

		if resp.StatusCode == http.StatusInternalServerError {
			return "Found sql injection in POST URI parameter" + req.RequestURI, nil
		}
	}

	return "", nil
}