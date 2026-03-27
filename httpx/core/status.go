package core

type Status struct {
	Code int
}

func NewStatus(code int) Status {
	return Status{Code: code}
}

func (s Status) Phrase() string {
	return ReasonPhrase(s.Code)
}

func (s Status) IsSuccess() bool {
	return s.Code >= 200 && s.Code < 300
}

func (s Status) IsRedirect() bool {
	return s.Code >= 300 && s.Code < 400
}

func (s Status) IsClientError() bool {
	return s.Code >= 400 && s.Code < 500
}

func (s Status) IsServerError() bool {
	return s.Code >= 500 && s.Code < 600
}

func (s Status) IsError() bool {
	return s.Code >= 400
}

func (s Status) MayHaveBody() bool {
	return s.Code != 204 && s.Code != 304 && !(s.Code >= 100 && s.Code < 200)
}

func ReasonPhrase(code int) string {
	switch code {
	case 100:
		return "Continue"
	case 101:
		return "Switching Protocols"
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 202:
		return "Accepted"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 303:
		return "See Other"
	case 304:
		return "Not Modified"
	case 307:
		return "Temporary Redirect"
	case 308:
		return "Permanent Redirect"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 408:
		return "Request Timeout"
	case 409:
		return "Conflict"
	case 410:
		return "Gone"
	case 413:
		return "Payload Too Large"
	case 414:
		return "URI Too Long"
	case 415:
		return "Unsupported Media Type"
	case 418:
		return "I'm a teapot"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	default:
		return "Unknown Status"
	}
}
