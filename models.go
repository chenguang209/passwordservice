package passwordservice

type Response struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type MacResponse struct {
	Mac string `json:"mac"`
	Iv  string `json:"iv"`
}

type McaVerifyResponse struct {
	VerifyResult bool `json:"verifyResult"`
}
