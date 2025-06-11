package dataencrypt

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

const (
	EnvDataEncryptServiceAddr       = "DataEncryptServiceAddr"
	EnvDataEncryptBasicAuth         = "DataEncryptBasicAuth"
	EnvDataEncryptTenantCode        = "DataEncryptTenantCode"
	EnvDataEncryptKeyCode           = "DataEncryptKeyCode"
	EnvDataEncryptAlgorithmParam    = "DataEncryptAlgorithmParam"
	EnvDataEncryptMacAlgorithmParam = "DataEncryptMacAlgorithmParam"

	DefaultDataEncryptAlgorithmParam    = "SM4/ECB/PKCS7Padding"
	DefaultDataEncryptMacAlgorithmParam = "SM4_MAC"
)

var (
	DataEncryptServiceAddr       string
	DataEncryptBasicAuth         string
	DataEncryptTenantCode        string
	DataEncryptKeyCode           string
	DataEncryptAlgorithmParam    string
	DataEncryptMacAlgorithmParam string
)

type MacResponse struct {
	Mac string `json:"mac"`
	Iv  string `json:"iv"`
}

func init() {
	DataEncryptServiceAddr = getEnvDefault(EnvDataEncryptServiceAddr, "")
	DataEncryptBasicAuth = getEnvDefault(EnvDataEncryptBasicAuth, "")
	DataEncryptTenantCode = getEnvDefault(EnvDataEncryptTenantCode, "")
	DataEncryptKeyCode = getEnvDefault(EnvDataEncryptKeyCode, "")
	DataEncryptAlgorithmParam = getEnvDefault(EnvDataEncryptAlgorithmParam, DefaultDataEncryptAlgorithmParam)
	DataEncryptMacAlgorithmParam = getEnvDefault(EnvDataEncryptMacAlgorithmParam, DefaultDataEncryptMacAlgorithmParam)
}

func getEnvDefault(key string, defVal string) string {
	val, ex := os.LookupEnv(key)
	if !ex {
		return defVal
	}
	return val
}

func checkGlobalVars() error {

	if DataEncryptServiceAddr == "" {
		return fmt.Errorf("the value of env %s is empty, check", EnvDataEncryptServiceAddr)
	}
	if DataEncryptBasicAuth == "" {
		return fmt.Errorf("the value of env %s is empty, check", EnvDataEncryptBasicAuth)
	}
	if DataEncryptTenantCode == "" {
		return fmt.Errorf("the value of env %s is empty, check", EnvDataEncryptTenantCode)
	}
	if DataEncryptKeyCode == "" {
		return fmt.Errorf("the value of env %s is empty, check", EnvDataEncryptKeyCode)
	}

	return nil
}

func Encrypt(data map[string]string) (map[string]string, error) {

	if err := checkGlobalVars(); err != nil {
		return nil, err
	}

	requestBody := map[string]interface{}{
		"keyCode": DataEncryptKeyCode,
		"algorithmParam": DataEncryptAlgorithmParam,
		"data": data,
	}

	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	httpClient := &http.Client{
		Transport: transport,
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/cipher/json/encrypt", DataEncryptServiceAddr), bytes.NewBuffer(requestBodyBytes))
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Basic " + DataEncryptBasicAuth)
	req.Header.Add("X-ICSP-Tenant-Code", DataEncryptTenantCode)

	response := struct {
		Response Response
		Data map[string]string `json:"data"`
	}{}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to request with %s, %s", response.Response.Code, response.Response.Message)
	}

	return response.Data, nil
}

func Decrypt(data map[string]string) (map[string]string, error) {

	if err := checkGlobalVars(); err != nil {
		return nil, err
	}

	requestBody := map[string]interface{}{
		"keyCode": DataEncryptKeyCode,
		"algorithmParam": DataEncryptAlgorithmParam,
		"encData": data,
	}

	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	httpClient := &http.Client{
		Transport: transport,
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/cipher/json/decrypt", DataEncryptServiceAddr), bytes.NewBuffer(requestBodyBytes))
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Basic " + DataEncryptBasicAuth)
	req.Header.Add("X-ICSP-Tenant-Code", DataEncryptTenantCode)

	response := struct {
		Response Response
		Data map[string]string `json:"data"`
	}{}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to request with %s, %s", response.Response.Code, response.Response.Message)
	}

	return response.Data, nil
}

func CalculateDataIntegrity(data string) (MacResponse, error) {

}

func VerifyDataIntegrity(data string, macResponse MacResponse) (bool, error) {

}
