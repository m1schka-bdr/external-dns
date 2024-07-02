/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// TODO: add logging
// TODO: add timeouts
package api

import (
	"bytes"
	"crypto/tls"
	b64 "encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// TODO: Ensure DNS Deploy Type Defaults to no-deploy instead of ""
type BluecatConfig struct {
	BluecatHost      string `json:"bluecatHost"`
	BluecatUsername  string `json:"bluecatUsername,omitempty"`
	BluecatPassword  string `json:"bluecatPassword,omitempty"`
	DNSConfiguration string `json:"dnsConfiguration"`
	DNSServerName    string `json:"dnsServerName"`
	DNSDeployType    string `json:"dnsDeployType"`
	View             string `json:"dnsView"`
	RootZone         string `json:"rootZone"`
	SkipTLSVerify    bool   `json:"skipTLSVerify"`
}

type BluecatV2Client interface {
	GetBluecatZones(zoneName string) ([]Zone, error)
	GetRecord(name string) (*GenericRecord, error)
	GetHostRecords(zone Zone, records *[]HostRecordEmbeddedAddresses) error
	GetCNAMERecords(zone Zone, records *[]AliasRecord) error
	GetHostRecord(name string, record *HostRecordEmbeddedAddresses) error
	GetCNAMERecord(name string, record *AliasRecord) error
	CreateHostRecord(zone Zone, req *HostRecordPostRequestBody) error
	CreateCNAMERecord(zone Zone, req *AliasRecordPostRequestBody) error
	DeleteHostRecord(name string, zone Zone) (err error)
	DeleteCNAMERecord(name string, zone Zone) (err error)
	GetTXTRecords(zone Zone, records *[]TXTRecord) error
	GetTXTRecord(name string, record *TXTRecord) error
	CreateTXTRecord(zone Zone, req *TXTRecordPostRequestBody) error
	DeleteTXTRecord(name string, zone Zone) error
	UpdateDynamicDeploy(zones []Zone, dynamicUpdateEnabled *bool) error
	DeployZone(zone Zone) error
}

// In BluecatV2 ist the CLient Implementation for te BluecatV2Client
type BluecatV2 struct {
	Token            string
	Host             string
	DNSConfiguration string
	View             string
	RootZone         string
	DNSServerName    string
	SkipTLSVerify    bool
}

// NewBluecatV2Client creates and returns a new Bluecat (v2) client
func NewBluecatV2(token, bluecatHost, dnsConfiguration, view, rootZone, dnsServerName string, skipTLSVerify bool) BluecatV2 {
	// TODO: do not handle defaulting here
	//
	// Right now the Bluecat doesn't seem to have a way to get the root zone from the API. If the user
	// doesn't provide one via the config file we'll assume it's 'com'
	if rootZone == "" {
		rootZone = "com"
	}
	return BluecatV2{
		Token:            token,
		Host:             bluecatHost,
		DNSConfiguration: dnsConfiguration,
		DNSServerName:    dnsServerName,
		View:             view,
		RootZone:         rootZone,
		SkipTLSVerify:    skipTLSVerify,
	}
}

// GetBluecatBluecatToken retrieves a Bluecat API token.
func GetBluecatV2Token(cfg BluecatConfig) (string, error) {
	var username string
	if cfg.BluecatUsername != "" {
		username = cfg.BluecatUsername
	}
	if v, ok := os.LookupEnv("BLUECAT_USERNAME"); ok {
		username = v
	}

	var password string
	if cfg.BluecatPassword != "" {
		password = cfg.BluecatPassword
	}
	if v, ok := os.LookupEnv("BLUECAT_PASSWORD"); ok {
		password = v
	}

	auth := UserSession{
		Username: &username,
		Password: &password,
	}
	body, err := json.Marshal(auth)
	if err != nil {
		return "", errors.Wrap(err, "could not unmarshal credentials for bluecat config")
	}
	url := cfg.BluecatHost + "/api/v2/sessions"

	response, err := executeHTTPRequest(cfg.SkipTLSVerify, http.MethodPost, url, "", bytes.NewBuffer(body))
	if err != nil {
		return "", errors.Wrap(err, "error obtaining API token from bluecat")
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return "", errors.Wrap(err, "failed to read login response from bluecat")
	}

	if response.StatusCode != http.StatusCreated {
		return "", errors.Errorf("got HTTP response code %v, detailed message: %v", response.StatusCode, string(responseBody))
	}

	session := UserSession{}
	err = json.Unmarshal(responseBody, &session)
	if err != nil {
		return "", errors.Wrap(err, "error unmarshaling json response (auth) from bluecat")
	}

	encodedBasicAuthtoken := b64.StdEncoding.EncodeToString([]byte(username + ":" + *session.ApiToken))

	return encodedBasicAuthtoken, nil
}

func (c BluecatV2) GetBluecatZones(zoneName string) ([]Zone, error) {
	url := c.Host + "/api/v2/zones?total=true&filter=absoluteName:contains('" + zoneName + "')"

	response, err := executeHTTPRequest(c.SkipTLSVerify, http.MethodGet, url, c.Token, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "error requesting zones from bluecat: %v, %v", url, zoneName)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read login response from bluecat")
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.Errorf("received http %v requesting zones from bluecat in zone %v, message %v", response.StatusCode, zoneName, string(responseBody))
	}

	zones := ZoneResponse{}
	err = json.Unmarshal(responseBody, &zones)

	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal json")
	}

	return zones.Zones, nil
}

func (c BluecatV2) GetHostRecords(zone Zone, records *[]HostRecordEmbeddedAddresses) error {

	url := c.Host + "/api/v2/zones/" + strconv.FormatInt(*zone.Id, 10) + "/resourceRecords?total=true&filter=type:eq('HostRecord')&fields=embed(addresses)"

	response, err := executeHTTPRequest(c.SkipTLSVerify, http.MethodGet, url, c.Token, nil)
	if err != nil {
		return errors.Wrapf(err, "error requesting host records from bluecat in zone %v", zone)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return errors.Errorf("received http %v requesting host records from bluecat in zone %v", response.StatusCode, zone)
	}

	hostResponse := HostRecordResponse{}

	json.NewDecoder(response.Body).Decode(&hostResponse)
	log.Debugf("Get Host Records Body: %+v", hostResponse)

	*records = append(*records, hostResponse.HostRecords...)

	return nil
}

func (c BluecatV2) GetCNAMERecords(zone Zone, records *[]AliasRecord) error {

	url := c.Host + "/api/v2/zones/" + strconv.FormatInt(*zone.Id, 10) + "/resourceRecords?total=true&filter=type:eq('AliasRecord')"

	response, err := executeHTTPRequest(c.SkipTLSVerify, http.MethodGet, url, c.Token, nil)
	if err != nil {
		return errors.Wrapf(err, "error retrieving cname records from bluecat in zone %v", zone)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return errors.Errorf("received http %v requesting cname records from bluecat in zone %v", response.StatusCode, zone)
	}

	cNameResponse := CNameRecordResponse{}
	json.NewDecoder(response.Body).Decode(&cNameResponse)
	log.Debugf("Get CName Records Response: %v", cNameResponse)

	*records = append(*records, cNameResponse.CNameRecords...)

	return nil
}

func (c BluecatV2) GetTXTRecords(zone Zone, records *[]TXTRecord) error {

	url := c.Host + "/api/v2/zones/" + strconv.FormatInt(*zone.Id, 10) + "/resourceRecords?total=true&filter=type:eq('TXTRecord')"

	log.Debugf("url: %s", url)

	response, err := executeHTTPRequest(c.SkipTLSVerify, http.MethodGet, url, c.Token, nil)
	if err != nil {
		return errors.Wrapf(err, "error retrieving txt records from bluecat in zone %v", zone)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		result := make(map[string]interface{})
		json.NewDecoder(response.Body).Decode(&result)
		log.Debugf("Response: %v", result)
		return errors.Errorf("received http %v requesting txt records from bluecat in zone %v", response.StatusCode, zone)
	}

	txtResponse := TXTRecordResponse{}

	log.Debugf("Get Txt Records response: %v", response)
	json.NewDecoder(response.Body).Decode(&txtResponse)
	log.Debugf("Get TXT Records Body: %v", txtResponse)

	*records = append(*records, txtResponse.TxtRecords...)

	return nil
}

func (c BluecatV2) GetHostRecord(name string, record *HostRecordEmbeddedAddresses) error {
	params := url.Values{}
	params.Add("total", "true")
	params.Add("filter", "absoluteName:eq('"+name+"') and type:eq('AliasRecord')")
	params.Add("fields", "embed(addresses)")

	url := c.Host + "/api/v2/resourceRecords?" + params.Encode()

	response, err := executeHTTPRequest(c.SkipTLSVerify, http.MethodGet, url, c.Token, nil)
	if err != nil {
		return errors.Wrapf(err, "error retrieving host record %v from bluecat", name)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return errors.Errorf("received http %v while retrieving host record %v from bluecat", response.StatusCode, name)
	}

	hostResponse := HostRecordResponse{}
	json.NewDecoder(response.Body).Decode(&hostResponse)
	log.Debugf("Get Host Records Body: %+v", hostResponse)

	*record = hostResponse.HostRecords[0]

	return nil
}

func (c BluecatV2) GetCNAMERecord(name string, record *AliasRecord) error {
	params := url.Values{}
	params.Add("total", "true")
	params.Add("filter", "absoluteName:eq('"+name+"') and type:eq('AliasRecord')")
	url := c.Host + "/api/v2/resourceRecords?" + params.Encode()

	response, err := executeHTTPRequest(c.SkipTLSVerify, http.MethodGet, url, c.Token, nil)
	if err != nil {
		return errors.Wrapf(err, "error retrieving cname record %v from bluecat", name)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(response.Body)
		// if u want to read the body many time
		// u need to restore
		// reader := io.NopCloser(bytes.NewReader(bodyBytes))
		if err != nil {
			log.Fatal(err)
		}
		bodyString := string(bodyBytes)
		log.Debugf("Get CNAME Record response: %v", bodyString)
		return errors.Errorf("received http %v while retrieving cname record %v from bluecat with body %s", response.StatusCode, name, bodyString)
	}

	cNameResponse := CNameRecordResponse{}
	json.NewDecoder(response.Body).Decode(&cNameResponse)
	log.Debugf("Get CName Records Response: %v", cNameResponse)

	*record = cNameResponse.CNameRecords[0]

	return nil
}

func (c BluecatV2) GetTXTRecord(name string, record *TXTRecord) error {
	params := url.Values{}
	params.Add("total", "true")
	params.Add("filter", "absoluteName:eq('"+name+"') and type:eq('TXTRecord')")
	url := c.Host + "/api/v2/resourceRecords?" + params.Encode()

	response, err := executeHTTPRequest(c.SkipTLSVerify, http.MethodGet, url, c.Token, nil)
	if err != nil {
		return errors.Wrapf(err, "error retrieving record %v from bluecat", name)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return errors.Errorf("received http %v while retrieving txt record %v from bluecat", response.StatusCode, name)
	}

	txtResponse := TXTRecordResponse{}

	log.Debugf("Get Txt Records response: %v", response)
	json.NewDecoder(response.Body).Decode(&txtResponse)
	log.Debugf("Get TXT Records Body: %v", txtResponse)

	*record = txtResponse.TxtRecords[0]

	return nil
}

func (c BluecatV2) GetRecord(name string) (*GenericRecord, error) {
	params := url.Values{}
	params.Add("total", "true")
	params.Add("filter", "absoluteName:eq('"+name+"')")
	url := c.Host + "/api/v2/resourceRecords?" + params.Encode()

	response, err := executeHTTPRequest(c.SkipTLSVerify, http.MethodGet, url, c.Token, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "error retrieving record %v from bluecat", name)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, errors.Errorf("received http %v while retrieving txt record %v from bluecat", response.StatusCode, name)
	}

	txtResponse := GenericRecordResponse{}

	log.Debugf("Get Txt Records response: %v", response)
	json.NewDecoder(response.Body).Decode(&txtResponse)
	log.Debugf("Get TXT Records Body: %v", txtResponse)

	if *txtResponse.Count == 0 {
		return nil, nil
	}

	if *txtResponse.Count > 1 {
		return nil, errors.Errorf("received too many results for a single get of name %v, expected 1, got %d", name, *txtResponse.Count)
	}

	record := &txtResponse.Records[0]

	return record, nil
}

// func (c BluecatV2) GetAddresses(id int64) {
// 	/api/v2/resourceRecords/581213/addresses
// }

func (c BluecatV2) CreateHostRecord(zone Zone, req *HostRecordPostRequestBody) error {
	var url, method string
	if req.Id == nil {
		method = http.MethodPost
		url = c.Host + "/api/v2/zones/" + strconv.FormatInt(*zone.Id, 10) + "/resourceRecords"
	} else {
		method = http.MethodPut
		url = c.Host + "/api/v2/resourceRecords/" + strconv.FormatInt(*req.Id, 10)
	}
	// here we have the zone, so we can calculate the name (absoluteName minus Zone)
	name := strings.TrimSuffix(*req.AbsoluteName, "."+*zone.AbsoluteName)
	req.AbsoluteName = nil
	req.Name = &name

	body, err := json.Marshal(req)
	if err != nil {
		return errors.Wrap(err, "could not marshal body for create host record")
	}

	response, err := executeHTTPRequest(c.SkipTLSVerify, method, url, c.Token, bytes.NewBuffer(body))
	if err != nil {
		return errors.Wrapf(err, "error creating host record %v in bluecat", req.AbsoluteName)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return errors.Errorf("received http %v while creating host record %v in bluecat", response.StatusCode, req.AbsoluteName)
	}

	return nil
}

func (c BluecatV2) CreateCNAMERecord(zone Zone, req *AliasRecordPostRequestBody) error {
	var url, method string
	if req.Id == nil {
		method = http.MethodPost
		url = c.Host + "/api/v2/zones/" + strconv.FormatInt(*zone.Id, 10) + "/resourceRecords"
	} else {
		method = http.MethodPut
		url = c.Host + "/api/v2/resourceRecords/" + strconv.FormatInt(*req.Id, 10)
	}
	c.mapLinkedCname(req)

	// here we have the zone, so we can calculate the name (absoluteName minus Zone)
	name := strings.TrimSuffix(*req.AbsoluteName, "."+*zone.AbsoluteName)
	req.AbsoluteName = nil
	req.Name = &name

	body, err := json.Marshal(req)
	if err != nil {
		return errors.Wrap(err, "could not marshal body for create cname record")
	}

	response, err := executeHTTPRequest(c.SkipTLSVerify, method, url, c.Token, bytes.NewBuffer(body))
	if err != nil {
		return errors.Wrapf(err, "error creating cname record %v in bluecat", req.AbsoluteName)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(response.Body)
		// if u want to read the body many time
		// u need to restore
		// reader := io.NopCloser(bytes.NewReader(bodyBytes))
		if err != nil {
			log.Fatal(err)
		}
		bodyString := string(bodyBytes)
		log.Debugf("Create CNAME Record response: %v", bodyString)
		return errors.Errorf("received http %v while creating cname record %v to alias %v in bluecat", response.StatusCode, req.AbsoluteName, req.LinkedRecord)
	}

	return nil
}

func (c BluecatV2) mapLinkedCname(req *AliasRecordPostRequestBody) error {
	// first, resolve the target locally
	linkedRecord, err := req.LinkedRecord.AsAliasRecordLinkedRecord0()
	if err != nil {
		return errors.Wrapf(err, "could not parse linked record")
	}
	cnameTarget := *linkedRecord.AbsoluteName
	// first, resolve the target locally
	targetRecord, err := c.GetRecord(cnameTarget)
	if err != nil {
		return errors.Wrapf(err, "error when resolving CNAME target %v", cnameTarget)
	}

	if targetRecord != nil {
		// we got something from bluecat, insert information
		linkedRecord.Id = targetRecord.Id
		linkedRecord.AbsoluteName = targetRecord.AbsoluteName
		tyype := InlinedResourceRecordType(*targetRecord.Type)
		linkedRecord.Type = &tyype
	} else {
		// nothing found. declaring it as external Host
		tyype := InlinedResourceRecordType(ExternalHostRecordTypeExternalHostRecord)
		linkedRecord.Type = &tyype

	}

	req.LinkedRecord.FromAliasRecordLinkedRecord0(linkedRecord)
	return nil
}

func (c BluecatV2) CreateTXTRecord(zone Zone, req *TXTRecordPostRequestBody) error {
	var url, method string
	if req.Id == nil {
		method = http.MethodPost
		url = c.Host + "/api/v2/zones/" + strconv.FormatInt(*zone.Id, 10) + "/resourceRecords"
	} else {
		method = http.MethodPut
		url = c.Host + "/api/v2/resourceRecords/" + strconv.FormatInt(*req.Id, 10)
	}

	// here we have the zone, so we can calculate the name (absoluteName minus Zone)
	name := strings.TrimSuffix(*req.AbsoluteName, "."+*zone.AbsoluteName)
	req.AbsoluteName = nil
	req.Name = &name
	body, err := json.Marshal(req)
	if err != nil {
		return errors.Wrap(err, "could not marshal body for create txt record")
	}

	response, err := executeHTTPRequest(c.SkipTLSVerify, method, url, c.Token, bytes.NewBuffer(body))
	if err != nil {
		return errors.Wrapf(err, "error creating txt record %v in bluecat", req.AbsoluteName)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(response.Body)
		// if u want to read the body many time
		// u need to restore
		// reader := io.NopCloser(bytes.NewReader(bodyBytes))
		if err != nil {
			log.Fatal(err)
		}
		bodyString := string(bodyBytes)
		log.Debugf("Create TXT Record response: %v", bodyString)
		return errors.Errorf("received http %v while creating txt record %v in bluecat", response.StatusCode, req.AbsoluteName)
	}

	return nil
}

func (c BluecatV2) DeleteHostRecord(name string, zone Zone) (err error) {
	record := HostRecordEmbeddedAddresses{}
	err = c.GetHostRecord(name, &record)
	if err != nil {
		return errors.Wrapf(err, "error getting host record %v from bluecat", name)
	}

	url := c.Host + "/api/v2/resourceRecords/" + strconv.FormatInt(*record.Id, 10) + "/"

	response, err := executeHTTPRequest(c.SkipTLSVerify, http.MethodDelete, url, c.Token, nil)
	if err != nil {
		return errors.Wrapf(err, "error deleting host record %v from bluecat", name)
	}

	if response.StatusCode != http.StatusNoContent {
		return errors.Errorf("received http %v while deleting host record %v from bluecat", response.StatusCode, name)
	}

	return nil
}

func (c BluecatV2) DeleteCNAMERecord(name string, zone Zone) (err error) {
	record := AliasRecord{}
	err = c.GetCNAMERecord(name, &record)
	if err != nil {
		return errors.Wrapf(err, "error getting cname record %v from bluecat", name)
	}

	url := c.Host + "/api/v2/resourceRecords/" + strconv.FormatInt(*record.Id, 10) + "/"

	response, err := executeHTTPRequest(c.SkipTLSVerify, http.MethodDelete, url, c.Token, nil)
	if err != nil {
		return errors.Wrapf(err, "error deleting cname record %v from bluecat", name)
	}
	if response.StatusCode != http.StatusNoContent {
		return errors.Errorf("received http %v while deleting cname record %v from bluecat", response.StatusCode, name)
	}

	return nil
}

func (c BluecatV2) DeleteTXTRecord(name string, zone Zone) (err error) {
	record := TXTRecord{}
	err = c.GetTXTRecord(name, &record)
	if err != nil {
		return errors.Wrapf(err, "error getting txt record %v from bluecat", name)
	}

	url := c.Host + "/api/v2/resourceRecords/" + strconv.FormatInt(*record.Id, 10) + "/"

	response, err := executeHTTPRequest(c.SkipTLSVerify, http.MethodDelete, url, c.Token, nil)
	if err != nil {
		return errors.Wrapf(err, "error deleting txt record %v from bluecat", name)
	}
	if response.StatusCode != http.StatusNoContent {
		return errors.Errorf("received http %v while deleting txt record %v from bluecat", response.StatusCode, name)
	}

	return nil
}

func (c BluecatV2) DeployZone(zone Zone) error {
	log.Infof("Executing deploy for zone %s", *zone.AbsoluteName)
	url := c.Host + "/api/v2/zones/" + strconv.FormatInt(*zone.Id, 10) + "/deployments"
	tyype := QuickDeploymentTypeQuickDeployment
	requestBody := QuickDeploymentPostRequestBody{
		Type: &tyype,
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		return errors.Wrap(err, "could not marshal body for quick deploy")
	}

	response, err := executeHTTPRequest(c.SkipTLSVerify, http.MethodPost, url, c.Token, bytes.NewBuffer(body))
	if err != nil {
		return errors.Wrap(err, "error executing quick deploy")
	}

	if response.StatusCode != http.StatusCreated {
		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			return errors.Wrap(err, "failed to read quick deploy response body")
		}
		return errors.Errorf("got HTTP response code %v, detailed message: %v", response.StatusCode, string(responseBody))
	}

	return nil
}

func (c BluecatV2) UpdateDynamicDeploy(zones []Zone, dynamicUpdateEnabled *bool) error {
	for _, zone := range zones {
		if *zone.DynamicUpdateEnabled {
			continue
		}
		url := c.Host + "/api/v2/zones/" + strconv.FormatInt(*zone.Id, 10)

		zone.DynamicUpdateEnabled = dynamicUpdateEnabled

		body, err := json.Marshal(zone)
		if err != nil {
			return errors.Wrapf(err, "could not marshal body for updating dynamic deploy for zone %s", zone)
		}

		response, err := executeHTTPRequest(c.SkipTLSVerify, http.MethodPut, url, c.Token, bytes.NewBuffer(body))
		if err != nil {
			return errors.Wrapf(err, "error updating dynamic deploy for zone: %v, %v", url, zone)
		}
		defer response.Body.Close()

		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			return errors.Wrap(err, "failed to update dynamic deploy response from bluecat")
		}

		if response.StatusCode != http.StatusOK {
			return errors.Errorf("received http %v update dynamic deploy in bluecat for zone %v, message %v", response.StatusCode, zone, string(responseBody))
		}

		t := true

		zone.DeploymentEnabled = &t
	}
	return nil
}

// IsValidDNSDeployType validates the deployment type provided by a users configuration is supported by the Bluecat Provider.
func IsValidDNSDeployType(deployType string) bool {
	validDNSDeployTypes := []string{"no-deploy", "quick-deploy", "dynamic"}
	for _, t := range validDNSDeployTypes {
		if t == deployType {
			return true
		}
	}
	return false
}

func executeHTTPRequest(skipTLSVerify bool, method, url, token string, body io.Reader) (*http.Response, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipTLSVerify,
			},
		},
	}
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if request.Method == http.MethodPost || request.Method == http.MethodPut {
		request.Header.Add("Content-Type", "application/json")
	}
	request.Header.Add("Accept", "application/hal+json")

	if token != "" {
		request.Header.Add("Authorization", "Basic "+token)
	}

	return httpClient.Do(request)
}
