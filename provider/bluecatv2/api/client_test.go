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

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBluecatNewGatewayClient(t *testing.T) {
	testToken := "exampleToken"
	testgateWayBluecatHost := "exampleBluecatHost"
	testDNSConfiguration := "exampleDNSConfiguration"
	testDNSServer := "exampleServer"
	testView := "testView"
	testZone := "example.com"
	testVerify := true

	client := NewBluecatV2(testToken, testgateWayBluecatHost, testDNSConfiguration, testView, testZone, testDNSServer, testVerify)

	if client.Token != testToken || client.Host != testgateWayBluecatHost || client.DNSConfiguration != testDNSConfiguration || client.View != testView || client.RootZone != testZone || client.SkipTLSVerify != testVerify {
		t.Fatal("Client values dont match")
	}
}

// func TestBluecatExpandZones(t *testing.T) {
// 	tests := map[string]struct {
// 		input string
// 		want  string
// 	}{
// 		"with subdomain":        {input: "example.com", want: "zones/com/zones/example/zones/"},
// 		"only top level domain": {input: "com", want: "zones/com/zones/"},
// 	}

// 	for name, tc := range tests {
// 		t.Run(name, func(t *testing.T) {
// 			got := expandZone(tc.input)
// 			diff := cmp.Diff(tc.want, got)
// 			if diff != "" {
// 				t.Fatalf(diff)
// 			}
// 		})
// 	}
// }

func TestBluecatValidDeployTypes(t *testing.T) {
	validTypes := []string{"no-deploy", "full-deploy"}
	invalidTypes := []string{"anything-else"}
	for _, i := range validTypes {
		if !IsValidDNSDeployType(i) {
			t.Fatalf("%s should be a valid deploy type", i)
		}
	}
	for _, i := range invalidTypes {
		if IsValidDNSDeployType(i) {
			t.Fatalf("%s should be a invalid deploy type", i)
		}
	}
}

func TestCreateTXTRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := TXTRecordPostRequestBody{}
		requestBodyBytes, _ := io.ReadAll(r.Body)
		err := json.Unmarshal(requestBodyBytes, &req)
		if err != nil {
			t.Fatalf("failed to unmarshal body for server full deploy")
		}
		if *req.AbsoluteName == "alreadyexists.test.com" {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer server.Close()

	s := func(s string) *string { return &s }

	tests := map[string]struct {
		config      BluecatV2
		zone        Zone
		record      TXTRecordPostRequestBody
		expectError bool
	}{
		"simple-success": {BluecatV2{Host: server.URL}, Zone{AbsoluteName: s("test.com")}, TXTRecordPostRequestBody{AbsoluteName: stringPointer("my.test.com"), Text: stringPointer("here is my text")}, false},
		"simple-failure": {BluecatV2{Host: server.URL}, Zone{AbsoluteName: s("test.com")}, TXTRecordPostRequestBody{AbsoluteName: stringPointer("alreadyexists.test.com"), Text: stringPointer("here is my text")}, true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := tc.config.CreateTXTRecord(tc.zone, &tc.record)
			if got != nil && !tc.expectError {
				t.Fatalf("expected error %v, received error %v", tc.expectError, got)
			}
		})
	}
}

func TestGetTXTRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.RequestURI, "doesnotexist") {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	tests := map[string]struct {
		config      BluecatV2
		name        string
		expectError bool
	}{
		"simple-success": {BluecatV2{Host: server.URL}, "mytxtrecord", false},
		"simple-failure": {BluecatV2{Host: server.URL}, "doesnotexist", true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			record := TXTRecord{}
			got := tc.config.GetTXTRecord(tc.name, &record)
			if got != nil && !tc.expectError {
				t.Fatalf("expected error %v, received error %v", tc.expectError, got)
			}
		})
	}
}

func TestDeleteTXTRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.RequestURI, "doesnotexist") {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	s := func(s string) *string { return &s }

	tests := map[string]struct {
		config      BluecatV2
		name        string
		zone        Zone
		expectError bool
	}{
		"simple-success": {BluecatV2{Host: server.URL}, "todelete", Zone{AbsoluteName: s("test.com")}, false},
		"simple-failure": {BluecatV2{Host: server.URL}, "doesnotexist", Zone{AbsoluteName: s("test.com")}, true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := tc.config.DeleteTXTRecord(tc.name, tc.zone)
			if got != nil && !tc.expectError {
				t.Fatalf("expected error %v, received error %v", tc.expectError, got)
			}
		})
	}
}

func TestServerFullDeploy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := BluecatServerFullDeployRequest{}
		requestBodyBytes, _ := io.ReadAll(r.Body)
		err := json.Unmarshal(requestBodyBytes, &req)
		if err != nil {
			t.Fatalf("failed to unmarshal body for server full deploy")
		}
		if req.ServerName == "serverdoesnotexist" {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer server.Close()

	tests := map[string]struct {
		config      BluecatV2
		expectError bool
	}{
		"simple-success": {BluecatV2{Host: server.URL, DNSServerName: "myserver"}, false},
		"simple-failure": {BluecatV2{Host: server.URL, DNSServerName: "serverdoesnotexist"}, true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := tc.config.ServerFullDeploy()
			if got != nil && !tc.expectError {
				t.Fatalf("expected error %v, received error %v", tc.expectError, got)
			}
		})
	}
}
