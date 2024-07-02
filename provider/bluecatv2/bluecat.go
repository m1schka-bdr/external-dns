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

// TODO: Ensure we have proper error handling/logging for API calls to Bluecat. getBluecatGatewayToken has a good example of this
// TODO: Remove studdering
// TODO: Make API calls more consistent (eg error handling on HTTP response codes)
// TODO: zone-id-filter does not seem to work with our provider

package bluecatv2

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
	"sigs.k8s.io/external-dns/provider/bluecatv2/api"
)

// BluecatProvider implements the DNS provider for Bluecat DNS
type BluecatProvider struct {
	provider.BaseProvider
	domainFilter        endpoint.DomainFilter
	zoneIDFilter        provider.ZoneIDFilter
	dryRun              bool
	RootZone            string
	DNSConfiguration    string
	DNSServerName       string
	DNSDeployType       string
	View                string
	bluecatClient       api.BluecatV2Client
	TxtPrefix           string
	TxtSuffix           string
	EnableDynamicDeploy bool
}

type bluecatRecordSet struct {
	obj interface{}
	res interface{}
}

// NewBluecatProvider creates a new Bluecat provider.
//
// Returns a pointer to the provider or an error if a provider could not be created.
func NewBluecatProvider(configFile, dnsConfiguration, dnsServerName, dnsDeployType, dnsView, bluecatHost, rootZone, txtPrefix, txtSuffix string, domainFilter endpoint.DomainFilter, zoneIDFilter provider.ZoneIDFilter, dryRun, skipTLSVerify bool) (*BluecatProvider, error) {
	cfg := api.BluecatConfig{}
	contents, err := os.ReadFile(configFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg = api.BluecatConfig{
				BluecatHost:      bluecatHost,
				DNSConfiguration: dnsConfiguration,
				DNSServerName:    dnsServerName,
				DNSDeployType:    dnsDeployType,
				View:             dnsView,
				RootZone:         rootZone,
				SkipTLSVerify:    skipTLSVerify,
				BluecatUsername:  "",
				BluecatPassword:  "",
			}
		} else {
			return nil, errors.Wrapf(err, "failed to read Bluecat config file %v", configFile)
		}
	} else {
		err = json.Unmarshal(contents, &cfg)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse Bluecat JSON config file %v", configFile)
		}
	}

	if !api.IsValidDNSDeployType(cfg.DNSDeployType) {
		return nil, errors.Errorf("%v is not a valid deployment type", cfg.DNSDeployType)
	}

	dynamicUpdate := false

	if cfg.DNSDeployType == "dynamic" {
		dynamicUpdate = true
	}

	token, err := api.GetBluecatV2Token(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get API token from Bluecat")
	}
	bluecatClient := api.NewBluecatV2(token, cfg.BluecatHost, cfg.DNSConfiguration, cfg.View, cfg.RootZone, cfg.DNSServerName, cfg.SkipTLSVerify)

	provider := &BluecatProvider{
		domainFilter:        domainFilter,
		zoneIDFilter:        zoneIDFilter,
		dryRun:              dryRun,
		bluecatClient:       bluecatClient,
		DNSConfiguration:    cfg.DNSConfiguration,
		DNSServerName:       cfg.DNSServerName,
		DNSDeployType:       cfg.DNSDeployType,
		View:                cfg.View,
		RootZone:            cfg.RootZone,
		TxtPrefix:           txtPrefix,
		TxtSuffix:           txtSuffix,
		EnableDynamicDeploy: dynamicUpdate,
	}
	return provider, nil
}

// Records fetches Host, CNAME, and TXT records from bluecat
func (p *BluecatProvider) Records(ctx context.Context) (endpoints []*endpoint.Endpoint, err error) {
	zones, err := p.zones()
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch zones")
	}

	// Parsing Text records first, so we can get the owner from them.
	for _, zone := range zones {
		log.Debugf("fetching records from zone '%s'", zone)

		var resT []api.TXTRecord
		err = p.bluecatClient.GetTXTRecords(zone, &resT)
		if err != nil {
			return nil, errors.Wrapf(err, "could not fetch TXT records for zone: %v", zone)
		}
		for _, rec := range resT {
			tempEndpoint := endpoint.NewEndpoint(*rec.AbsoluteName, endpoint.RecordTypeTXT, *rec.Text)
			if rec.Comment != nil {
				var labels endpoint.Labels
				err := json.Unmarshal([]byte(*rec.Comment), &labels)
				if err != nil {
					log.Debugf("Could not unmarshall endpoint labels from Comment: %s, Error %s", *rec.Comment, err)
				}
				tempEndpoint.Labels = labels
			}
			endpoints = append(endpoints, tempEndpoint)
		}

		var resH []api.HostRecordEmbeddedAddresses
		err = p.bluecatClient.GetHostRecords(zone, &resH)
		if err != nil {
			return nil, errors.Wrapf(err, "could not fetch host records for zone: %v", zone)
		}
		var ep *endpoint.Endpoint
		for _, rec := range resH {
			// propMap := api.SplitProperties(*rec.Comment)
			ips := rec.EmbeddedAddresses.Addresses
			// ips := strings.Split(propMap["addresses"], ",")
			for _, ip := range ips {
				if rec.Ttl != nil {
					ep = endpoint.NewEndpointWithTTL(*rec.AbsoluteName, endpoint.RecordTypeA, endpoint.TTL(*rec.Ttl), *ip.Address)
				} else {
					ep = endpoint.NewEndpoint(*rec.AbsoluteName, endpoint.RecordTypeA, *ip.Address)
				}
				if rec.Comment != nil {
					var labels endpoint.Labels
					err := json.Unmarshal([]byte(*rec.Comment), &labels)
					if err != nil {
						log.Debugf("Could not unmarshall endpoint labels from Comment: %s, Error %s", *rec.Comment, err)
					}
					ep.Labels = labels
				}
			}
		}

		var resC []api.AliasRecord
		err = p.bluecatClient.GetCNAMERecords(zone, &resC)
		if err != nil {
			return nil, errors.Wrapf(err, "could not fetch CNAME records for zone: %v", zone)
		}

		for _, rec := range resC {
			// var linkedRecord = rec.LinkedRecord.UnmarshallAsGenericRecord()
			var linkedRecord, err = rec.LinkedRecord.AsAliasRecordLinkedRecord0()
			if err != nil {
				return nil, errors.Wrapf(err, "could not parse linked record: %v", rec.LinkedRecord)
			}
			if rec.Ttl != nil {
				ep = endpoint.NewEndpointWithTTL(*rec.AbsoluteName, endpoint.RecordTypeCNAME, endpoint.TTL(*rec.Ttl), *linkedRecord.AbsoluteName)
			} else {
				ep = endpoint.NewEndpoint(*rec.AbsoluteName, endpoint.RecordTypeCNAME, *linkedRecord.AbsoluteName)
			}
			if rec.Comment != nil {
				var labels endpoint.Labels
				err := json.Unmarshal([]byte(*rec.Comment), &labels)
				if err != nil {
					log.Debugf("Could not unmarshall endpoint labels from Comment: %s, Error %s", *rec.Comment, err)
				}
				ep.Labels = labels
			}
			endpoints = append(endpoints, ep)
		}
	}

	log.Debugf("fetched %d records from Bluecat", len(endpoints))
	return endpoints, nil
}

// ApplyChanges updates necessary zones and replaces old records with new ones
//
// Returns nil upon success and err is there is an error
func (p *BluecatProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	zones, err := p.zones()
	if err != nil {
		return err
	}
	log.Infof("zones is: %+v\n", zones)
	log.Infof("changes: %+v\n", changes)
	created, deleted := p.mapChanges(zones, changes)
	log.Infof("created: %+v\n", created)
	log.Infof("deleted: %+v\n", deleted)
	p.deleteRecords(deleted)
	p.createRecords(created)

	if p.DNSServerName != "" {
		if p.dryRun {
			log.Debug("Not executing deploy because this is running in dry-run mode")
		} else {
			switch p.DNSDeployType {
			case "quick-deploy":
				if !p.EnableDynamicDeploy {
					for _, zone := range zones {
						err := p.bluecatClient.DeployZone(zone)
						if err != nil {
							return err
						}
						log.Infof("Deployed Zone %v", zone)
					}
				}
			case "no-deploy":
				log.Debug("Not executing deploy because DNSDeployType is set to 'no-deploy'")
			}
		}
	} else {
		log.Debug("Not executing deploy because server name was not provided")
	}

	return nil
}

type bluecatChangeMap map[api.Zone][]*endpoint.Endpoint

func (p *BluecatProvider) mapChanges(zones []api.Zone, changes *plan.Changes) (bluecatChangeMap, bluecatChangeMap) {
	created := bluecatChangeMap{}
	deleted := bluecatChangeMap{}

	mapChange := func(changeMap bluecatChangeMap, change *endpoint.Endpoint) {
		zone := p.findZone(zones, change.DNSName)
		if zone == nil {
			log.Debugf("ignoring changes to '%s' because a suitable Bluecat DNS zone was not found", change.DNSName)
			return
		}
		changeMap[*zone] = append(changeMap[*zone], change)
	}

	for _, change := range changes.Delete {
		mapChange(deleted, change)
	}
	// for _, change := range changes.UpdateOld {
	// 	mapChange(deleted, change)
	// }
	for _, change := range changes.Create {
		mapChange(created, change)
	}
	for _, change := range changes.UpdateNew {
		mapChange(created, change)
	}

	return created, deleted
}

// findZone finds the most specific matching zone for a given record 'name' from a list of all zones
func (p *BluecatProvider) findZone(zones []api.Zone, name string) *api.Zone {
	var result *api.Zone

	for _, apizone := range zones {
		zoneName := *apizone.AbsoluteName
		if strings.HasSuffix(name, "."+zoneName) {
			if result == nil || len(zoneName) > len(*result.AbsoluteName) {
				result = &apizone
			}
		} else if strings.EqualFold(name, zoneName) {
			if result == nil || len(zoneName) > len(*result.AbsoluteName) {
				result = &apizone
			}
		}
	}

	return result
}

func (p *BluecatProvider) zones() ([]api.Zone, error) {
	log.Debugf("retrieving Bluecat zones for configuration: %s, view: %s", p.DNSConfiguration, p.View)
	var zones []api.Zone

	zonelist, err := p.bluecatClient.GetBluecatZones(p.RootZone)
	if err != nil {
		return nil, err
	}

	p.bluecatClient.UpdateDynamicDeploy(zonelist, &p.EnableDynamicDeploy)

	for _, zone := range zonelist {
		if !p.domainFilter.Match(*zone.Name) {
			continue
		}

		// TODO: match to absoluteName(string) not Id(int)"Failed to do run once
		if !p.zoneIDFilter.Match(strconv.FormatInt(*zone.Id, 10)) {
			continue
		}
		zones = append(zones, zone)
	}
	log.Debugf("found %d zones", len(zones))
	return zones, nil
}

func (p *BluecatProvider) createRecords(created bluecatChangeMap) {
	for zone, endpoints := range created {
		for _, ep := range endpoints {
			if p.dryRun {
				log.Infof("would creating/updating %s record named '%s' to '%s' for Bluecat DNS zone '%s'.",
					ep.RecordType,
					ep.DNSName,
					ep.Targets,
					zone,
				)
				continue
			}

			log.Infof("creating/updating %s record named '%s' to '%s' for Bluecat DNS zone '%s'.",
				ep.RecordType,
				ep.DNSName,
				ep.Targets,
				zone,
			)

			record, err := p.recordForEndpoint(ep)
			if err != nil {
				log.Errorf(
					"Failed to retrieve %s record named '%s' to '%s' for Bluecat DNS zone '%s': %v",
					ep.RecordType,
					ep.DNSName,
					ep.Targets,
					zone,
					err,
				)
				continue
			}
			switch ep.RecordType {
			case endpoint.RecordTypeA:
				rec := record.record.(*api.HostRecordEmbeddedAddresses)
				err = p.bluecatClient.CreateHostRecord(zone, &rec.HostRecord)
			case endpoint.RecordTypeCNAME:
				rec := record.record.(*api.AliasRecord)
				err = p.bluecatClient.CreateCNAMERecord(zone, rec)
			case endpoint.RecordTypeTXT:
				rec := record.record.(*api.TXTRecord)
				err = p.bluecatClient.CreateTXTRecord(zone, rec)
			}
			if err != nil {
				log.Errorf(
					"Failed to create %s record named '%s' to '%s' for Bluecat DNS zone '%s': %v",
					ep.RecordType,
					ep.DNSName,
					ep.Targets,
					zone,
					err,
				)
			}
		}
	}
}

func (p *BluecatProvider) deleteRecords(deleted bluecatChangeMap) {
	// run deletions first
	for zone, endpoints := range deleted {
		for _, ep := range endpoints {
			if p.dryRun {
				log.Infof("would delete %s record named '%s' for Bluecat DNS zone '%s'.",
					ep.RecordType,
					ep.DNSName,
					zone,
				)
				continue
			} else {
				log.Infof("deleting %s record named '%s' for Bluecat DNS zone '%s'.",
					ep.RecordType,
					ep.DNSName,
					zone,
				)

				recordSet, err := p.recordSet(ep, true)
				if err != nil {
					log.Errorf(
						"Failed to retrieve %s record named '%s' to '%s' for Bluecat DNS zone '%s': %v",
						ep.RecordType,
						ep.DNSName,
						ep.Targets,
						zone,
						err,
					)
					continue
				}

				switch ep.RecordType {
				case endpoint.RecordTypeA:
					for _, record := range *recordSet.res.(*[]api.HostRecord) {
						err = p.bluecatClient.DeleteHostRecord(*record.AbsoluteName, zone)
					}
				case endpoint.RecordTypeCNAME:
					for _, record := range *recordSet.res.(*[]api.AliasRecord) {
						err = p.bluecatClient.DeleteCNAMERecord(*record.AbsoluteName, zone)
					}
				case endpoint.RecordTypeTXT:
					for _, record := range *recordSet.res.(*[]api.TXTRecord) {
						err = p.bluecatClient.DeleteTXTRecord(*record.AbsoluteName, zone)
					}
				}
				if err != nil {
					log.Errorf("Failed to delete %s record named '%s' for Bluecat DNS zone '%s': %v",
						ep.RecordType,
						ep.DNSName,
						zone,
						err)
				}
			}
		}
	}
}

type Record struct {
	record interface{}
}

func (p *BluecatProvider) recordForEndpoint(ep *endpoint.Endpoint) (*Record, error) {
	// check existing record, get id if it exists, so we can update
	existing, err := p.bluecatClient.GetRecord(ep.DNSName)
	if err != nil {
		return nil, err
	}

	var id *int64
	if existing != nil {
		id = existing.Id
	}

	var result interface{}

	switch ep.RecordType {
	case endpoint.RecordTypeA:
		obj := &api.HostRecordEmbeddedAddresses{
			HostRecord: api.HostRecord{
				Id: id,
			},
		}
		err := obj.FromEndpoint(ep)
		if err != nil {
			return nil, err
		}
		result = obj

	case endpoint.RecordTypeCNAME:
		obj := &api.AliasRecord{
			Id: id,
		}
		err := obj.FromEndpoint(ep)
		if err != nil {
			return nil, err
		}
		result = obj
	case endpoint.RecordTypeTXT:
		obj := &api.TXTRecord{
			Id: id,
		}
		err := obj.FromEndpoint(ep)
		if err != nil {
			return nil, err
		}
		result = obj
	}
	return &Record{result}, nil
}

func (p *BluecatProvider) recordSet(ep *endpoint.Endpoint, getObject bool) (bluecatRecordSet, error) {
	recordSet := bluecatRecordSet{}
	switch ep.RecordType {
	case endpoint.RecordTypeA:
		var res []api.HostRecordEmbeddedAddresses
		obj := &api.HostRecordEmbeddedAddresses{}
		err := obj.FromEndpoint(ep)
		if err != nil {
			return bluecatRecordSet{}, err
		}

		if getObject {
			var record api.HostRecordEmbeddedAddresses
			err := p.bluecatClient.GetHostRecord(ep.DNSName, &record)
			if err != nil {
				return bluecatRecordSet{}, err
			}
			res = append(res, record)
		}
		recordSet = bluecatRecordSet{
			obj: obj,
			res: &res,
		}
	case endpoint.RecordTypeCNAME:
		var res []api.AliasRecord
		obj := &api.AliasRecord{}
		err := obj.FromEndpoint(ep)
		if err != nil {
			return bluecatRecordSet{}, err
		}

		if getObject {
			var record api.AliasRecord
			err := p.bluecatClient.GetCNAMERecord(ep.DNSName, &record)
			if err != nil {
				return bluecatRecordSet{}, err
			}
			res = append(res, record)
		}
		recordSet = bluecatRecordSet{
			obj: obj,
			res: &res,
		}
	case endpoint.RecordTypeTXT:
		var res []api.TXTRecord
		obj := &api.TXTRecord{}
		err := obj.FromEndpoint(ep)
		if err != nil {
			return bluecatRecordSet{}, err
		}
		if getObject {
			var record api.TXTRecord
			err := p.bluecatClient.GetTXTRecord(ep.DNSName, &record)
			if err != nil {
				return bluecatRecordSet{}, err
			}
			res = append(res, record)
		}
		recordSet = bluecatRecordSet{
			obj: obj,
			res: &res,
		}
	}
	return recordSet, nil
}

func stringPointer(input []byte) *string {
	s := string(input)
	return &s
}

func (p *BluecatProvider) AdjustEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
	return endpoints, nil
}
