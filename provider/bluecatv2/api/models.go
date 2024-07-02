package api

import (
	"encoding/json"
	"fmt"

	"sigs.k8s.io/external-dns/endpoint"
)

//go:generate go run github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen --config=generate-config.yaml api.yaml

type ZoneResponse struct {
	Count      *int64 `json:"count,omitempty"`
	TotalCount *int64 `json:"totalCount,omitempty"`
	// in theory, we need to differentiate between
	// - $ref: '#/components/schemas/ENUMNumberZone'
	// - $ref: '#/components/schemas/ENUMZone'
	// - $ref: '#/components/schemas/ExternalHostsZone'
	// - $ref: '#/components/schemas/InternalRootZone'
	// - $ref: '#/components/schemas/ResponsePolicyZone'
	// - $ref: '#/components/schemas/Zone'
	// but we assume we always have a standard Zone
	Zones []Zone `json:"data,omitempty"`
}

type HostRecordResponse struct {
	Count      *int64 `json:"count,omitempty"`
	TotalCount *int64 `json:"totalCount,omitempty"`
	// in theory, we need to differentiate between
	// - $ref: '#/components/schemas/ENUMNumberZone'
	// - $ref: '#/components/schemas/ENUMZone'
	// - $ref: '#/components/schemas/ExternalHostsZone'
	// - $ref: '#/components/schemas/InternalRootZone'
	// - $ref: '#/components/schemas/ResponsePolicyZone'
	// - $ref: '#/components/schemas/Zone'
	// but we assume we always have a standard Zone
	HostRecords []HostRecordEmbeddedAddresses `json:"data,omitempty"`
}

type HostRecordEmbeddedAddresses struct {
	HostRecord
	EmbeddedAddresses HostAddresses `json:"_embedded,omitempty"`
}

type HostAddresses struct {
	Addresses []IPv4Address `json:"addresses,omitempty"`
}

type TXTRecordResponse struct {
	Count      *int64 `json:"count,omitempty"`
	TotalCount *int64 `json:"totalCount,omitempty"`
	// in theory, we need to differentiate between
	// - $ref: '#/components/schemas/ENUMNumberZone'
	// - $ref: '#/components/schemas/ENUMZone'
	// - $ref: '#/components/schemas/ExternalHostsZone'
	// - $ref: '#/components/schemas/InternalRootZone'
	// - $ref: '#/components/schemas/ResponsePolicyZone'
	// - $ref: '#/components/schemas/Zone'
	// but we assume we always have a standard Zone
	TxtRecords []TXTRecord `json:"data,omitempty"`
}

func (zz Zone) String() string {
	return fmt.Sprintf("Zone{AbsoluteName:%s,Id:%d}", *zz.AbsoluteName, *zz.Id)
}

func (tr TXTRecordResponse) String() string {
	return fmt.Sprintf("TXTRecordResponse{Data: %v,Count:%d}", tr.TxtRecords, *tr.Count)
}

func (tr TXTRecord) String() string {
	return fmt.Sprintf("TXTRecord{AbsoluteName: %s,Text:%s}", *tr.AbsoluteName, *tr.Text)
}

type CNameRecordResponse struct {
	Count      *int64 `json:"count,omitempty"`
	TotalCount *int64 `json:"totalCount,omitempty"`
	// in theory, we need to differentiate between
	// - $ref: '#/components/schemas/ENUMNumberZone'
	// - $ref: '#/components/schemas/ENUMZone'
	// - $ref: '#/components/schemas/ExternalHostsZone'
	// - $ref: '#/components/schemas/InternalRootZone'
	// - $ref: '#/components/schemas/ResponsePolicyZone'
	// - $ref: '#/components/schemas/Zone'
	// but we assume we always have a standard Zone
	CNameRecords []AliasRecord `json:"data,omitempty"`
}

// helper function as the union inside is not visible outside this package
func (lr *AliasRecord_LinkedRecord) UnmarshallAsGenericRecord() GenericRecord {
	res := GenericRecord{}
	json.Unmarshal(lr.union, &res)
	return res
}

type GenericRecordResponse struct {
	Count      *int64 `json:"count,omitempty"`
	TotalCount *int64 `json:"totalCount,omitempty"`
	// in theory, we need to differentiate between
	// - $ref: '#/components/schemas/AliasRecord'
	// - $ref: '#/components/schemas/ExternalHostRecord'
	// - $ref: '#/components/schemas/GenericRecord'
	// - $ref: '#/components/schemas/HINFORecord'
	// - $ref: '#/components/schemas/HostRecord'
	// - $ref: '#/components/schemas/HTTPSRecord'
	// - $ref: '#/components/schemas/MXRecord'
	// - $ref: '#/components/schemas/NAPTRRecord'
	// - $ref: '#/components/schemas/SRVRecord'
	// - $ref: '#/components/schemas/SVCBRecord'
	// - $ref: '#/components/schemas/TXTRecord'
	// - $ref: '#/components/schemas/URIRecord'
	Records []GenericRecord `json:"data,omitempty"`
}

func (r *HostRecordEmbeddedAddresses) FromEndpoint(ep *endpoint.Endpoint) error {
	ttl := int64(ep.RecordTTL)
	tyype := HostRecordType("HostRecord")
	comment, err := json.Marshal(ep.Labels)
	if err != nil {
		return err
	}
	// since we don't know whether this is beeing used for get or post, we both put the address in linked and embedded
	r.HostRecord = HostRecord{
		Type:         &tyype,
		AbsoluteName: &ep.DNSName,
		// IP4Address:   ep.Targets[0],
		Ttl: &ttl,
		Addresses: &[]Address{
			{
				Address: &ep.Targets[0],
			},
		},
		Comment: stringPointer(comment),
	}
	r.EmbeddedAddresses = HostAddresses{
		Addresses: []IPv4Address{
			{
				Address: &ep.Targets[0],
			},
		},
	}

	// id, err := extractId(ep)
	// if err != nil {
	// 	return err
	// }
	// r.Id = id
	return nil
}

func (r *AliasRecord) FromEndpoint(ep *endpoint.Endpoint) error {
	ttl := int64(ep.RecordTTL)
	tyype := AliasRecordType("AliasRecord")
	linked := AliasRecord_LinkedRecord{}
	linked.FromAliasRecordLinkedRecord0(InlinedResourceRecord{
		AbsoluteName: &ep.Targets[0],
	})
	comment, err := json.Marshal(ep.Labels)
	if err != nil {
		return err
	}
	r.Type = &tyype
	r.AbsoluteName = &ep.DNSName
	r.LinkedRecord = &linked
	r.Ttl = &ttl
	r.Comment = stringPointer(comment)

	// id, err := extractId(ep)
	// if err != nil {
	// 	return err
	// }
	// r.Id = id
	return nil
}

func (r *TXTRecord) FromEndpoint(ep *endpoint.Endpoint) error {
	tyype := TXTRecordType("TXTRecord")
	ttl := int64(ep.RecordTTL)
	comment, err := json.Marshal(ep.Labels)
	if err != nil {
		return err
	}
	r.Type = &tyype
	r.AbsoluteName = &ep.DNSName
	r.Ttl = &ttl
	r.Comment = stringPointer(comment)
	r.Text = &ep.Targets[0]

	// id, err := extractId(ep)
	// if err != nil {
	// 	return err
	// }
	// r.Id = id
	return nil
}

// func extractId(ep *endpoint.Endpoint) (*int64, error) {
// 	bluecatid, bluecatidexists := ep.GetProviderSpecificProperty("bluecatid")
// 	if bluecatidexists {
// 		i, err := strconv.ParseInt(bluecatid, 10, 64)
// 		if err != nil {
// 			return nil, err
// 		}
// 		return &i, nil
// 	}
// 	return nil, nil
// }

func stringPointer(input []byte) *string {
	s := string(input)
	return &s
}
