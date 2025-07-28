package oidfed

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/luci/go-render/render"
	"github.com/vmihailenco/msgpack/v5"
	zutils "github.com/zachmann/go-utils"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/unixtime"
)

type marshalData struct {
	Data   []byte
	Object any
}

var entitystatementMarshalData = map[string]marshalData{
	"empty": {
		Data:   []byte(`{"exp":0,"iat":0,"iss":"","jwks":null,"sub":""}`),
		Object: EntityStatementPayload{},
	},
	"normal fields": {
		Data: []byte(`{"aud":"aud","authority_hints":["hint1","hint2"],"constraints":{"max_path_length":2,"naming_constraints":{"permitted":["foo"]},"allowed_entity_types":["openid_provider"]},"crit":["jti"],"exp":200,"iat":100,"iss":"issuer","jwks":null,"metadata":{"federation_entity":{"organization_name":"organization","organization_uri":"https://somewhere.com"},"openid_relying_party":{"application_type":"web","client_registration_types":["automatic"],"contacts":["contact@email.com"],"grant_types":["refresh_token","authorization_code"],"id_token_signed_response_alg":"ES512","redirect_uris":["https://redirect.to.somewher"],"response_types":["code"],"scope":"some scope"}},"metadata_policy":{"federation_entity":{"contacts":{"add":"value"}}},"metadata_policy_crit":["remove"],"sub":"subject"}`),
		Object: EntityStatementPayload{
			Issuer:    "issuer",
			Subject:   "subject",
			IssuedAt:  unixtime.Unixtime{Time: time.Unix(100, 0)},
			ExpiresAt: unixtime.Unixtime{Time: time.Unix(200, 0)},
			Audience:  "aud",
			AuthorityHints: []string{
				"hint1",
				"hint2",
			},
			Metadata: &Metadata{
				RelyingParty: &OpenIDRelyingPartyMetadata{
					Scope:         "some scope",
					RedirectURIS:  []string{"https://redirect.to.somewher"},
					ResponseTypes: []string{"code"},
					GrantTypes: []string{
						"refresh_token",
						"authorization_code",
					},
					ApplicationType:          "web",
					Contacts:                 []string{"contact@email.com"},
					IDTokenSignedResponseAlg: "ES512",
					ClientRegistrationTypes:  []string{"automatic"},
					wasSet: map[string]bool{
						"Scope":                    true,
						"RedirectURIS":             true,
						"ResponseTypes":            true,
						"GrantTypes":               true,
						"ApplicationType":          true,
						"Contacts":                 true,
						"IDTokenSignedResponseAlg": true,
						"ClientRegistrationTypes":  true,
					},
				},
				FederationEntity: &FederationEntityMetadata{
					OrganizationName: "organization",
					OrganizationURI:  "https://somewhere.com",
					wasSet: map[string]bool{
						"OrganizationName": true,
						"OrganizationURI":  true,
					},
				},
			},
			MetadataPolicy: &MetadataPolicies{
				FederationEntity: MetadataPolicy{
					"contacts": {
						"add": "value",
					},
				},
			},
			Constraints: &ConstraintSpecification{
				MaxPathLength: zutils.NewInt(2),
				NamingConstraints: &NamingConstraints{
					Permitted: []string{"foo"},
				},
				AllowedEntityTypes: []string{"openid_provider"},
			},
			CriticalExtensions: []string{"jti"},
			MetadataPolicyCrit: []PolicyOperatorName{"remove"},
			Extra:              nil,
		},
	},
	"extra fields": {
		Data: []byte(`{"exp":200,"extra-field":"value","foo":["bar"],"iat":100,"iss":"issuer","jwks":null,"sub":"subject"}`),
		Object: EntityStatementPayload{
			IssuedAt:  unixtime.Unixtime{Time: time.Unix(100, 0)},
			ExpiresAt: unixtime.Unixtime{Time: time.Unix(200, 0)},
			Issuer:    "issuer",
			Subject:   "subject",
			Extra: map[string]interface{}{
				"extra-field": "value",
				"foo":         []any{"bar"},
			},
		},
	},
}

func TestEntityStatementPayload_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		marshalData
	}{
		{
			name:        "empty",
			marshalData: entitystatementMarshalData["empty"],
		},
		{
			name:        "all normal fields",
			marshalData: entitystatementMarshalData["normal fields"],
		},
		{
			name:        "extra",
			marshalData: entitystatementMarshalData["extra fields"],
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				j, err := json.Marshal(test.Object)
				if err != nil {
					t.Error(err)
				}
				if !bytes.Equal(j, test.Data) {
					t.Errorf("Marshal result not as expected.\nExpected: %s\n     Got: %s", test.Data, j)
				}
			},
		)
	}
}

func TestEntityStatementPayload_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		marshalData
	}{
		{
			name:        "all normal fields",
			marshalData: entitystatementMarshalData["normal fields"],
		},
		{
			name:        "extra",
			marshalData: entitystatementMarshalData["extra fields"],
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				var result EntityStatementPayload
				err := json.Unmarshal(test.Data, &result)
				if err != nil {
					t.Errorf("%+v", err)
				}
				if !reflect.DeepEqual(test.Object, result) {
					t.Errorf(
						"Unmarshal result not as expected.\nExpected: %s\n     Got: %s\nMarshalled: %s\n  Original: %s\n",
						render.Render(test.Object),
						render.Render(result),
						test.Data,
						test.marshalData.Data,
					)
				}
			},
		)
	}
}

func TestEntityStatementMarshalAndUnmarshalJSON(t *testing.T) {
	// sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	tests := []struct {
		name string
		data EntityStatementPayload
	}{
		{
			name: "all normal fields",
			data: entitystatementMarshalData["normal fields"].Object.(EntityStatementPayload),
		},
		{
			name: "extra",
			data: entitystatementMarshalData["extra fields"].Object.(EntityStatementPayload),
		},
		// {
		// 	name: "jwks",
		// 	data: EntityStatementPayload{
		// 		JWKS: jwx.KeyToJWKS(sk.Public(), jwa.ES512),
		// 	},
		// }, // this is hard to compare
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				data, err := json.Marshal(&test.data)
				if err != nil {
					t.Fatal(err)
				}
				var result EntityStatementPayload
				if err = json.Unmarshal(data, &result); err != nil {
					t.Error(err)
				}
				if !reflect.DeepEqual(test.data, result) {
					t.Errorf(
						"Unmarshal result not as expected.\n"+
							"Original: %s\nMarshalled: %s\nGot: %s\n",
						render.Render(test.data),
						data,
						render.Render(result),
					)
					t.FailNow()
				}
			},
		)
	}
}

func TestEntityStatementMarshalAndUnmarshalMsgpack(t *testing.T) {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkJWKS, err := jwx.KeyToJWKS(sk.Public(), jwa.ES512())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data EntityStatementPayload
	}{
		// {
		// 	name: "all normal fields",
		// 	data: entitystatementMarshalData["normal fields"].Object.(EntityStatementPayload),
		// },
		// {
		// 	name: "extra",
		// 	data: entitystatementMarshalData["extra fields"].Object.(EntityStatementPayload),
		// },
		{
			name: "jwks",
			data: EntityStatementPayload{
				JWKS: pkJWKS,
			},
		}, // this is hard to compare
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				data, err := msgpack.Marshal(&test.data)
				if err != nil {
					t.Fatal(err)
				}
				var result EntityStatementPayload
				if err = msgpack.Unmarshal(data, &result); err != nil {
					t.Errorf("%+v", err)
				}
				if !reflect.DeepEqual(test.data, result) {
					t.Errorf(
						"Unmarshal result not as expected.\n"+
							"Original: %s\nMarshalled: %s\nGot: %s\n",
						render.Render(test.data.JWKS),
						data,
						render.Render(result.JWKS),
					)
					t.FailNow()
				}
			},
		)
	}
}
