package oidfed

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jarcoal/httpmock"

	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/internal/http"
)

func setup() {
	httpmock.Activate()
	httpmock.ActivateNonDefault(http.Do().GetClient())
	internal.EnableDebugLogging()
	// cache.UseRedisCache(&redis.Options{Addr: "localhost:6379"})
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	// Ensure httpmock is properly deactivated and registry reset after all tests
	httpmock.DeactivateAndReset()
	os.Exit(code)
}

func TestTrustResolver_ResolveToValidChains(t *testing.T) {
	tests := []struct {
		name           string
		resolver       TrustResolver
		expectedChains TrustChains
	}{
		{
			name: "empty starting entity",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{
						{EntityID: ta1.EntityID},
						{EntityID: ta2.EntityID},
					}
					tas[0].SetJWKS(ta1.data.JWKS)
					tas[1].SetJWKS(ta2.data.JWKS)
					return tas
				}(),
				StartingEntity: "",
			},
		},
		{
			name: "empty TAs",
			resolver: TrustResolver{
				TrustAnchors:   TrustAnchors{},
				StartingEntity: rp1.EntityID,
			},
		},
		{
			name: "rp1: ta1",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: ta1.EntityID}}
					tas[0].SetJWKS(ta1.data.JWKS)
					return tas
				}(),
				StartingEntity: rp1.EntityID,
			},
			expectedChains: ta1Chains,
		},
		{
			name: "cached rp1: ta1",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: ta1.EntityID}}
					tas[0].SetJWKS(ta1.data.JWKS)
					return tas
				}(),
				StartingEntity: rp1.EntityID,
			},
			expectedChains: ta1Chains,
		},
		{
			name: "rp1: ta2",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: ta2.EntityID}}
					tas[0].SetJWKS(ta2.data.JWKS)
					return tas
				}(),
				StartingEntity: rp1.EntityID,
			},
			expectedChains: ta2Chains,
		},
		{
			name: "rp1: ta1,ta2",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{
						{EntityID: ta1.EntityID},
						{EntityID: ta2.EntityID},
					}
					tas[0].SetJWKS(ta1.data.JWKS)
					tas[1].SetJWKS(ta2.data.JWKS)
					return tas
				}(),
				StartingEntity: rp1.EntityID,
			},
			expectedChains: allChains,
		},
		{
			name: "proxy: ta1",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: ta1.EntityID}}
					tas[0].SetJWKS(ta1.data.JWKS)
					return tas
				}(),
				StartingEntity: proxy.EntityID,
			},
			expectedChains: allProxyChains,
		},
		{
			name: "constraints: pathlen 1: op2",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: taConstraintsPathLen.EntityID}}
					tas[0].SetJWKS(taConstraintsPathLen.data.JWKS)
					return tas
				}(),
				StartingEntity: op2.EntityID,
			},
			expectedChains: TrustChains{
				chainOP2IA2TACPL,
			},
		},
		{
			name: "constraints: pathlen 1: op1",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: taConstraintsPathLen.EntityID}}
					tas[0].SetJWKS(taConstraintsPathLen.data.JWKS)
					return tas
				}(),
				StartingEntity: op1.EntityID,
			},
			expectedChains: TrustChains{
				chainOP1IA2TACPL,
			},
		},
		{
			name: "constraints: pathlen 1: op3",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: taConstraintsPathLen.EntityID}}
					tas[0].SetJWKS(taConstraintsPathLen.data.JWKS)
					return tas
				}(),
				StartingEntity: op3.EntityID,
			},
			expectedChains: nil,
		},
		{
			name: "constraints: entity_type op: op2",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: taConstraintsEntityTypes.EntityID}}
					tas[0].SetJWKS(taConstraintsEntityTypes.data.JWKS)
					return tas
				}(),
				StartingEntity: op2.EntityID,
			},
			expectedChains: TrustChains{
				chainOP2IA2TACET,
			},
		},
		{
			name: "constraints: entity_type op: rp1",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: taConstraintsEntityTypes.EntityID}}
					tas[0].SetJWKS(taConstraintsEntityTypes.data.JWKS)
					return tas
				}(),
				StartingEntity: rp1.EntityID,
			},
			expectedChains: nil,
		},
		{
			name: "constraints: naming: op2",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: taConstraintsNaming.EntityID}}
					tas[0].SetJWKS(taConstraintsNaming.data.JWKS)
					return tas
				}(),
				StartingEntity: op2.EntityID,
			},
			expectedChains: nil,
		},
		{
			name: "constraints: naming: op3",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: taConstraintsNaming.EntityID}}
					tas[0].SetJWKS(taConstraintsNaming.data.JWKS)
					return tas
				}(),
				StartingEntity: op3.EntityID,
			},
			expectedChains: TrustChains{
				chainOP3IA1IA2TACN,
			},
		},
		{
			name: "constraints: naming: op1",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: taConstraintsNaming.EntityID}}
					tas[0].SetJWKS(taConstraintsNaming.data.JWKS)
					return tas
				}(),
				StartingEntity: op1.EntityID,
			},
			expectedChains: TrustChains{
				chainOP1IA2TACN,
				chainOP1IA1IA2TACN,
			},
		},
		{
			name: "constraints: naming: proxy",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: taConstraintsNaming.EntityID}}
					tas[0].SetJWKS(taConstraintsNaming.data.JWKS)
					return tas
				}(),
				StartingEntity: proxy.EntityID,
			},
			expectedChains: nil,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				chains := test.resolver.ResolveToValidChains()
				if !compareTrustChains(chains, test.expectedChains) {
					t.Log("resolved TrustChains are not what we expected")
					t.Log("Resolved:")
					for i, chain := range chains {
						t.Logf("BEGIN CHAIN %d\n", i)
						for _, c := range chain {
							t.Logf("%s -> %s\n", c.Issuer, c.Subject)
						}
						t.Logf("END CHAIN %d\n", i)
						t.Log()
					}
					t.Log("Expected:")
					for i, chain := range test.expectedChains {
						t.Logf("BEGIN CHAIN %d\n", i)
						for _, c := range chain {
							t.Logf("%s -> %s\n", c.Issuer, c.Subject)
						}
						t.Logf("END CHAIN %d\n", i)
						t.Log()
					}
					t.FailNow()
				}
			},
		)
	}
}

func TestTrustResolver_ResolveWithType(t *testing.T) {
	tests := []struct {
		name             string
		resolver         TrustResolver
		includedMetadata []string
	}{
		{
			name: "proxy: ta1",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: ta1.EntityID}}
					tas[0].SetJWKS(ta1.data.JWKS)
					return tas
				}(),
				StartingEntity: proxy.EntityID,
			},
			includedMetadata: []string{
				"federation_entity",
				"openid_provider",
				"openid_relying_party",
			},
		},
		{
			name: "proxy as op: ta1",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: ta1.EntityID}}
					tas[0].SetJWKS(ta1.data.JWKS)
					return tas
				}(),
				StartingEntity: proxy.EntityID,
				Types:          []string{"openid_provider"},
			},
			includedMetadata: []string{"openid_provider"},
		},
		{
			name: "proxy as rp: ta1",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: ta1.EntityID}}
					tas[0].SetJWKS(ta1.data.JWKS)
					return tas
				}(),
				StartingEntity: proxy.EntityID,
				Types:          []string{"openid_relying_party"},
			},
			includedMetadata: []string{"openid_relying_party"},
		},
		{
			name: "proxy as op_rp: ta1",
			resolver: TrustResolver{
				TrustAnchors: func() TrustAnchors {
					tas := TrustAnchors{{EntityID: ta1.EntityID}}
					tas[0].SetJWKS(ta1.data.JWKS)
					return tas
				}(),
				StartingEntity: proxy.EntityID,
				Types: []string{
					"openid_provider",
					"openid_relying_party",
				},
			},
			includedMetadata: []string{
				"openid_provider",
				"openid_relying_party",
			},
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				chains := test.resolver.ResolveToValidChains()
				if len(chains) == 0 {
					t.Fatal("no valid trust chain found")
				}
				for _, c := range chains {
					m, err := c.Metadata()
					if err != nil {
						t.Fatal(err)
					}
					fmt.Printf("%+v\n", m)

					val := reflect.ValueOf(m).Elem()
					typ := val.Type()
					for i := 0; i < val.NumField(); i++ {
						field := val.Field(i)
						fieldType := typ.Field(i)
						tag := fieldType.Tag.Get("json")

						// Handle the case where the tag includes ",omitempty" or other options
						tagParts := strings.Split(tag, ",")
						baseTag := tagParts[0]
						if baseTag == "" {
							// If no json tag is present, use the field name as the tag
							baseTag = fieldType.Name
						}

						if slices.Contains(test.includedMetadata, baseTag) {
							if field.IsZero() {
								t.Errorf("field %s is missing in metadata", baseTag)
							}
						} else {
							if !field.IsZero() {
								t.Errorf("field %s is not null in metadata", baseTag)
							}
						}
					}
				}
			},
		)
	}
}
