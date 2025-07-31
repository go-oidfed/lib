package oidfed

import (
	"testing"

	arrops "github.com/adam-hanna/arrayOperations"
	zutils "github.com/zachmann/go-utils"

	"github.com/go-oidfed/lib/oidfedconst"
)

var rp1 = newMockRP(
	"https://rp1.example.com",
	&OpenIDRelyingPartyMetadata{ClientRegistrationTypes: []string{oidfedconst.ClientRegistrationTypeAutomatic}},
)

var op1 = newMockOP(
	"https://op1.example.com",
	&OpenIDProviderMetadata{
		ClientRegistrationTypesSupported: []string{oidfedconst.ClientRegistrationTypeAutomatic},
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
			"address",
		},
	},
)
var op2 = newMockOP(
	"https://op2.example.com",
	&OpenIDProviderMetadata{
		ClientRegistrationTypesSupported: []string{oidfedconst.ClientRegistrationTypeAutomatic},
		ScopesSupported: []string{
			"openid",
			"profile",
		},
	},
)
var op3 = newMockOP(
	"https://op3.example.com",
	&OpenIDProviderMetadata{
		ClientRegistrationTypesSupported: []string{oidfedconst.ClientRegistrationTypeAutomatic},
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
		},
	},
)

var proxy = newMockProxy(
	"https://proxy.example.org",
	&OpenIDRelyingPartyMetadata{ClientRegistrationTypes: []string{oidfedconst.ClientRegistrationTypeAutomatic}},
	&OpenIDProviderMetadata{
		ClientRegistrationTypesSupported: []string{oidfedconst.ClientRegistrationTypeAutomatic},
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
		},
	},
)

var ia1 = newMockAuthority("https://ia1.example.com", EntityStatementPayload{})
var ia2 = newMockAuthority(
	"https://ia2.example.com",
	EntityStatementPayload{
		MetadataPolicy: &MetadataPolicies{
			RelyingParty: MetadataPolicy{
				"contacts": MetadataPolicyEntry{
					PolicyOperatorAdd: "ia@example.org",
				},
			},
		},
	},
)
var ta1 = newMockAuthority("https://ta.example.com", EntityStatementPayload{})
var ta2 = newMockAuthority(
	"https://ta.foundation.example.org",
	EntityStatementPayload{
		MetadataPolicy: &MetadataPolicies{
			RelyingParty: MetadataPolicy{
				"contacts": MetadataPolicyEntry{
					PolicyOperatorAdd: "ta@foundation.example.org",
				},
				"client_registration_types": MetadataPolicyEntry{
					PolicyOperatorEssential: true,
				},
			},
		},
	},
)
var ta2WithRemove = newMockAuthority(
	"https://ta.foundation.example.org/remove",
	EntityStatementPayload{
		MetadataPolicy: &MetadataPolicies{
			RelyingParty: MetadataPolicy{
				"contacts": MetadataPolicyEntry{
					PolicyOperatorAdd: "ta@foundation.example.org",
				},
				"client_registration_types": MetadataPolicyEntry{
					PolicyOperatorEssential: true,
					"remove":                "explicit",
				},
			},
		},
	},
)
var ta2WithRemoveCrit = newMockAuthority(
	"https://ta.foundation.example.org/remove/crit",
	EntityStatementPayload{
		MetadataPolicy: &MetadataPolicies{
			RelyingParty: MetadataPolicy{
				"contacts": MetadataPolicyEntry{
					PolicyOperatorAdd: "ta@foundation.example.org",
				},
				"client_registration_types": MetadataPolicyEntry{
					PolicyOperatorEssential: true,
					"remove":                "explicit",
				},
			},
		},
		MetadataPolicyCrit: []PolicyOperatorName{"remove"},
	},
)
var taConstraintsPathLen = newMockAuthority(
	"https://ta.foundation.example.org/constraints/path-len",
	EntityStatementPayload{
		Constraints: &ConstraintSpecification{MaxPathLength: zutils.NewInt(1)},
	},
)
var taConstraintsNaming = newMockAuthority(
	"https://ta.foundation.example.org/constraints/naming",
	EntityStatementPayload{
		Constraints: &ConstraintSpecification{
			NamingConstraints: &NamingConstraints{
				Permitted: []string{".example.com"},
				Excluded:  []string{"op2.example.com"},
			},
		},
	},
)
var taConstraintsEntityTypes = newMockAuthority(
	"https://ta.foundation.example.org/constraints/entity-type",
	EntityStatementPayload{
		Constraints: &ConstraintSpecification{AllowedEntityTypes: []string{"openid_provider"}},
	},
)

func init() {
	ia1.RegisterSubordinate(rp1)
	ia2.RegisterSubordinate(rp1)
	ia1.RegisterSubordinate(op1)
	ia2.RegisterSubordinate(op1)
	ia1.RegisterSubordinate(op3)
	ia1.RegisterSubordinate(proxy)
	ia2.RegisterSubordinate(op2)
	ia2.RegisterSubordinate(ia1)
	ta1.RegisterSubordinate(ia1)
	ta1.RegisterSubordinate(ia2)
	ta2.RegisterSubordinate(ia2)
	ta2WithRemove.RegisterSubordinate(ia2)
	ta2WithRemoveCrit.RegisterSubordinate(ia2)
	taConstraintsPathLen.RegisterSubordinate(ia2)
	taConstraintsEntityTypes.RegisterSubordinate(ia2)
	taConstraintsNaming.RegisterSubordinate(ia2)
}

// Current mock Federation
//
// 	┌───┐┌───┐┌─────┐┌──────┐┌─────┐┌──────┐┌─────┐
// 	│ta1││ta2││ta2WR││ta2WRC││taCPL││taCPET││taCPN│
// 	└┬─┬┘└┬──┘└┬────┘└┬─────┘└┬────┘└┬─────┘└┬────┘
// 	│┌▽──▽────▽──────▽───────▽──────▽───────▽─┐
// 	││ia2                                     │
// 	│└┬─┬────────────────┬─┬──────────────────┘
// 	└─│─│─┐              │ │
// 	┌──▽┐│┌▽──────────────▽┐│
// 	│op2│││ia1             ││
// 	└───┘│└┬──┬────┬──────┬┘│
// 	┌────▽─▽┐┌▽──┐┌▽────┐┌▽─▽┐
// 	│op1    ││op3││proxy││rp1│
// 	└───────┘└───┘└─────┘└───┘
//

var chainRPIA1TA1 = TrustChain{
	{EntityStatementPayload: rp1.EntityStatementPayload()},
	{EntityStatementPayload: ia1.SubordinateEntityStatementPayload(rp1.EntityID)},
	{EntityStatementPayload: ta1.SubordinateEntityStatementPayload(ia1.EntityID)},
	{EntityStatementPayload: *ta1.EntityStatementPayload()},
}

var chainRPIA2TA1 = TrustChain{
	{EntityStatementPayload: rp1.EntityStatementPayload()},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(rp1.EntityID)},
	{EntityStatementPayload: ta1.SubordinateEntityStatementPayload(ia2.EntityID)},
	{EntityStatementPayload: *ta1.EntityStatementPayload()},
}

var chainRPIA1IA2TA1 = TrustChain{
	{EntityStatementPayload: rp1.EntityStatementPayload()},
	{EntityStatementPayload: ia1.SubordinateEntityStatementPayload(rp1.EntityID)},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(ia1.EntityID)},
	{EntityStatementPayload: ta1.SubordinateEntityStatementPayload(ia2.EntityID)},
	{EntityStatementPayload: *ta1.EntityStatementPayload()},
}

var chainRPIA2TA2 = TrustChain{
	{EntityStatementPayload: rp1.EntityStatementPayload()},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(rp1.EntityID)},
	{EntityStatementPayload: ta2.SubordinateEntityStatementPayload(ia2.EntityID)},
	{EntityStatementPayload: *ta2.EntityStatementPayload()},
}
var chainRPIA2TA2WithRemove = TrustChain{
	{EntityStatementPayload: rp1.EntityStatementPayload()},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(rp1.EntityID)},
	{EntityStatementPayload: ta2WithRemove.SubordinateEntityStatementPayload(ia2.EntityID)},
	{EntityStatementPayload: *ta2WithRemove.EntityStatementPayload()},
}
var chainRPIA2TA2WithRemoveCrit = TrustChain{
	{EntityStatementPayload: rp1.EntityStatementPayload()},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(rp1.EntityID)},
	{EntityStatementPayload: ta2WithRemoveCrit.SubordinateEntityStatementPayload(ia2.EntityID)},
	{EntityStatementPayload: *ta2WithRemoveCrit.EntityStatementPayload()},
}

var chainRPIA1IA2TA2 = TrustChain{
	{EntityStatementPayload: rp1.EntityStatementPayload()},
	{EntityStatementPayload: ia1.SubordinateEntityStatementPayload(rp1.EntityID)},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(ia1.EntityID)},
	{EntityStatementPayload: ta2.SubordinateEntityStatementPayload(ia2.EntityID)},
	{EntityStatementPayload: *ta2.EntityStatementPayload()},
}

var chainProxyIA1IA2TA1 = TrustChain{
	{EntityStatementPayload: proxy.EntityStatementPayload()},
	{EntityStatementPayload: ia1.SubordinateEntityStatementPayload(proxy.EntityID)},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(ia1.EntityID)},
	{EntityStatementPayload: ta1.SubordinateEntityStatementPayload(ia2.EntityID)},
	{EntityStatementPayload: *ta1.EntityStatementPayload()},
}
var chainProxyIA1TA1 = TrustChain{
	{EntityStatementPayload: proxy.EntityStatementPayload()},
	{EntityStatementPayload: ia1.SubordinateEntityStatementPayload(proxy.EntityID)},
	{EntityStatementPayload: ta1.SubordinateEntityStatementPayload(ia1.EntityID)},
	{EntityStatementPayload: *ta1.EntityStatementPayload()},
}
var chainOP2IA2TACPL = TrustChain{
	{EntityStatementPayload: op2.EntityStatementPayload()},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(op2.EntityID)},
	{EntityStatementPayload: taConstraintsPathLen.SubordinateEntityStatementPayload(ia2.EntityID)},
	{EntityStatementPayload: *taConstraintsPathLen.EntityStatementPayload()},
}
var chainOP1IA2TACPL = TrustChain{
	{EntityStatementPayload: op1.EntityStatementPayload()},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(op1.EntityID)},
	{EntityStatementPayload: taConstraintsPathLen.SubordinateEntityStatementPayload(ia2.EntityID)},
	{EntityStatementPayload: *taConstraintsPathLen.EntityStatementPayload()},
}
var chainOP2IA2TACET = TrustChain{
	{EntityStatementPayload: op2.EntityStatementPayload()},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(op2.EntityID)},
	{EntityStatementPayload: taConstraintsEntityTypes.SubordinateEntityStatementPayload(ia2.EntityID)},
	{EntityStatementPayload: *taConstraintsEntityTypes.EntityStatementPayload()},
}
var chainOP1IA2TACN = TrustChain{
	{EntityStatementPayload: op1.EntityStatementPayload()},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(op1.EntityID)},
	{EntityStatementPayload: taConstraintsNaming.SubordinateEntityStatementPayload(ia2.EntityID)},
	{EntityStatementPayload: *taConstraintsNaming.EntityStatementPayload()},
}
var chainOP1IA1IA2TACN = TrustChain{
	{EntityStatementPayload: op1.EntityStatementPayload()},
	{EntityStatementPayload: ia1.SubordinateEntityStatementPayload(op1.EntityID)},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(ia1.EntityID)},
	{EntityStatementPayload: taConstraintsNaming.SubordinateEntityStatementPayload(ia2.EntityID)},
	{EntityStatementPayload: *taConstraintsNaming.EntityStatementPayload()},
}
var chainOP3IA1IA2TACN = TrustChain{
	{EntityStatementPayload: op3.EntityStatementPayload()},
	{EntityStatementPayload: ia1.SubordinateEntityStatementPayload(op3.EntityID)},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(ia1.EntityID)},
	{EntityStatementPayload: taConstraintsNaming.SubordinateEntityStatementPayload(ia2.EntityID)},
	{EntityStatementPayload: *taConstraintsNaming.EntityStatementPayload()},
}

var allProxyChains = TrustChains{
	chainProxyIA1TA1,
	chainProxyIA1IA2TA1,
}

var allChains = TrustChains{
	chainRPIA1TA1,
	chainRPIA1IA2TA1,
	chainRPIA1IA2TA2,
	chainRPIA2TA2,
	chainRPIA2TA1,
}
var ia1Chains = TrustChains{
	chainRPIA1TA1,
	chainRPIA1IA2TA1,
	chainRPIA1IA2TA2,
}
var ia2Chains = TrustChains{
	chainRPIA2TA2,
	chainRPIA2TA1,
}
var ta1Chains = TrustChains{
	chainRPIA1TA1,
	chainRPIA1IA2TA1,
	chainRPIA2TA1,
}
var ta2Chains = TrustChains{
	chainRPIA1IA2TA2,
	chainRPIA2TA2,
}

func compareTrustChains(a, b TrustChains) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if len(a) != len(b) {
		return false
	}
	aIssChains := make([]string, len(a))
	bIssChains := make([]string, len(b))
	for i, aa := range a {
		var issChain string
		for _, e := range aa {
			issChain += "->" + e.Issuer
		}
		aIssChains[i] = issChain
	}
	for i, bb := range b {
		var issChain string
		for _, e := range bb {
			issChain += "->" + e.Issuer
		}
		bIssChains[i] = issChain
	}
	return len(arrops.Difference(aIssChains, bIssChains)) == 0
}

func TestTrustChainFiltersTrustAnchor(t *testing.T) {
	tests := []struct {
		name     string
		filter   TrustChainsFilter
		in       TrustChains
		expected TrustChains
	}{
		{
			name:     "all chains -> ta2",
			filter:   TrustChainsFilterTrustAnchor(ta2.EntityID),
			in:       allChains,
			expected: ta2Chains,
		},
		{
			name:     "all chains -> ta1",
			filter:   TrustChainsFilterTrustAnchor(ta1.EntityID),
			in:       allChains,
			expected: ta1Chains,
		},
		{
			name:     "ta1 chains -> ta1",
			filter:   TrustChainsFilterTrustAnchor(ta1.EntityID),
			in:       ta1Chains,
			expected: ta1Chains,
		},
		{
			name:     "ta1 chains -> ta2",
			filter:   TrustChainsFilterTrustAnchor(ta2.EntityID),
			in:       ta1Chains,
			expected: nil,
		},
		{
			name:     "all chains -> unknown",
			filter:   TrustChainsFilterTrustAnchor("https://ta.unknown.com"),
			in:       allChains,
			expected: nil,
		},
		{
			name:   "ia1 chains -> ta1",
			filter: TrustChainsFilterTrustAnchor(ta1.EntityID),
			in:     ia1Chains,
			expected: TrustChains{
				chainRPIA1TA1,
				chainRPIA1IA2TA1,
			},
		},
		{
			name:   "ia1 chains -> ta2",
			filter: TrustChainsFilterTrustAnchor(ta2.EntityID),
			in:     ia1Chains,
			expected: TrustChains{
				chainRPIA1IA2TA2,
			},
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				filtered := test.filter.Filter(test.in)
				if !compareTrustChains(filtered, test.expected) {
					t.Errorf(
						"filtered TrustChains are not what we expected:\n\nFiltered:\n%+v\n\nExpected:\n%+v\n\n",
						filtered, test.expected,
					)
				}
			},
		)
	}
}

func TestTrustChainFiltersMinPath(t *testing.T) {
	filter := TrustChainsFilterMinPathLength
	tests := []struct {
		name     string
		in       TrustChains
		expected TrustChains
	}{
		{
			name: "all chains",
			in:   allChains,
			expected: TrustChains{
				chainRPIA1TA1,
				chainRPIA2TA2,
				chainRPIA2TA1,
			},
		},
		{
			name: "ta1 chains",
			in:   ta1Chains,
			expected: TrustChains{
				chainRPIA1TA1,
				chainRPIA2TA1,
			},
		},
		{
			name: "ta2 chains",
			in:   ta2Chains,
			expected: TrustChains{
				chainRPIA2TA2,
			},
		},
		{
			name: "ia1 chains",
			in:   ia1Chains,
			expected: TrustChains{
				chainRPIA1TA1,
			},
		},
		{
			name: "ia2 chains",
			in:   ia2Chains,
			expected: TrustChains{
				chainRPIA2TA2,
				chainRPIA2TA1,
			},
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				filtered := filter.Filter(test.in)
				if !compareTrustChains(filtered, test.expected) {
					t.Errorf(
						"filtered TrustChains are not what we expected:\n\nFiltered:\n%+v\n\nExpected:\n%+v\n\n",
						filtered, test.expected,
					)
				}
			},
		)
	}
}

func TestTrustChainFiltersPathLength(t *testing.T) {
	tests := []struct {
		name     string
		filter   TrustChainsFilter
		in       TrustChains
		expected TrustChains
	}{
		{
			name:     "all chains -> max 3 intermediates",
			filter:   TrustChainsFilterMaxPathLength(3),
			in:       allChains,
			expected: allChains,
		},
		{
			name:     "all chains -> max 2 intermediates",
			filter:   TrustChainsFilterMaxPathLength(2),
			in:       allChains,
			expected: allChains,
		},
		{
			name:   "all chains -> max 1 intermediate",
			filter: TrustChainsFilterMaxPathLength(1),
			in:     allChains,
			expected: TrustChains{
				chainRPIA2TA2,
				chainRPIA2TA1,
				chainRPIA1TA1,
			},
		},
		{
			name:     "all chains -> no intermediates allowed",
			filter:   TrustChainsFilterMaxPathLength(0),
			in:       allChains,
			expected: nil,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				filtered := test.filter.Filter(test.in)
				if !compareTrustChains(filtered, test.expected) {
					t.Errorf(
						"filtered TrustChains are not what we expected:\n\nFiltered:\n%+v\n\nExpected:\n%+v\n\n",
						filtered, test.expected,
					)
				}
			},
		)
	}
}

func TestTrustChains_Filter(t *testing.T) {
	tests := []struct {
		name     string
		filter   []TrustChainsFilter
		in       TrustChains
		expected TrustChains
	}{
		{
			name: "all chains -> ta2 min",
			filter: []TrustChainsFilter{
				TrustChainsFilterTrustAnchor(ta2.EntityID),
				TrustChainsFilterMinPathLength,
			},
			in: allChains,
			expected: TrustChains{
				chainRPIA2TA2,
			},
		},
		{
			name: "all chains -> min ta2",
			filter: []TrustChainsFilter{
				TrustChainsFilterMinPathLength,
				TrustChainsFilterTrustAnchor(ta2.EntityID),
			},
			in: allChains,
			expected: TrustChains{
				chainRPIA2TA2,
			},
		},
		{
			name: "all chains -> ta1 min",
			filter: []TrustChainsFilter{
				TrustChainsFilterTrustAnchor(ta1.EntityID),
				TrustChainsFilterMinPathLength,
			},
			in: allChains,
			expected: TrustChains{
				chainRPIA1TA1,
				chainRPIA2TA1,
			},
		},
		{
			name: "ta1 chains -> ta1 min",
			filter: []TrustChainsFilter{
				TrustChainsFilterTrustAnchor(ta1.EntityID),
				TrustChainsFilterMinPathLength,
			},
			in: ta1Chains,
			expected: TrustChains{
				chainRPIA1TA1,
				chainRPIA2TA1,
			},
		},
		{
			name: "ta1 chains -> ta2 min",
			filter: []TrustChainsFilter{
				TrustChainsFilterTrustAnchor(ta2.EntityID),
				TrustChainsFilterMinPathLength,
			},
			in:       ta1Chains,
			expected: nil,
		},
		{
			name: "all chains -> unknown min",
			filter: []TrustChainsFilter{
				TrustChainsFilterTrustAnchor("https://ta.unknown.com"),
				TrustChainsFilterMinPathLength,
			},
			in:       allChains,
			expected: nil,
		},
		{
			name: "all chains -> min unknown",
			filter: []TrustChainsFilter{
				TrustChainsFilterMinPathLength,
				TrustChainsFilterTrustAnchor("https://ta.unknown.com"),
			},
			in:       allChains,
			expected: nil,
		},
		{
			name: "ia1 chains -> ta1 min",
			filter: []TrustChainsFilter{
				TrustChainsFilterTrustAnchor(ta1.EntityID),
				TrustChainsFilterMinPathLength,
			},
			in: ia1Chains,
			expected: TrustChains{
				chainRPIA1TA1,
			},
		},
		{
			name: "ia1 chains -> ta2 min",
			filter: []TrustChainsFilter{
				TrustChainsFilterTrustAnchor(ta2.EntityID),
				TrustChainsFilterMinPathLength,
			},
			in: ia1Chains,
			expected: TrustChains{
				chainRPIA1IA2TA2,
			},
		},
		{
			name: "ia1 chains -> min ta2",
			filter: []TrustChainsFilter{
				TrustChainsFilterMinPathLength,
				TrustChainsFilterTrustAnchor(ta2.EntityID),
			},
			in:       ia1Chains,
			expected: nil,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				filtered := test.in.Filter(test.filter...)
				if !compareTrustChains(filtered, test.expected) {
					t.Errorf(
						"filtered TrustChains are not what we expected:\n\nFiltered:\n%+v\n\nExpected:\n%+v\n\n",
						filtered, test.expected,
					)
				}
			},
		)
	}
}
