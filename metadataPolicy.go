package oidfed

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"github.com/zachmann/go-utils/maputils"
	"tideland.dev/go/slices"
)

// MetadataPolicies is a type for holding the different MetadataPolicy
type MetadataPolicies struct {
	OpenIDProvider           MetadataPolicy `json:"openid_provider,omitempty"`
	RelyingParty             MetadataPolicy `json:"openid_relying_party,omitempty"`
	OAuthAuthorizationServer MetadataPolicy `json:"oauth_authorization_server,omitempty"`
	OAuthClient              MetadataPolicy `json:"oauth_client,omitempty"`
	OAuthProtectedResource   MetadataPolicy `json:"oauth_resource,omitempty"`
	FederationEntity         MetadataPolicy `json:"federation_entity,omitempty"`
	// Extra contains metadata policies for entity types unknown to this module.
	Extra map[string]MetadataPolicy `json:"-"`
}

// MarshalJSON implements the json.Marshaler interface
func (m MetadataPolicies) MarshalJSON() ([]byte, error) {
	type Alias MetadataPolicies
	explicitFields, err := json.Marshal(Alias(m))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	interfaceMap := make(map[string]interface{})
	for k, v := range m.Extra {
		interfaceMap[k] = interface{}(v)
	}

	return extraMarshalHelper(explicitFields, interfaceMap)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It also unmarshalls additional fields into the Extra claim.
func (m *MetadataPolicies) UnmarshalJSON(data []byte) error {
	type Alias MetadataPolicies
	mm := Alias(*m)
	extra, err := unmarshalWithExtra(data, &mm)
	if err != nil {
		return err
	}

	// Be careful not to set mm.Extra if there was no extra in the JSON, so that
	// we don't set the field to an empty map when we want it to be nil.
	if len(extra) > 0 {
		policyMap := make(map[string]MetadataPolicy)
		for k, v := range extra {
			policy, ok := v.(MetadataPolicy)
			if !ok {
				return errors.Errorf("non MetadataPolicy in metadata policies")
			}

			policyMap[k] = policy
		}

		mm.Extra = policyMap
	}
	*m = MetadataPolicies(mm)
	return nil
}

// MetadataPolicy is a type for holding MetadataPolicyEntry for each relevant attribute
type MetadataPolicy map[string]MetadataPolicyEntry

// MetadataPolicyEntry is a type for holding the operator value for each operator
type MetadataPolicyEntry map[PolicyOperatorName]any

// PolicyOperatorName is the name of a PolicyOperator
type PolicyOperatorName string

// Verify verifies that the MetadataPolicy is valid
func (p MetadataPolicy) Verify(pathInfo string) error {
	for k, v := range p {
		if err := v.Verify(fmt.Sprintf("%s.%s", pathInfo, k)); err != nil {
			return err
		}
	}
	return nil
}

// MergeMetadataPolicies combines multiples MetadataPolicies from a chain into a single one
func MergeMetadataPolicies(policies ...*MetadataPolicies) (*MetadataPolicies, error) {
	opEntries := make([]MetadataPolicy, 0)
	rpEntries := make([]MetadataPolicy, 0)
	asEntries := make([]MetadataPolicy, 0)
	ocEntries := make([]MetadataPolicy, 0)
	prEntries := make([]MetadataPolicy, 0)
	feEntries := make([]MetadataPolicy, 0)
	extraEntries := make(map[string][]MetadataPolicy, 0)
	for _, p := range policies {
		if p == nil {
			continue
		}
		opEntries = append(opEntries, p.OpenIDProvider)
		rpEntries = append(rpEntries, p.RelyingParty)
		asEntries = append(asEntries, p.OAuthAuthorizationServer)
		ocEntries = append(ocEntries, p.OAuthClient)
		prEntries = append(prEntries, p.OAuthProtectedResource)
		feEntries = append(feEntries, p.FederationEntity)
		for k, v := range p.Extra {
			extraEntries[k] = append(extraEntries[k], v)
		}
	}
	op, err := CombineMetadataPolicy("openid_provider", opEntries...)
	if err != nil {
		return nil, err
	}
	rp, err := CombineMetadataPolicy("openid_relying_party", rpEntries...)
	if err != nil {
		return nil, err
	}
	as, err := CombineMetadataPolicy("oauth_authorization_server", asEntries...)
	if err != nil {
		return nil, err
	}
	c, err := CombineMetadataPolicy("oauth_client", ocEntries...)
	if err != nil {
		return nil, err
	}
	pr, err := CombineMetadataPolicy("oauth_resource", prEntries...)
	if err != nil {
		return nil, err
	}
	fed, err := CombineMetadataPolicy("federation_entity", feEntries...)
	if err != nil {
		return nil, err
	}
	extra := make(map[string]MetadataPolicy, 0)
	for k, v := range extraEntries {
		extra[k], err = CombineMetadataPolicy(k, v...)
		if err != nil {
			return nil, err
		}
	}
	return &MetadataPolicies{
		OpenIDProvider:           op,
		RelyingParty:             rp,
		OAuthAuthorizationServer: as,
		OAuthClient:              c,
		OAuthProtectedResource:   pr,
		FederationEntity:         fed,
		Extra:                    extra,
	}, nil
}

// CombineMetadataPolicy combines multiples MetadataPolicy into a single MetadataPolicy,
// at each step verifying that the result is valid
func CombineMetadataPolicy(pathInfo string, policies ...MetadataPolicy) (MetadataPolicy, error) {
	if len(policies) == 0 {
		return nil, nil
	}
	var err error
	out := policies[0]
	if err = out.Verify(pathInfo); err != nil {
		return nil, err
	}
	for i := 1; i < len(policies); i++ {
		out, err = combineMetadataPolicy(out, policies[i], pathInfo)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// combineMetadataPolicy combines two MetadataPolicy and verifies that the resulting MetadataPolicy is valid
func combineMetadataPolicy(parent, sub MetadataPolicy, pathInfo string) (MetadataPolicy, error) {
	if len(sub) == 0 {
		return parent, nil
	}
	if len(parent) == 0 {
		return sub, nil
	}
	out := make(MetadataPolicy)
	for k, pv := range parent {
		sv, sFound := sub[k]
		if !sFound {
			out[k] = pv
			continue
		}
		combined, err := mergeMetadataPolicyEntries(pv, sv, fmt.Sprintf("%s.%s", pathInfo, k))
		if err != nil {
			return nil, err
		}
		out[k] = combined
	}
	for k, sv := range sub {
		if _, found := out[k]; found {
			continue
		}
		out[k] = sv
	}
	return out, out.Verify(pathInfo)
}

func mergeMetadataPolicyEntries(a, b MetadataPolicyEntry, pathInfo string) (MetadataPolicyEntry, error) {
	out := make(MetadataPolicyEntry)
	for op, av := range a {
		bv, bFound := b[op]
		if !bFound {
			out[op] = av
			continue
		}
		operator, ok := operators[op]
		if !ok {
			// return nil, errors.Errorf("unknown policy operator '%s'; cannot combine these policies", op)
			// We already checked that this is not a crit operator, so it is just ignored
			return nil, nil
		}
		combined, err := operator.Merge(av, bv, pathInfo)
		if err != nil {
			return nil, err
		}
		out[op] = combined
	}
	for op, bv := range b {
		if _, found := out[op]; found {
			continue
		}
		out[op] = bv
	}
	return out, nil
}

// Verify verifies that the MetadataPolicyEntry is valid
func (p MetadataPolicyEntry) Verify(pathInfo string) error {
	activeOperators := maputils.Keys(p)
	for _, opN := range activeOperators {
		op, ok := operators[opN]
		if !ok {
			continue
		}
		mayCombine := op.MayCombineWith()
		if mayCombine == nil {
			continue
		}
		notAllowed := slices.Subtract(activeOperators, append(mayCombine, op.Name()))
		if len(notAllowed) > 0 {
			return errors.Errorf(
				"policy operator '%s' in '%s' cannot be combined with these operators: %v", opN,
				pathInfo, notAllowed,
			)
		}
	}
	for _, v := range policyVerifiers {
		if err := v(p, pathInfo); err != nil {
			return err
		}
	}
	return nil
}

// ApplyTo applies this MetadataPolicyEntry to the passed value and returns the resulting value
func (p MetadataPolicyEntry) ApplyTo(value any, valueSet bool, pathInfo string) (any, error) {
	var err error
	essentialV, ok := p[PolicyOperatorEssential]
	essential := false
	if ok {
		essential, _ = essentialV.(bool)
	}
	for _, policyName := range OperatorOrder {
		policyValue, ok := p[policyName]
		if !ok {
			continue
		}
		operator, found := operators[policyName]
		if !found {
			return value, errors.Errorf("unsupported policy operator '%s' in '%s'", policyName, pathInfo)
		}
		value, valueSet, err = operator.Apply(value, valueSet, policyValue, essential, pathInfo)
		if err != nil {
			return value, err
		}
	}
	return value, nil
}
