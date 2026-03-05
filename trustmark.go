package oidfed

import (
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/zachmann/go-utils/duration"
	"gopkg.in/yaml.v3"

	"github.com/go-oidfed/lib/apimodel"
	jwxi "github.com/go-oidfed/lib/internal/jwx"
	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/oidfedconst"
	"github.com/go-oidfed/lib/unixtime"
)

// TrustMarkInfos is a slice of TrustMarkInfo
type TrustMarkInfos []TrustMarkInfo

// VerifiedFederation verifies all TrustMarkInfos by using the passed trust anchor and returns only the valid TrustMarkInfos
func (tms TrustMarkInfos) VerifiedFederation(ta *EntityStatementPayload) (verified TrustMarkInfos) {
	for _, tm := range tms {
		if err := tm.VerifyFederation(ta); err == nil {
			verified = append(verified, tm)
		}
	}
	return
}

// VerifiedExternal verifies all TrustMarkInfos by using the passed trust mark issuer jwks and optionally the passed
// trust mark owner jwks and returns only the valid TrustMarkInfos
func (tms TrustMarkInfos) VerifiedExternal(
	jwks jwx.JWKS,
	tmo ...TrustMarkOwnerSpec,
) (verified TrustMarkInfos) {
	for _, tm := range tms {
		if err := tm.VerifyExternal(jwks, tmo...); err == nil {
			verified = append(verified, tm)
		}
	}
	return
}

// Find uses the passed function to find the first matching TrustMarkInfo
func (tms TrustMarkInfos) Find(matcher func(info TrustMarkInfo) bool) *TrustMarkInfo {
	for _, tm := range tms {
		if matcher(tm) {
			return &tm
		}
	}
	return nil
}

// FindByID returns the (first) TrustMarkInfo with the passed id
// DEPRECATED: use FindByType instead
func (tms TrustMarkInfos) FindByID(id string) *TrustMarkInfo {
	return tms.FindByType(id)
}

// FindByType returns the (first) TrustMarkInfo with the passed trust mark type
func (tms TrustMarkInfos) FindByType(trustMarkType string) *TrustMarkInfo {
	return tms.Find(func(info TrustMarkInfo) bool { return info.TrustMarkType == trustMarkType })
}

// TrustMarkInfo is a type for holding a trust mark as represented in an EntityConfiguration
type TrustMarkInfo struct {
	TrustMarkType string                 `json:"trust_mark_type" yaml:"type"`
	TrustMarkJWT  string                 `json:"trust_mark" yaml:"trust_mark"`
	Extra         map[string]interface{} `json:"-" yaml:"-"`
	trustmark     *TrustMark
}

// MarshalJSON implements the json.Marshaler interface.
// It also marshals extra fields.
func (tm TrustMarkInfo) MarshalJSON() ([]byte, error) {
	type trustMarkInfo TrustMarkInfo
	explicitFields, err := json.Marshal(trustMarkInfo(tm))
	if err != nil {
		return nil, err
	}
	return extraMarshalHelper(explicitFields, tm.Extra)
}

// ParseTrustMark parses a trust mark jwt into a TrustMark
func ParseTrustMark(data []byte) (*TrustMark, error) {
	m, err := jwxi.Parse(data)
	if err != nil {
		return nil, err
	}
	if !m.VerifyType(oidfedconst.JWTTypeTrustMark) {
		return nil, errors.Errorf("trustmark jwt does not have '%s' JWT type", oidfedconst.JWTTypeTrustMark)
	}
	t := &TrustMark{jwtMsg: m}
	if err = json.Unmarshal(m.Payload(), t); err != nil {
		return nil, err
	}
	return t, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It also unmarshalls additional fields into the Extra claim.
func (tm *TrustMarkInfo) UnmarshalJSON(data []byte) error {
	type trustMarkInfo TrustMarkInfo
	tmi := trustMarkInfo(*tm)
	extra, err := unmarshalWithExtra(data, &tmi)
	if err != nil {
		return err
	}
	tmi.Extra = extra
	*tm = TrustMarkInfo(tmi)
	return nil
}

// TrustMark returns the TrustMark for this TrustMarkInfo
func (tm *TrustMarkInfo) TrustMark() (*TrustMark, error) {
	if tm.trustmark == nil || tm.trustmark.jwtMsg == nil {
		t, err := ParseTrustMark([]byte(tm.TrustMarkJWT))
		if err != nil {
			return nil, err
		}
		tm.trustmark = t
	}
	return tm.trustmark, nil
}

// VerifyFederation verifies the TrustMarkInfo by using the passed trust anchor
func (tm *TrustMarkInfo) VerifyFederation(ta *EntityStatementPayload) error {
	mark, err := tm.TrustMark()
	if err != nil {
		return err
	}
	if mark.TrustMarkType != tm.TrustMarkType {
		return errors.Errorf("trust mark object claim 'trust_mark_type' does not match JWT claim")
	}
	return mark.VerifyFederation(ta)
}

// VerifyExternal verifies the TrustMarkInfo by using the passed trust mark issuer jwks and optionally the passed
// trust mark owner jwks
func (tm *TrustMarkInfo) VerifyExternal(
	jwks jwx.JWKS,
	tmo ...TrustMarkOwnerSpec,
) error {
	mark, err := tm.TrustMark()
	if err != nil {
		return err
	}
	if mark.TrustMarkType != tm.TrustMarkType {
		return errors.Errorf("trust mark object claim 'trust_mark_type' does not match JWT claim")
	}
	return mark.VerifyExternal(jwks, tmo...)
}

// TrustMark is a type for holding a trust mark
type TrustMark struct {
	Issuer        string                 `json:"iss"`
	Subject       string                 `json:"sub"`
	TrustMarkType string                 `json:"trust_mark_type"`
	IssuedAt      unixtime.Unixtime      `json:"iat"`
	LogoURI       string                 `json:"logo_uri,omitempty"`
	ExpiresAt     *unixtime.Unixtime     `json:"exp,omitempty"`
	Ref           string                 `json:"ref,omitempty"`
	DelegationJWT string                 `json:"delegation,omitempty"`
	Extra         map[string]interface{} `json:"-"`
	jwtMsg        *jwxi.ParsedJWT
	delegation    *DelegationJWT
}

// MarshalJSON implements the json.Marshaler interface.
// It also marshals extra fields.
func (tm TrustMark) MarshalJSON() ([]byte, error) {
	type trustMark TrustMark
	explicitFields, err := json.Marshal(trustMark(tm))
	if err != nil {
		return nil, err
	}
	return extraMarshalHelper(explicitFields, tm.Extra)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It also unmarshalls additional fields into the Extra claim.
func (tm *TrustMark) UnmarshalJSON(data []byte) error {
	type trustMark TrustMark
	tmi := trustMark(*tm)
	extra, err := unmarshalWithExtra(data, &tmi)
	if err != nil {
		return err
	}
	tmi.Extra = extra
	*tm = TrustMark(tmi)
	return nil
}

func parseDelegationJWT(delegationJWT []byte) (*DelegationJWT, error) {
	m, err := jwxi.Parse(delegationJWT)
	if err != nil {
		return nil, err
	}
	if !m.VerifyType(oidfedconst.JWTTypeTrustMarkDelegation) {
		return nil, errors.Errorf(
			"trustmark delegation jwt does not have '%s' JWT type", oidfedconst.JWTTypeTrustMarkDelegation,
		)
	}
	d := &DelegationJWT{jwtMsg: m}
	if err = json.Unmarshal(m.Payload(), d); err != nil {
		return nil, err
	}
	return d, nil
}

// Delegation returns the DelegationJWT (if any) for this TrustMark
func (tm *TrustMark) Delegation() (*DelegationJWT, error) {
	var err error
	if tm.delegation == nil {
		if tm.DelegationJWT == "" {
			return nil, nil
		}
		tm.delegation, err = parseDelegationJWT([]byte(tm.DelegationJWT))
	}
	return tm.delegation, err
}

func getTrustMarkIssuerJWKS(
	trustMarkIssuer string,
	ta *EntityStatementPayload,
) (jwks jwx.JWKS, err error) {
	if trustMarkIssuer == ta.Subject {
		jwks = ta.JWKS
		return
	}

	resolveRequest := apimodel.ResolveRequest{
		Subject:     trustMarkIssuer,
		TrustAnchor: []string{ta.Subject},
	}
	var res ResolveResponsePayload
	switch resolver := DefaultMetadataResolver.(type) {
	case LocalMetadataResolver:
		res, _, err = resolver.resolveResponsePayloadWithoutTrustMarks(resolveRequest)
	default:
		res, err = DefaultMetadataResolver.ResolveResponsePayload(resolveRequest)
	}
	if err != nil {
		err = errors.Wrap(err, "error while resolving trust mark issuer")
		return
	}
	var tmi *EntityStatement
	if len(res.TrustChain) > 0 {
		tmi, err = ParseEntityStatement(res.TrustChain[0].RawJWT)
	} else {
		tmi, err = GetEntityConfiguration(trustMarkIssuer)
	}
	if err != nil {
		err = errors.Wrap(err, "error while parsing trust mark issuer entity statement")
		return
	}
	if tmi == nil || tmi.JWKS.Len() == 0 {
		err = errors.New("no jwks found for trust mark issuer")
		return
	}
	jwks = tmi.JWKS
	return
}

// VerifyFederation verifies the TrustMark by using the passed trust anchor
func (tm *TrustMark) VerifyFederation(ta *EntityStatementPayload) error {
	if ta.TrustMarkIssuers != nil {
		if tmis, found := ta.TrustMarkIssuers[tm.TrustMarkType]; found {
			if !slices.Contains(tmis, tm.Issuer) {
				return errors.New("verify trustmark: trust mark issuer is not allowed by trust anchor")
			}
		}
	}
	jwks, err := getTrustMarkIssuerJWKS(tm.Issuer, ta)
	if err != nil {
		return err
	}
	tmo, tmoFound := ta.TrustMarkOwners[tm.TrustMarkType]
	if !tmoFound {
		// no delegation
		return tm.VerifyExternal(jwks)
	}
	return tm.VerifyExternal(jwks, tmo)
}

// VerifyExternal verifies the TrustMark by using the passed trust mark issuer jwks and optionally the passed
// trust mark owner jwks
func (tm *TrustMark) VerifyExternal(jwks jwx.JWKS, tmo ...TrustMarkOwnerSpec) error {
	if err := unixtime.VerifyTime(&tm.IssuedAt, tm.ExpiresAt); err != nil {
		return err
	}
	if _, err := tm.jwtMsg.VerifyWithSet(jwks); err != nil {
		return errors.Wrap(err, "verify trustmark")
	}
	if len(tmo) == 0 {
		// no delegation
		return nil
	}
	// delegation
	delegation, err := tm.Delegation()
	if err != nil {
		return errors.Wrap(err, "verify trustmark: parsing delegation jwt")
	}
	if delegation == nil {
		return errors.New("verify trustmark: no delegation jwt in trust mark")
	}
	if delegation.TrustMarkType != tm.TrustMarkType {
		return errors.New("verify trustmark: delegation jwt not for this trust mark")
	}
	if delegation.Subject != tm.Issuer {
		return errors.New("verify trustmark: delegation jwt not for this trust mark issuer")
	}
	if delegation.Issuer != tmo[0].ID {
		return errors.New("verify trustmark: delegation jwt not issued by trust mark owner")
	}
	return delegation.VerifyExternal(tmo[0].JWKS)
}

// DelegationJWT is a type for holding information about a delegation jwt
type DelegationJWT struct {
	Issuer        string                 `json:"iss"`
	Subject       string                 `json:"sub"`
	TrustMarkType string                 `json:"trust_mark_type"`
	IssuedAt      unixtime.Unixtime      `json:"iat"`
	ExpiresAt     *unixtime.Unixtime     `json:"exp,omitempty"`
	Ref           string                 `json:"ref,omitempty"`
	Extra         map[string]interface{} `json:"-"`
	jwtMsg        *jwxi.ParsedJWT
}

// MarshalJSON implements the json.Marshaler interface.
// It also marshals extra fields.
func (djwt DelegationJWT) MarshalJSON() ([]byte, error) {
	type delegationJWT DelegationJWT
	explicitFields, err := json.Marshal(delegationJWT(djwt))
	if err != nil {
		return nil, err
	}
	return extraMarshalHelper(explicitFields, djwt.Extra)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It also unmarshalls additional fields into the Extra claim.
func (djwt *DelegationJWT) UnmarshalJSON(data []byte) error {
	type delegationJWT DelegationJWT
	tmi := delegationJWT(*djwt)
	extra, err := unmarshalWithExtra(data, &tmi)
	if err != nil {
		return err
	}
	tmi.Extra = extra
	*djwt = DelegationJWT(tmi)
	return nil
}

// VerifyFederation verifies the DelegationJWT by using the passed trust anchor
func (djwt DelegationJWT) VerifyFederation(ta *EntityStatementPayload) error {
	if err := unixtime.VerifyTime(&djwt.IssuedAt, djwt.ExpiresAt); err != nil {
		return errors.Wrap(err, "verify delegation jwt")
	}
	owner, ok := ta.TrustMarkOwners[djwt.TrustMarkType]
	if !ok {
		return errors.New("verify delegation jwt: unknown trust mark owner")
	}
	_, err := djwt.jwtMsg.VerifyWithSet(owner.JWKS)
	return errors.Wrap(err, "verify delegation jwt")
}

// VerifyExternal verifies the DelegationJWT by using the passed trust mark owner jwks
func (djwt DelegationJWT) VerifyExternal(jwks jwx.JWKS) error {
	if err := unixtime.VerifyTime(&djwt.IssuedAt, djwt.ExpiresAt); err != nil {
		return errors.Wrap(err, "verify delegation jwt")
	}
	_, err := djwt.jwtMsg.VerifyWithSet(jwks)
	return errors.Wrap(err, "verify delegation jwt")
}

// TrustMarkSpecProvider provides TrustMarkSpecs dynamically.
// Implementations can fetch specs from config, database, or other sources.
// Implementations MUST be safe for concurrent use.
type TrustMarkSpecProvider interface {
	// GetTrustMarkSpec returns the TrustMarkSpec for the given trust mark type.
	// Returns nil if the trust mark type is not found.
	GetTrustMarkSpec(trustMarkType string) *TrustMarkSpec

	// TrustMarkTypes returns all available trust mark types.
	TrustMarkTypes() []string
}

// MapTrustMarkSpecProvider is a TrustMarkSpecProvider backed by an in-memory map.
// It is safe for concurrent use.
type MapTrustMarkSpecProvider struct {
	mu    sync.RWMutex
	specs map[string]TrustMarkSpec
}

// NewMapTrustMarkSpecProvider creates a new MapTrustMarkSpecProvider.
func NewMapTrustMarkSpecProvider(specs []TrustMarkSpec) *MapTrustMarkSpecProvider {
	m := make(map[string]TrustMarkSpec, len(specs))
	for _, s := range specs {
		m[s.TrustMarkType] = s
	}
	return &MapTrustMarkSpecProvider{specs: m}
}

// GetTrustMarkSpec returns the TrustMarkSpec for the given trust mark type.
func (p *MapTrustMarkSpecProvider) GetTrustMarkSpec(trustMarkType string) *TrustMarkSpec {
	p.mu.RLock()
	defer p.mu.RUnlock()
	spec, ok := p.specs[trustMarkType]
	if !ok {
		return nil
	}
	return &spec
}

// TrustMarkTypes returns all available trust mark types.
func (p *MapTrustMarkSpecProvider) TrustMarkTypes() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	types := make([]string, 0, len(p.specs))
	for t := range p.specs {
		types = append(types, t)
	}
	return types
}

// AddTrustMark adds or updates a TrustMarkSpec.
func (p *MapTrustMarkSpecProvider) AddTrustMark(spec TrustMarkSpec) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.specs[spec.TrustMarkType] = spec
}

// RemoveTrustMark removes a TrustMarkSpec by type.
func (p *MapTrustMarkSpecProvider) RemoveTrustMark(trustMarkType string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.specs, trustMarkType)
}

// IssueTrustMarkOptions contains options for issuing a trust mark.
type IssueTrustMarkOptions struct {
	// Lifetime overrides the spec's lifetime if set (> 0).
	Lifetime time.Duration
	// SubjectClaims are additional claims specific to this subject.
	// These are merged with (and override) the spec's Extra claims.
	SubjectClaims map[string]any
}

// TrustMarkIssuer is an entity that can issue TrustMarkInfo
type TrustMarkIssuer struct {
	EntityID string
	*jwx.TrustMarkSigner

	mu         sync.RWMutex
	provider   TrustMarkSpecProvider
	trustMarks map[string]TrustMarkSpec // Used when no provider is set
}

// TrustMarkSpec describes a TrustMark for a TrustMarkIssuer
type TrustMarkSpec struct {
	TrustMarkType string                  `json:"trust_mark_type" yaml:"trust_mark_type"`
	Lifetime      duration.DurationOption `json:"lifetime" yaml:"lifetime"`
	Ref           string                  `json:"ref" yaml:"ref"`
	LogoURI       string                  `json:"logo_uri" yaml:"logo_uri"`
	Extra         map[string]any          `json:"-" yaml:"-"`
	DelegationJWT string                  `json:"delegation_jwt" yaml:"delegation_jwt"`
}

// MarshalJSON implements the json.Marshaler interface
func (tms TrustMarkSpec) MarshalJSON() ([]byte, error) {
	type Alias TrustMarkSpec
	explicitFields, err := json.Marshal(Alias(tms))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return extraMarshalHelper(explicitFields, tms.Extra)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (tms *TrustMarkSpec) UnmarshalJSON(data []byte) error {
	type Alias TrustMarkSpec
	mm := Alias(*tms)

	extra, err := unmarshalWithExtra(data, &mm)
	if err != nil {
		return errors.WithStack(err)
	}
	mm.Extra = extra
	*tms = TrustMarkSpec(mm)
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface
func (tms TrustMarkSpec) MarshalYAML() (any, error) {
	type Alias TrustMarkSpec
	explicitFields, err := yaml.Marshal(Alias(tms))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return yamlExtraMarshalHelper(explicitFields, tms.Extra)
}

// UnmarshalYAML implements the yaml.Unmarshaler interface
func (tms *TrustMarkSpec) UnmarshalYAML(data *yaml.Node) error {
	type Alias TrustMarkSpec
	mm := Alias(*tms)

	extra, err := yamlUnmarshalWithExtra(data, &mm)
	if err != nil {
		return errors.WithStack(err)
	}
	mm.Extra = extra
	*tms = TrustMarkSpec(mm)
	return nil
}

// NewTrustMarkIssuer creates a new TrustMarkIssuer
func NewTrustMarkIssuer(
	entityID string, signer *jwx.TrustMarkSigner, trustMarkSpecs []TrustMarkSpec,
) *TrustMarkIssuer {
	trustMarks := make(map[string]TrustMarkSpec, len(trustMarkSpecs))
	for _, tms := range trustMarkSpecs {
		trustMarks[tms.TrustMarkType] = tms
	}
	return &TrustMarkIssuer{
		EntityID:        entityID,
		TrustMarkSigner: signer,
		trustMarks:      trustMarks,
		// provider is nil by default, uses trustMarks map
	}
}

// SetProvider sets a custom TrustMarkSpecProvider for dynamic spec lookup.
// When a provider is set, it takes precedence over the static in-memory map.
func (tmi *TrustMarkIssuer) SetProvider(provider TrustMarkSpecProvider) {
	tmi.mu.Lock()
	defer tmi.mu.Unlock()
	tmi.provider = provider
}

// getSpec retrieves a TrustMarkSpec.
// If a provider is configured, it is used exclusively.
// Otherwise, the legacy in-memory map is used.
func (tmi *TrustMarkIssuer) getSpec(trustMarkType string) *TrustMarkSpec {
	tmi.mu.RLock()
	defer tmi.mu.RUnlock()

	// If provider is configured, use it exclusively
	if tmi.provider != nil {
		return tmi.provider.GetTrustMarkSpec(trustMarkType)
	}

	// Fallback to legacy in-memory map
	spec, ok := tmi.trustMarks[trustMarkType]
	if ok {
		return &spec
	}
	return nil
}

// HasTrustMarkType checks if a trust mark type is available for issuance.
func (tmi *TrustMarkIssuer) HasTrustMarkType(trustMarkType string) bool {
	return tmi.getSpec(trustMarkType) != nil
}

// AddTrustMark adds a TrustMarkSpec to the in-memory map.
// Note: If a provider is configured, this has no effect on issuance.
func (tmi *TrustMarkIssuer) AddTrustMark(spec TrustMarkSpec) {
	tmi.mu.Lock()
	defer tmi.mu.Unlock()
	if tmi.trustMarks == nil {
		tmi.trustMarks = make(map[string]TrustMarkSpec)
	}
	tmi.trustMarks[spec.TrustMarkType] = spec
}

// RemoveTrustMark removes a TrustMarkSpec from the in-memory map.
// Note: If a provider is configured, this has no effect on issuance.
func (tmi *TrustMarkIssuer) RemoveTrustMark(trustMarkType string) {
	tmi.mu.Lock()
	defer tmi.mu.Unlock()
	delete(tmi.trustMarks, trustMarkType)
}

// TrustMarkTypes returns a slice of the trust mark ids for which this TrustMarkIssuer can issue TrustMarks
func (tmi *TrustMarkIssuer) TrustMarkTypes() []string {
	tmi.mu.RLock()
	defer tmi.mu.RUnlock()

	// If provider is configured, use it exclusively
	if tmi.provider != nil {
		return tmi.provider.TrustMarkTypes()
	}

	// Fallback to legacy in-memory map
	trustMarkTypes := make([]string, 0, len(tmi.trustMarks))
	for id := range tmi.trustMarks {
		trustMarkTypes = append(trustMarkTypes, id)
	}
	return trustMarkTypes
}

// buildTrustMark is a shared helper that builds and signs a TrustMark from a spec.
// It returns the TrustMark, the signed JWT, and any error.
func buildTrustMark(
	entityID, sub string, spec TrustMarkSpec, signer *jwx.TrustMarkSigner, lifetime ...time.Duration,
) (*TrustMark, []byte, error) {
	now := time.Now()
	tm := &TrustMark{
		Issuer:        entityID,
		Subject:       sub,
		TrustMarkType: spec.TrustMarkType,
		IssuedAt:      unixtime.Unixtime{Time: now},
		LogoURI:       spec.LogoURI,
		Ref:           spec.Ref,
		DelegationJWT: spec.DelegationJWT,
		Extra:         spec.Extra,
	}
	lf := spec.Lifetime.Duration()
	if len(lifetime) > 0 {
		lf = lifetime[0]
	}
	if lf != 0 {
		tm.ExpiresAt = &unixtime.Unixtime{Time: now.Add(lf)}
	}
	jwt, err := signer.JWT(tm)
	if err != nil {
		return nil, nil, err
	}
	return tm, jwt, nil
}

// IssueTrustMarkWithOptions issues a trust mark with additional options.
// If SubjectClaims is non-nil (even if empty), it is used exclusively.
// If SubjectClaims is nil, the spec's Extra claims are used.
func (tmi *TrustMarkIssuer) IssueTrustMarkWithOptions(
	trustMarkType, sub string,
	opts IssueTrustMarkOptions,
) (string, *unixtime.Unixtime, error) {
	spec := tmi.getSpec(trustMarkType)
	if spec == nil {
		return "", nil, errors.Errorf("unknown trustmark '%s'", trustMarkType)
	}

	// Create a copy of spec
	specWithClaims := *spec

	// If subject claims are provided (non-nil), use them exclusively
	// If subject claims are nil, use the spec's Extra claims
	if opts.SubjectClaims != nil {
		specWithClaims.Extra = opts.SubjectClaims
	}
	// else: specWithClaims.Extra = spec.Extra (already copied)

	var lifetime []time.Duration
	if opts.Lifetime > 0 {
		lifetime = []time.Duration{opts.Lifetime}
	}

	tm, jwt, err := buildTrustMark(tmi.EntityID, sub, specWithClaims, tmi.TrustMarkSigner, lifetime...)
	if err != nil {
		return "", nil, err
	}
	return string(jwt), tm.ExpiresAt, nil
}

// IssueTrustMark issues a trust mark JWT for the passed trust mark type and subject; optionally a custom lifetime can
// be passed. Returns the signed JWT string and expiration time.
func (tmi *TrustMarkIssuer) IssueTrustMark(trustMarkType, sub string, lifetime ...time.Duration) (
	string, *unixtime.Unixtime, error,
) {
	opts := IssueTrustMarkOptions{}
	if len(lifetime) > 0 {
		opts.Lifetime = lifetime[0]
	}
	return tmi.IssueTrustMarkWithOptions(trustMarkType, sub, opts)
}

// SelfIssuedTrustMarkSpec describes a TrustMark for a SelfIssuedTrustMarkIssuer.
// It extends TrustMarkSpec with self-issuance specific options.
type SelfIssuedTrustMarkSpec struct {
	TrustMarkSpec            `yaml:",inline"`
	IncludeExtraClaimsInInfo bool `json:"include_extra_claims_in_info" yaml:"include_extra_claims_in_info"`
}

// SelfIssuedTrustMarkIssuer is an entity that can issue TrustMarkInfo for itself.
// Unlike TrustMarkIssuer, it returns a full TrustMarkInfo including metadata.
type SelfIssuedTrustMarkIssuer struct {
	EntityID string
	*jwx.TrustMarkSigner
	trustMarks map[string]SelfIssuedTrustMarkSpec
}

// NewSelfIssuedTrustMarkIssuer creates a new SelfIssuedTrustMarkIssuer
func NewSelfIssuedTrustMarkIssuer(
	entityID string, signer *jwx.TrustMarkSigner, trustMarkSpecs []SelfIssuedTrustMarkSpec,
) *SelfIssuedTrustMarkIssuer {
	trustMarks := make(map[string]SelfIssuedTrustMarkSpec, len(trustMarkSpecs))
	for _, tms := range trustMarkSpecs {
		trustMarks[tms.TrustMarkType] = tms
	}
	return &SelfIssuedTrustMarkIssuer{
		EntityID:        entityID,
		TrustMarkSigner: signer,
		trustMarks:      trustMarks,
	}
}

// AddTrustMark adds a SelfIssuedTrustMarkSpec to the SelfIssuedTrustMarkIssuer enabling it to issue the TrustMarkInfo
func (tmi *SelfIssuedTrustMarkIssuer) AddTrustMark(spec SelfIssuedTrustMarkSpec) {
	tmi.trustMarks[spec.TrustMarkType] = spec
}

// TrustMarkTypes returns a slice of the trust mark types for which this SelfIssuedTrustMarkIssuer can issue TrustMarks
func (tmi *SelfIssuedTrustMarkIssuer) TrustMarkTypes() []string {
	trustMarkTypes := make([]string, 0, len(tmi.trustMarks))
	for id := range tmi.trustMarks {
		trustMarkTypes = append(trustMarkTypes, id)
	}
	return trustMarkTypes
}

// IssueTrustMark issues a TrustMarkInfo for the passed trust mark type and subject; optionally a custom lifetime can
// be passed. Returns the full TrustMarkInfo including metadata.
func (tmi SelfIssuedTrustMarkIssuer) IssueTrustMark(trustMarkType, sub string, lifetime ...time.Duration) (
	*TrustMarkInfo, error,
) {
	spec, ok := tmi.trustMarks[trustMarkType]
	if !ok {
		return nil, errors.Errorf("unknown trustmark '%s'", trustMarkType)
	}
	tm, jwt, err := buildTrustMark(tmi.EntityID, sub, spec.TrustMarkSpec, tmi.TrustMarkSigner, lifetime...)
	if err != nil {
		return nil, err
	}
	var extra map[string]any
	if spec.IncludeExtraClaimsInInfo {
		extra = spec.Extra
	}
	return &TrustMarkInfo{
		TrustMarkType: spec.TrustMarkType,
		TrustMarkJWT:  string(jwt),
		Extra:         extra,
		trustmark:     tm,
	}, nil
}

// TrustMarkOwner is a type describing the owning entity of a trust mark; it can be used to issue DelegationJWT
type TrustMarkOwner struct {
	EntityID string
	*jwx.TrustMarkDelegationSigner
	ownedTrustMarks map[string]OwnedTrustMark
}

// OwnedTrustMark is a type describing the trust marks owned by a TrustMarkOwner
type OwnedTrustMark struct {
	ID                 string
	DelegationLifetime time.Duration
	Ref                string
	Extra              map[string]any
}

// NewTrustMarkOwner creates a new TrustMarkOwner
func NewTrustMarkOwner(
	entityID string, signer *jwx.TrustMarkDelegationSigner, ownedTrustMarks []OwnedTrustMark,
) *TrustMarkOwner {
	trustMarks := make(map[string]OwnedTrustMark, len(ownedTrustMarks))
	for _, tms := range ownedTrustMarks {
		trustMarks[tms.ID] = tms
	}
	return &TrustMarkOwner{
		EntityID:                  entityID,
		TrustMarkDelegationSigner: signer,
		ownedTrustMarks:           trustMarks,
	}
}

// AddTrustMark adds a new OwnedTrustMark to the TrustMarkOwner
func (tmo *TrustMarkOwner) AddTrustMark(spec OwnedTrustMark) {
	tmo.ownedTrustMarks[spec.ID] = spec
}

// DelegationJWT issues a DelegationJWT (as []byte) for the passed trust mark id and subject; optionally a custom
// lifetime can be passed
func (tmo TrustMarkOwner) DelegationJWT(trustMarkType, sub string, lifetime ...time.Duration) ([]byte, error) {
	spec, ok := tmo.ownedTrustMarks[trustMarkType]
	if !ok {
		return nil, errors.Errorf("unknown trustmark '%s'", trustMarkType)
	}
	now := time.Now()
	delegation := &DelegationJWT{
		Issuer:        tmo.EntityID,
		Subject:       sub,
		TrustMarkType: spec.ID,
		IssuedAt:      unixtime.Unixtime{Time: now},
		Ref:           spec.Ref,
		Extra:         spec.Extra,
	}
	lf := spec.DelegationLifetime
	if len(lifetime) > 0 {
		lf = lifetime[0]
	}
	if spec.DelegationLifetime != 0 {
		delegation.ExpiresAt = &unixtime.Unixtime{Time: now.Add(lf)}
	}
	return tmo.TrustMarkDelegationSigner.JWT(delegation)
}
