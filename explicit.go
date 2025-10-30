package oidfed

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/go-oidfed/lib/cache"
	"github.com/go-oidfed/lib/internal/http"
	"github.com/go-oidfed/lib/internal/jwx"
	jwx2 "github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/oidfedconst"
)

// OIDCRP is a type for using an OIDC Relying Party with the oauth2 and oidc library. It holds an oauth2.Config,
// oidc.Provider, and oidc.IDTokenVerifier
type OIDCRP struct {
	*oauth2.Config
	*oidc.Provider
	*oidc.IDTokenVerifier
}

// GetExplicitRegistrationOIDCRP returns an OIDCRP by re-using an explicit client registration from cache or
// registering a new one.
func (f FederationLeaf) GetExplicitRegistrationOIDCRP(
	ctx context.Context, op string,
) (*OIDCRP, error) {
	client, errRes, err := f.GetExplicitRegistration(op)
	if err != nil {
		return nil, err
	}
	if errRes != nil {
		return nil, errRes.Err()
	}

	opMetadata, err := f.ResolveOPMetadata(op)
	if err != nil {
		return nil, err
	}
	providerConfig := oidc.ProviderConfig{
		IssuerURL:     opMetadata.Issuer,
		AuthURL:       opMetadata.AuthorizationEndpoint,
		TokenURL:      opMetadata.TokenEndpoint,
		DeviceAuthURL: opMetadata.DeviceAuthorizationEndpoint,
		UserInfoURL:   opMetadata.UserinfoEndpoint,
		JWKSURL:       opMetadata.JWKSURI,
		Algorithms:    opMetadata.IDTokenSigningAlgValuesSupported,
	}
	provider := providerConfig.NewProvider(ctx)
	return &OIDCRP{
		Config: &oauth2.Config{
			ClientID:     client.ClientID,
			ClientSecret: client.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  client.RedirectURIS[0],
			Scopes:       strings.Split(client.Scope, " "),
		},
		Provider: provider,
		IDTokenVerifier: provider.Verifier(
			&oidc.Config{
				ClientID: client.ClientID,
			},
		),
	}, nil
}

// GetExplicitRegistration returns an explicit client registration as OpenIDRelyingPartMetadata. It re-uses an
// explicit client registration from cache or registers a new one.
func (f FederationLeaf) GetExplicitRegistration(op string) (
	*OpenIDRelyingPartyMetadata, *http.HttpError, error,
) {
	var client OpenIDRelyingPartyMetadata
	found, err := cache.Get(cache.Key(cache.KeyExplicitRegistration, op), &client)
	if err != nil {
		log.WithError(err).Error("error retrieving explicit registration from cache")
	}
	if found {
		return &client, nil, nil
	}
	resp, errRes, err := f.DoExplicitClientRegistration(op)
	if err != nil || errRes != nil {
		return nil, errRes, err
	}
	if resp == nil || resp.Metadata == nil || resp.Metadata.RelyingParty == nil {
		return nil, nil, errors.New("explicit client registration: unexpected response")
	}
	client = *resp.Metadata.RelyingParty
	err = cache.Set(
		cache.Key(cache.KeyExplicitRegistration, op), client, time.Until(resp.ExpiresAt.Time.Add(-10*time.Second)),
	)
	if err != nil {
		log.WithError(err).Error("error caching explicit registration")
	}
	return &client, nil, nil
}

// DoExplicitClientRegistration performs an explicit client registration with
// an OP and returns the response as an EntityStatementPayload.
func (f FederationLeaf) DoExplicitClientRegistration(op string) (
	*EntityStatementPayload, *http.HttpError, error,
) {
	opMetadata, err := f.ResolveOPMetadata(op)
	if err != nil {
		return nil, nil, err
	}
	if opMetadata == nil || opMetadata.FederationRegistrationEndpoint == "" {
		return nil, nil, errors.New("op does not have a federation registration endpoint")
	}
	entityConfigurationData := f.EntityConfigurationPayload()
	AdjustRPMetadataToOP(entityConfigurationData.Metadata.RelyingParty, opMetadata)
	entityConfigurationData.Audience = op
	entityConfiguration, err := f.EntityStatementSigner.JWT(entityConfigurationData)
	if err != nil {
		return nil, nil, err
	}
	resp, errRes, err := http.Post(
		opMetadata.FederationRegistrationEndpoint,
		entityConfiguration,
		nil, map[string]string{
			fiber.HeaderContentType: oidfedconst.ContentTypeEntityStatement,
		},
	)
	if err != nil || errRes != nil {
		return nil, errRes, err
	}
	if !strings.EqualFold(
		resp.Header().Get(fiber.HeaderContentType), oidfedconst.ContentTypeExplicitRegistrationResponse,
	) {
		return nil, nil, errors.New("explicit client registration: unexpected content type in response")
	}

	opEntityConfiguration, err := GetEntityConfiguration(op)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not get OP entity configuration")
	}

	res, err := parseExplicitRegistrationResponse(resp.Body(), opEntityConfiguration.JWKS)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not parse explicit registration response")
	}
	if res.Audience != f.EntityID {
		return nil, nil,
			errors.New("explicit client registration: OP returned unexpected audience")
	}
	return res, nil, nil
}

func parseExplicitRegistrationResponse(
	jwt []byte,
	keys jwx2.JWKS,
) (*EntityStatementPayload, error) {
	parsed, err := jwx.Parse(jwt)
	if err != nil {
		return nil, err
	}
	if !parsed.VerifyType(oidfedconst.JWTTypeExplicitRegistrationResponse) {
		return nil, errors.Errorf(
			"explicit client registration response does not have '%s' JWT type",
			oidfedconst.JWTTypeExplicitRegistrationResponse,
		)
	}
	data, err := parsed.VerifyWithSet(keys)
	if err != nil {
		return nil, errors.Wrap(err, "could not verify explicit registration response")
	}
	var payload EntityStatementPayload
	if err = json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	return &payload, err
}

// AdjustRPMetadataToOP adjusts the RP metadata so it complies with the OP capabilities.
//   - For RP fields with multiple values, it filters them to those supported by the OP.
//   - For RP single-value fields with an OP "..._supported" list, it ensures the RP value is supported; if not,
//     it looks for an Extra entry on the RP with the same name as the OP claim to pick a mutually supported value.
func AdjustRPMetadataToOP(rp *OpenIDRelyingPartyMetadata, op *OpenIDProviderMetadata) {
	if rp == nil || op == nil {
		return
	}

	// Build a mapping for OP base claim names to RP json tags when they differ.
	// base name = OP tag with trailing _supported or _values_supported removed.
	opBaseToRPTag := map[string]string{
		// singular/plural or naming differences
		"subject_types":                "subject_type",
		"acr":                          "default_acr_values", // The op key here is acr instead of acr_values, because the algorithm below also trims the _values
		"token_endpoint_auth_methods":  "token_endpoint_auth_method",
		"scopes":                       "scope",
		"introspection_signing_alg":    "introspection_signed_response_alg",
		"introspection_encryption_alg": "introspection_encrypted_response_alg",
		"introspection_encryption_enc": "introspection_encrypted_response_enc",
		"id_token_signing_alg":         "id_token_signed_response_alg",
		"id_token_encryption_alg":      "id_token_encrypted_response_alg",
		"id_token_encryption_enc":      "id_token_encrypted_response_enc",
	}

	// Pre-index RP struct fields by JSON tag for O(1) lookups inside the loop.
	rpVal := reflect.ValueOf(rp).Elem()
	rpType := rpVal.Type()
	type rpFieldInfo struct {
		val reflect.Value
		typ reflect.StructField
	}
	rpFields := make(map[string]rpFieldInfo, rpType.NumField())
	for j := 0; j < rpType.NumField(); j++ {
		rf := rpType.Field(j)
		rj := rf.Tag.Get("json")
		if rj == "" {
			continue
		}
		rj, _, _ = strings.Cut(rj, ",")
		if rj == "-" || rj == "" {
			continue
		}
		rpFields[rj] = rpFieldInfo{
			val: rpVal.Field(j),
			typ: rf,
		}
	}

	// Iterate over OP fields and react to any `*_supported` slice claims.
	opVal := reflect.ValueOf(op).Elem()
	opType := opVal.Type()
	for i := 0; i < opType.NumField(); i++ {
		sf := opType.Field(i)
		jsonTag := sf.Tag.Get("json")
		if jsonTag == "" {
			continue
		}
		jsonTag, _, _ = strings.Cut(jsonTag, ",")

		// We only care about []string fields that end with "_supported"
		if !strings.HasSuffix(jsonTag, "_supported") {
			continue
		}
		if sf.Type.Kind() != reflect.Slice || sf.Type.Elem().Kind() != reflect.String {
			continue
		}

		supported := opVal.Field(i).Interface().([]string)
		// If OP does not declare anything, do not constrain the RP.
		if len(supported) == 0 {
			continue
		}

		// Compute base name, then RP tag name.
		base := strings.TrimSuffix(jsonTag, "_values_supported")
		base = strings.TrimSuffix(base, "_supported")
		rpTag := opBaseToRPTag[base]
		if rpTag == "" {
			rpTag = base
		}

		// Find the RP field by json tag using the prebuilt index.
		info, ok := rpFields[rpTag]
		if !ok {
			// No corresponding RP field; nothing to do.
			continue
		}
		rpFieldVal := info.val
		rpFieldType := info.typ

		// Special handling: space-separated string list, e.g. scope
		if rpFieldVal.Kind() == reflect.String && rpTag == "scope" {
			if rpFieldVal.String() == "" {
				continue
			}
			if len(supported) == 0 {
				// OP did not restrict; keep as is.
				continue
			}
			values := strings.Fields(rpFieldVal.String())
			values = intersectPreserveA(values, supported)
			rpFieldVal.SetString(strings.Join(values, " "))
			continue
		}

		switch rpFieldVal.Kind() {
		case reflect.Slice:
			// Filter RP slice values to only those supported by OP; preserve RP order.
			if rpFieldType.Type.Elem().Kind() == reflect.String {
				current := rpFieldVal.Interface().([]string)
				if len(supported) == 0 {
					// No restriction declared; keep as is.
					continue
				}
				filtered := intersectPreserveA(current, supported)
				rpFieldVal.Set(reflect.ValueOf(filtered))
			}
		case reflect.String:
			// Ensure single value is supported. Otherwise try Extra[rp-op-claim] selection.
			cur := rpFieldVal.String()
			if cur != "" && slices.Contains(supported, cur) {
				continue
			}
			if len(supported) == 0 {
				// OP does not restrict; keep current value.
				continue
			}
			// Use RP.Extra with the OP claim name (original OP json tag)
			choice := chooseSingleOrFromExtra(cur, rp.Extra, jsonTag, supported)
			if choice != "" {
				rpFieldVal.SetString(choice)
			} else {
				// No compatible value; clear it to indicate incompatibility.
				rpFieldVal.SetString("")
			}
		}
	}
}

// chooseSingleOrFromExtra returns v if it is contained in supported. Otherwise it looks into extra[extraKey]
// for a list of values and returns the first value that is contained in supported. If nothing matches, returns "".
func chooseSingleOrFromExtra(v string, extra map[string]any, extraKey string, supported []string) string {
	if len(supported) == 0 {
		// OP does not declare restrictions; keep the original value
		return v
	}
	if v != "" && slices.Contains(supported, v) {
		return v
	}
	// Try to read RP's supported values from Extra using the OP claim name
	if extra != nil {
		if raw, ok := extra[extraKey]; ok {
			if vals := toStringSlice(raw); len(vals) > 0 {
				// Prefer RP order from Extra
				for _, cand := range vals {
					if slices.Contains(supported, cand) {
						return cand
					}
				}
			}
		}
	}
	// No match; return empty to indicate unset/incompatible
	return ""
}

// intersectPreserveA returns elements of a that are also in b, preserving order of a.
func intersectPreserveA(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	out := make([]string, 0, len(a))
	for _, v := range a {
		if slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}

// toStringSlice attempts to convert interfaces from Extra into []string.
func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, i := range t {
			if s, ok := i.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	default:
		return nil
	}
}
