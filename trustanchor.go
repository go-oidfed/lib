package oidfed

import (
	"encoding/base64"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/zachmann/go-utils/duration"
	"gopkg.in/yaml.v3"

	"github.com/go-oidfed/lib/jwx"
)

// TrustAnchor is a type for specifying trust anchors
type TrustAnchor struct {
	EntityID         string                  `json:"entity_id"`
	JWKSFile         string                  `json:"jwks_file"`
	EnableJWKSUpdate bool                    `json:"enable_jwks_update"`
	KeyPollInterval  duration.DurationOption `json:"key_poll_interval"`

	jwks atomic.Pointer[jwx.JWKS] // Private, thread-safe storage
}

// UnmarshalYAML implements custom YAML unmarshaling to handle both legacy 'jwks' field
// and new 'jwks_file' field. It loads JWKS from file if jwks_file is specified.
func (t *TrustAnchor) UnmarshalYAML(node *yaml.Node) error {
	// Create a map to manually parse the YAML node
	var rawMap map[string]interface{}
	if err := node.Decode(&rawMap); err != nil {
		return fmt.Errorf("failed to decode TrustAnchor YAML: %w", err)
	}

	// Extract standard fields
	if entityID, ok := rawMap["entity_id"].(string); ok {
		t.EntityID = entityID
	}

	if jwksFile, ok := rawMap["jwks_file"].(string); ok {
		t.JWKSFile = jwksFile
	}

	if enableUpdate, ok := rawMap["enable_jwks_update"].(bool); ok {
		t.EnableJWKSUpdate = enableUpdate
	}

	// Handle key_poll_interval using duration.DurationOption's unmarshal logic
	if intervalVal, ok := rawMap["key_poll_interval"]; ok {
		var interval duration.DurationOption
		intervalNode, err := encodeToYAMLNode(intervalVal)
		if err == nil {
			if err := interval.UnmarshalYAML(intervalNode); err == nil {
				t.KeyPollInterval = interval
			}
		}
	}

	// Handle legacy 'jwks' field OR load from 'jwks_file'
	var jwksData jwx.JWKS
	var jwksLoaded bool

	// First, try to load from jwks_file if specified
	if t.JWKSFile != "" {
		loadedJWKS, err := loadJWKSFromFile(t.JWKSFile)
		if err != nil {
			return fmt.Errorf("failed to load JWks from file %q: %w", t.JWKSFile, err)
		}
		jwksData = loadedJWKS
		jwksLoaded = true
	}

	// If jwks_file wasn't specified or didn't load, try legacy 'jwks' field
	if !jwksLoaded {
		if jwksRaw, ok := rawMap["jwks"]; ok && jwksRaw != nil {
			// Convert the raw jwks data back to YAML for proper unmarshaling
			jwksNode, err := encodeToYAMLNode(jwksRaw)
			if err == nil {
				if err := jwksData.UnmarshalYAML(jwksNode); err == nil && jwksData.Set != nil {
					jwksLoaded = true
				}
			}
		}
	}

	// Store in atomic pointer if we have JWKS data
	if jwksLoaded && jwksData.Set != nil && jwksData.Len() > 0 {
		t.jwks.Store(&jwksData)
	}

	return nil
}

// encodeToYAMLNode converts a Go value to a yaml.Node for unmarshaling
func encodeToYAMLNode(v interface{}) (*yaml.Node, error) {
	data, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	// Return the content of the document node
	if len(node.Content) > 0 {
		return node.Content[0], nil
	}
	return &node, nil
}

// loadJWKSFromFile loads a JWKS from a JSON file
func loadJWKSFromFile(filepath string) (jwx.JWKS, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return jwx.JWKS{}, err
	}
	var jwks jwx.JWKS
	if err := jwks.UnmarshalJSON(data); err != nil {
		return jwx.JWKS{}, err
	}
	return jwks, nil
}

// MarshalYAML implements custom YAML marshaling for serialization
func (t TrustAnchor) MarshalYAML() (interface{}, error) {
	type Alias TrustAnchor
	result := map[string]interface{}{
		"entity_id":          t.EntityID,
		"jwks_file":          t.JWKSFile,
		"enable_jwks_update": t.EnableJWKSUpdate,
		"key_poll_interval":  t.KeyPollInterval,
	}

	// Include inline jwks if available (for debugging/serialization)
	jwks := t.JWKS()
	if jwks.Set != nil && jwks.Len() > 0 {
		result["jwks"] = jwks
	}

	return result, nil
}

// JWKS returns the current JWKS in a thread-safe manner
func (t *TrustAnchor) JWKS() jwx.JWKS {
	if p := t.jwks.Load(); p != nil {
		return *p
	}
	return jwx.JWKS{}
}

// SetJWKS sets the JWKS in a thread-safe manner
func (t *TrustAnchor) SetJWKS(jwks jwx.JWKS) {
	t.jwks.Store(&jwks)
}

// TrustAnchors is a slice of TrustAnchor
type TrustAnchors []*TrustAnchor

// EntityIDs returns the entity ids as a []string
func (anchors TrustAnchors) EntityIDs() (entityIDs []string) {
	for _, ta := range anchors {
		entityIDs = append(entityIDs, ta.EntityID)
	}
	return
}

// NewTrustAnchorsFromEntityIDs returns TrustAnchors for the passed entity ids; this does not set jwks.JWKS
func NewTrustAnchorsFromEntityIDs(anchorIDs ...string) (anchors TrustAnchors) {
	for _, id := range anchorIDs {
		ta := &TrustAnchor{EntityID: id}
		anchors = append(anchors, ta)
	}
	return
}

// GetByEntityID finds and returns a pointer to the TrustAnchor with the given entity ID
// Returns nil if not found
func (anchors TrustAnchors) GetByEntityID(entityID string) *TrustAnchor {
	for i := range anchors {
		if anchors[i].EntityID == entityID {
			return anchors[i]
		}
	}
	return nil
}

// encodedEntityID encodes an entity ID to a URL-safe base64 string for use in filenames
func encodedEntityID(entityID string) string {
	return base64.URLEncoding.EncodeToString([]byte(entityID))
}

// DecodedEntityID decodes a URL-safe base64 encoded entity ID
func DecodedEntityID(encoded string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
