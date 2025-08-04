package oidfed

import (
	"encoding/json"
	"testing"

	"github.com/go-oidfed/lib/internal/jwx"
)

func TestRequestObjectProducer_RequestObject(t *testing.T) {
	rop := NewRequestObjectProducer(rp1.EntityID, rp1.versatileSigner, 60)
	emptyKeys := []string{
		"sub",
		"client_secret",
	}
	tests := []struct {
		name           string
		requestValues  map[string]any
		expectedValues map[string]any
	}{
		{
			name:          "only aud",
			requestValues: map[string]any{"aud": "https://aud.example.com"},
			expectedValues: map[string]any{
				"aud":       "https://aud.example.com",
				"iss":       rp1.EntityID,
				"client_id": rp1.EntityID,
			},
		},
		{
			name: "key:value",
			requestValues: map[string]any{
				"aud": "https://aud.example.com",
				"key": "value",
			},
			expectedValues: map[string]any{
				"aud":       "https://aud.example.com",
				"iss":       rp1.EntityID,
				"client_id": rp1.EntityID,
				"key":       "value",
			},
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				ro, err := rop.RequestObject(test.requestValues)
				if err != nil {
					t.Error(err)
					return
				}
				m, err := jwx.Parse(ro)
				if err != nil {
					t.Error(err)
					return
				}
				payload, err := m.VerifyWithSet(rp1.jwks)
				if err != nil {
					t.Error(err)
					return
				}
				var data map[string]any
				if err = json.Unmarshal(payload, &data); err != nil {
					t.Error(err)
					return
				}
				for k, v := range test.expectedValues {
					if data[k] != v {
						t.Errorf("request object '%s' is '%s' instead of '%s'", k, data[k], v)
						return
					}
				}
				for _, k := range emptyKeys {
					if _, set := data[k]; set {
						t.Errorf("request object has claim '%s' but must be empty", k)
						return
					}
				}
			},
		)
	}
}

func TestRequestObjectProducer_ClientAssertion(t *testing.T) {
	rop := NewRequestObjectProducer(rp1.EntityID, rp1.versatileSigner, 60)
	emptyKeys := []string{"client_id"}
	tests := []struct {
		name           string
		expectedValues map[string]string
		emptyKeys      []string
	}{
		{
			name: "only aud",
			expectedValues: map[string]string{
				"aud": "https://aud.example.com",
				"iss": rp1.EntityID,
				"sub": rp1.EntityID,
			},
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				assertion, err := rop.ClientAssertion(test.expectedValues["aud"])
				if err != nil {
					t.Error(err)
					return
				}
				m, err := jwx.Parse(assertion)
				if err != nil {
					t.Error(err)
					return
				}
				payload, err := m.VerifyWithSet(rp1.jwks)
				if err != nil {
					t.Error(err)
					return
				}
				var data map[string]any
				if err = json.Unmarshal(payload, &data); err != nil {
					t.Error(err)
					return
				}
				for k, v := range test.expectedValues {
					if data[k] != v {
						t.Errorf("request object '%s' is '%s' instead of '%s'", k, data[k], v)
						return
					}
				}
				for _, k := range emptyKeys {
					if _, set := data[k]; set {
						t.Errorf("request object has claim '%s' but must be empty", k)
						return
					}
				}
			},
		)
	}
}
