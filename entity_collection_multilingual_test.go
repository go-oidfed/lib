package oidfed

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-oidfed/lib/apimodel"
)

func TestMultilingualUIInfo(t *testing.T) {
	// Create a test entity
	entity := &CollectedEntity{EntityID: "test-entity"}

	// Test setting multilingual values
	err := entity.setMultilingualUIInfoField("openid_provider", "description", "", "Default description")
	assert.NoError(t, err)

	err = entity.setMultilingualUIInfoField("openid_provider", "description", "en", "English description")
	assert.NoError(t, err)

	err = entity.setMultilingualUIInfoField("openid_provider", "description", "fr", "Description en français")
	assert.NoError(t, err)

	err = entity.setMultilingualUIInfoField("openid_provider", "description", "de", "Deutsche Beschreibung")
	assert.NoError(t, err)

	// Verify the default value is used when no language tag is specified
	assert.Equal(t, "Default description", entity.UIInfos["openid_provider"].Description)

	// Verify multilingual values are NOT stored in the old format (multilingual_description)
	_, ok := entity.UIInfos["openid_provider"].Extra["multilingual_description"]
	assert.False(t, ok, "multilingual_description should not be present")

	// Verify multilingual values are stored in the new format (description#langTag)
	assert.Equal(t, "English description", entity.UIInfos["openid_provider"].Extra["description#en"])
	assert.Equal(t, "Description en français", entity.UIInfos["openid_provider"].Extra["description#fr"])
	assert.Equal(t, "Deutsche Beschreibung", entity.UIInfos["openid_provider"].Extra["description#de"])
}

// TestNoMultilingualPrefix tests that the multilingual_ prefix is not used in the response
func TestNoMultilingualPrefix(t *testing.T) {
	// Create a test entity
	entity := &CollectedEntity{EntityID: "test-entity"}

	// Set values for all multilingual fields
	err := entity.setMultilingualUIInfoField("openid_provider", "display_name", "", "Default Name")
	assert.NoError(t, err)
	err = entity.setMultilingualUIInfoField("openid_provider", "display_name", "en", "English Name")
	assert.NoError(t, err)

	err = entity.setMultilingualUIInfoField("openid_provider", "description", "", "Default description")
	assert.NoError(t, err)
	err = entity.setMultilingualUIInfoField("openid_provider", "description", "en", "English description")
	assert.NoError(t, err)

	err = entity.setMultilingualUIInfoField("openid_provider", "logo_uri", "", "https://example.com/logo.png")
	assert.NoError(t, err)
	err = entity.setMultilingualUIInfoField("openid_provider", "logo_uri", "en", "https://example.com/logo-en.png")
	assert.NoError(t, err)

	// Check that no multilingual_ prefixed fields are present in the Extra map
	extra := entity.UIInfos["openid_provider"].Extra
	for key := range extra {
		assert.False(
			t, strings.HasPrefix(key, "multilingual_"),
			"Key %s should not have multilingual_ prefix", key,
		)
	}

	// Check that the tag#langTag format is used
	assert.Equal(t, "English Name", extra["display_name#en"])
	assert.Equal(t, "English description", extra["description#en"])
	assert.Equal(t, "https://example.com/logo-en.png", extra["logo_uri#en"])
}

func TestLanguageFiltering(t *testing.T) {
	// Create a test entity and metadata
	entity := &CollectedEntity{EntityID: "test-entity"}

	// Set up multilingual values directly in the UIInfo
	uiInfo := UIInfo{
		Description: "Default description",
		Extra: map[string]any{
			"multilingual_description": MultilingualString{
				"":   "Default description",
				"en": "English description",
				"fr": "Description en français",
				"de": "Deutsche Beschreibung",
			},
		},
	}
	entity.UIInfos = map[string]UIInfo{
		"openid_provider": uiInfo,
	}

	// Test language filtering with shouldIncludeLanguage
	assert.True(t, shouldIncludeLanguage("", []string{"en"}), "Default language should always be included")
	assert.True(t, shouldIncludeLanguage("en", []string{"en"}), "Requested language should be included")
	assert.False(t, shouldIncludeLanguage("fr", []string{"en"}), "Non-requested language should not be included")
	assert.True(
		t, shouldIncludeLanguage(
			"fr", []string{
				"en",
				"fr",
			},
		), "Multiple requested languages should be included",
	)
	assert.True(
		t, shouldIncludeLanguage("fr", []string{}), "All languages should be included when no filter is specified",
	)
}

func TestReadingMultilingualMetadata(t *testing.T) {
	// Create a test metadata with multilingual values in the new format
	metadata := Metadata{
		OpenIDProvider: &OpenIDProviderMetadata{
			Description: "Default description",
			Extra: map[string]any{
				"description#en": "English description",
				"description#fr": "Description en français",
				"description#de": "Deutsche Beschreibung",
			},
		},
	}

	// Create a map to collect the values
	collected := make(map[string]map[string]string)

	// Use IterateMultilingualStringClaim to read the values
	metadata.IterateMultilingualStringClaim(
		"description", func(entityType, langTag, value string) {
			if collected[entityType] == nil {
				collected[entityType] = make(map[string]string)
			}
			collected[entityType][langTag] = value
		},
	)

	// Verify that all values were collected
	assert.Equal(t, "Default description", collected["openid_provider"][""])
	assert.Equal(t, "English description", collected["openid_provider"]["en"])
	assert.Equal(t, "Description en français", collected["openid_provider"]["fr"])
	assert.Equal(t, "Deutsche Beschreibung", collected["openid_provider"]["de"])
}

func TestMultilingualDisplayNames(t *testing.T) {
	// Create a test metadata with multilingual display names
	metadata := Metadata{
		OpenIDProvider: &OpenIDProviderMetadata{
			DisplayName: "Default Display Name",
			Extra: map[string]any{
				"display_name#en": "English Display Name",
				"display_name#fr": "Nom d'affichage en français",
				"display_name#de": "Deutscher Anzeigename",
			},
		},
	}

	// Get multilingual display names
	multilingualDisplayNames := metadata.GuessMultilingualDisplayNames()

	// Verify that all display names were collected
	assert.Equal(t, "Default Display Name", multilingualDisplayNames["openid_provider"][""])
	assert.Equal(t, "English Display Name", multilingualDisplayNames["openid_provider"]["en"])
	assert.Equal(t, "Nom d'affichage en français", multilingualDisplayNames["openid_provider"]["fr"])
	assert.Equal(t, "Deutscher Anzeigename", multilingualDisplayNames["openid_provider"]["de"])

	// Create an entity and process UI claims
	entity := &CollectedEntity{
		EntityID: "test-entity",
		metadata: &metadata,
	}

	// Create a request with language filtering
	req := apimodel.EntityCollectionRequest{
		LanguageTags: []string{
			"en",
			"fr",
		}, // Only include English and French
	}

	// Process UI claims
	entityStatement := &EntityStatement{
		EntityStatementPayload: EntityStatementPayload{
			Metadata: &metadata,
		},
	}
	processUIClaims(entity, entityStatement, req)

	// Verify that only the default, English, and French display names were included
	assert.Equal(t, "Default Display Name", entity.UIInfos["openid_provider"].DisplayName)
	assert.Equal(t, "English Display Name", entity.UIInfos["openid_provider"].Extra["display_name#en"])
	assert.Equal(t, "Nom d'affichage en français", entity.UIInfos["openid_provider"].Extra["display_name#fr"])

	// German should not be included due to language filtering
	_, germanExists := entity.UIInfos["openid_provider"].Extra["display_name#de"]
	assert.False(t, germanExists, "German display name should not be included")
}

// TestMultilingualDisplayNameMatching tests that the shouldIncludeEntity function
// correctly matches multilingual display names against a query
func TestMultilingualDisplayNameMatching(t *testing.T) {
	// Create a test metadata with multilingual display names
	metadata := &Metadata{
		OpenIDProvider: &OpenIDProviderMetadata{
			DisplayName: "Default Display Name",
			Extra: map[string]any{
				"display_name#en": "English Display Name",
				"display_name#fr": "Nom d'affichage en français",
				"display_name#de": "Deutscher Anzeigename",
			},
		},
	}

	// Create an entity statement with the metadata
	entityConfig := &EntityStatement{
		EntityStatementPayload: EntityStatementPayload{
			Metadata: metadata,
		},
	}

	// Create a collector result for testing
	collector := &collectorResult{}

	// Test cases for different queries
	testCases := []struct {
		name     string
		query    string
		expected bool
	}{
		{
			"Match default language",
			"Default",
			true,
		},
		{
			"Match English",
			"English",
			true,
		},
		{
			"Match French",
			"français",
			true,
		},
		{
			"Match German",
			"Deutscher",
			true,
		},
		{
			"No match",
			"nonexistent",
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				// Create a request with the query
				req := apimodel.EntityCollectionRequest{
					Query: tc.query,
				}

				// Check if the entity should be included
				result := collector.shouldIncludeEntity(entityConfig, []string{"openid_provider"}, req)

				// Verify the result
				assert.Equal(
					t, tc.expected, result, "shouldIncludeEntity returned unexpected result for query: %s", tc.query,
				)
			},
		)
	}
}
