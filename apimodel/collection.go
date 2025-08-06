package apimodel

// EntityCollectionRequest is a request to the entity collection endpoint.
// It supports filtering entities by various criteria, including entity types,
// trust mark types, and UI claims. It also supports filtering UI claims by
// language tags according to BCP47 (RFC5646).
type EntityCollectionRequest struct {
	FromEntityID   string   `json:"from_entity_id" form:"from_entity_id" query:"from_entity_id" url:"from_entity_id"`
	Limit          uint64   `json:"limit" form:"limit" query:"limit" url:"limit"`
	EntityTypes    []string `json:"entity_type" form:"entity_type" query:"entity_type" url:"entity_type"`
	TrustMarkTypes []string `json:"trust_mark_type" form:"trust_mark_type" query:"trust_mark_type" url:"trust_mark_type"`
	TrustAnchor    string   `json:"trust_anchor" form:"trust_anchor" query:"trust_anchor" url:"trust_anchor"`
	Query          string   `json:"query" form:"query" query:"query"`
	EntityClaims   []string `json:"entity_claims" form:"entity_claims" query:"entity_claims" url:"entity_claims"`
	UIClaims       []string `json:"ui_claims" form:"ui_claims" query:"ui_claims" url:"ui_claims"`
	// LanguageTags specifies the preferred language tags according to BCP47 (RFC5646)
	// If provided, UI claims will be filtered to include only these languages
	// If not provided, all available languages will be included in the response
	// Multiple values can be provided in order of preference
	LanguageTags []string `json:"language_tags" form:"language_tags" query:"language_tags" url:"language_tags"`
}
