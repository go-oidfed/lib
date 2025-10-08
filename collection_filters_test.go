package oidfed

import (
	"testing"

	"github.com/go-oidfed/lib/apimodel"
)

func TestFilterAndTrim_EntityTypesFilter(t *testing.T) {
	e1 := &CollectedEntity{EntityID: "e1", EntityTypes: []string{"openid_provider"}}
	e2 := &CollectedEntity{EntityID: "e2", EntityTypes: []string{"federation_entity"}}

	got := FilterAndTrimEntities([]*CollectedEntity{e1, e2}, apimodel.EntityCollectionRequest{
		EntityTypes: []string{"openid_provider"},
	})

	if len(got) != 1 || got[0].EntityID != "e1" {
		t.Fatalf("expected only e1, got %+v", got)
	}
}

func TestFilterAndTrim_QueryFuzzy(t *testing.T) {
	e := &CollectedEntity{
		EntityID:    "e1",
		EntityTypes: []string{"openid_provider"},
		UIInfos: map[string]UIInfo{
			"openid_provider": {DisplayName: "Amazing Service", Extra: map[string]any{"display_name#en": "Amazing Service"}},
		},
	}

	got := FilterAndTrimEntities([]*CollectedEntity{e}, apimodel.EntityCollectionRequest{Query: "amaz"})
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
}

func TestFilterAndTrim_TrustMarks(t *testing.T) {
	e1 := &CollectedEntity{EntityID: "e1", TrustMarks: TrustMarkInfos{{TrustMarkType: "type1"}}}
	e2 := &CollectedEntity{EntityID: "e2", TrustMarks: TrustMarkInfos{{TrustMarkType: "type2"}}}

	got := FilterAndTrimEntities([]*CollectedEntity{e1, e2}, apimodel.EntityCollectionRequest{TrustMarkTypes: []string{"type1"}})
	if len(got) != 1 || got[0].EntityID != "e1" {
		t.Fatalf("expected only e1 by trust mark filter, got %+v", got)
	}
}

func TestTrim_LanguageFiltering(t *testing.T) {
	e := &CollectedEntity{
		EntityID: "e1",
		UIInfos: map[string]UIInfo{
			"openid_provider": {
				DisplayName: "Default Name",
				Extra: map[string]any{
					"display_name#en": "English Name",
					"display_name#de": "Deutscher Name",
				},
			},
		},
	}

	got := FilterAndTrimEntities([]*CollectedEntity{e}, apimodel.EntityCollectionRequest{
		UIClaims:     []string{"display_name"},
		LanguageTags: []string{"en"},
	})

	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	ui := got[0].UIInfos["openid_provider"]
	if ui.DisplayName != "Default Name" {
		t.Fatalf("expected default display name kept, got %q", ui.DisplayName)
	}
	if ui.Extra == nil || ui.Extra["display_name#en"] != "English Name" {
		t.Fatalf("expected only English extra kept, got %+v", ui.Extra)
	}
	if _, ok := ui.Extra["display_name#de"]; ok {
		t.Fatalf("did not expect German extra to be present: %+v", ui.Extra)
	}
}
