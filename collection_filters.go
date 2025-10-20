package oidfed

import (
	"slices"

	"github.com/go-oidfed/lib/apimodel"
)

// FilterAndTrimEntities applies request filters to a list of collected entities
// and trims the result to the requested claims and languages.
func FilterAndTrimEntities(cached []*CollectedEntity, req apimodel.EntityCollectionRequest) []*CollectedEntity {
	var out []*CollectedEntity
	for _, e := range cached {
		if e == nil {
			continue
		}
		if !passesFilters(e, req) {
			continue
		}
		out = append(out, trimEntity(e, req))
	}
	return out
}

func passesFilters(e *CollectedEntity, req apimodel.EntityCollectionRequest) bool {
	// Entity types overlap
	if len(req.EntityTypes) > 0 && len(e.EntityTypes) > 0 {
		var ok bool
		for _, et := range e.EntityTypes {
			if slices.Contains(req.EntityTypes, et) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}

	// Fuzzy query over multilingual display_name values
	if req.Query != "" {
		names := collectAllDisplayNames(e)
		if !matchWithMode(req.Query, names, MatchModeFuzzy) {
			return false
		}
	}

	// Trust mark types must all be present
	if len(req.TrustMarkTypes) > 0 {
		for _, t := range req.TrustMarkTypes {
			if e.TrustMarks.FindByType(t) == nil {
				return false
			}
		}
	}
	return true
}

// trimEntity reduces the entity to the requested claims and languages.
func trimEntity(e *CollectedEntity, req apimodel.EntityCollectionRequest) *CollectedEntity {
	out := &CollectedEntity{EntityID: e.EntityID}

	includeAllClaims := len(req.EntityClaims) == 0

	if includeAllClaims || contains(req.EntityClaims, "entity_types") {
		out.EntityTypes = append([]string(nil), e.EntityTypes...)
	}

	if includeAllClaims || contains(req.EntityClaims, "trust_marks") {
		out.TrustMarks = e.TrustMarks
	}

	includeAllUI := len(req.UIClaims) == 0
	if includeAllClaims || includeAllUI || anyUIRequested(req.UIClaims) {
		out.UIInfos = make(map[string]UIInfo, len(e.UIInfos))
		for et, ui := range e.UIInfos {
			var outUI UIInfo
			if includeAllUI || contains(req.UIClaims, "keywords") {
				outUI.Keywords = append([]string(nil), ui.Keywords...)
			}
			if includeAllUI || contains(req.UIClaims, "display_name") {
				outUI.DisplayName = ui.DisplayName
				outUI.Extra = filterLangExtras(ui.Extra, "display_name", req.LanguageTags)
			}
			if includeAllUI || contains(req.UIClaims, "description") {
				outUI.Description = ui.Description
				mergeExtras(&outUI, filterLangExtras(ui.Extra, "description", req.LanguageTags))
			}
			if includeAllUI || contains(req.UIClaims, "logo_uri") {
				outUI.LogoURI = ui.LogoURI
				mergeExtras(&outUI, filterLangExtras(ui.Extra, "logo_uri", req.LanguageTags))
			}
			if includeAllUI || contains(req.UIClaims, "policy_uri") {
				outUI.PolicyURI = ui.PolicyURI
				mergeExtras(&outUI, filterLangExtras(ui.Extra, "policy_uri", req.LanguageTags))
			}
			if includeAllUI || contains(req.UIClaims, "information_uri") {
				outUI.InformationURI = ui.InformationURI
				mergeExtras(&outUI, filterLangExtras(ui.Extra, "information_uri", req.LanguageTags))
			}
			if !isEmptyUIInfo(outUI) {
				out.UIInfos[et] = outUI
			}
		}
		if len(out.UIInfos) == 0 {
			out.UIInfos = nil
		}
	}

	return out
}

func contains(list []string, s string) bool {
	return slices.Contains(list, s)
}

func anyUIRequested(ss []string) bool {
	for _, v := range ss {
		switch v {
		case "display_name", "description", "logo_uri", "policy_uri", "information_uri", "keywords":
			return true
		}
	}
	return false
}

func collectAllDisplayNames(e *CollectedEntity) []string {
	var names []string
	for _, ui := range e.UIInfos {
		if ui.DisplayName != "" {
			names = append(names, ui.DisplayName)
		}
		for k, v := range ui.Extra {
			if len(k) >= len("display_name") && k[:len("display_name")] == "display_name" {
				if s, ok := v.(string); ok && s != "" {
					names = append(names, s)
				}
			}
		}
	}
	return names
}

func filterLangExtras(extra map[string]any, field string, requested []string) map[string]any {
	if extra == nil {
		return nil
	}
	out := make(map[string]any)
	for k, v := range extra {
		// match keys like "field#lang"
		if len(k) <= len(field)+1 || k[:len(field)] != field || k[len(field)] != '#' {
			continue
		}
		lang := k[len(field)+1:]
		if shouldIncludeLanguage(lang, requested) {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeExtras(dst *UIInfo, extras map[string]any) {
	if len(extras) == 0 {
		return
	}
	if dst.Extra == nil {
		dst.Extra = make(map[string]any)
	}
	for k, v := range extras {
		dst.Extra[k] = v
	}
}

func isEmptyUIInfo(i UIInfo) bool {
	return i.DisplayName == "" && i.Description == "" && len(i.Keywords) == 0 && i.LogoURI == "" && i.PolicyURI == "" && i.InformationURI == "" && len(i.Extra) == 0
}
