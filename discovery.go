package oidfed

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	arrays "github.com/adam-hanna/arrayOperations"
	"github.com/gofiber/fiber/v2/log"
	"github.com/google/go-querystring/query"
	"github.com/lithammer/fuzzysearch/fuzzy"
	"github.com/pkg/errors"
	"github.com/scylladb/go-set/strset"
	"github.com/zachmann/go-utils/sliceutils"

	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/cache"
	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/internal/http"
	"github.com/go-oidfed/lib/internal/utils"
	"github.com/go-oidfed/lib/oidfedconst"
	"github.com/go-oidfed/lib/unixtime"
)

const defaultSubordinateListingCacheTime = time.Hour

// EntityCollectionResponse is a type describing the response of an entity
// collection request
type EntityCollectionResponse struct {
	FederationEntities []*CollectedEntity `json:"federation_entities"`
	NextEntityID       string             `json:"next_entity_id,omitempty"`
	LastUpdated        *unixtime.Unixtime `json:"last_updated,omitempty"`
	Extra              map[string]any     `json:"-"`
}

// CollectedEntity is a type describing a single collected entity
type CollectedEntity struct {
	EntityID    string         `json:"entity_id"`
	TrustMarks  TrustMarkInfos `json:"trust_marks,omitempty"`
	TrustChain  JWSMessages    `json:"trust_chain,omitempty"`
	metadata    *Metadata
	EntityTypes []string          `json:"entity_types,omitempty"`
	UIInfos     map[string]UIInfo `json:"ui_infos,omitempty"`
	Extra       map[string]any    `json:"-"`
}

type UIInfo struct {
	DisplayName    string         `json:"display_name,omitempty"`
	Description    string         `json:"description,omitempty"`
	Keywords       []string       `json:"keywords,omitempty"`
	LogoURI        string         `json:"logo_uri,omitempty"`
	PolicyURI      string         `json:"policy_uri,omitempty"`
	InformationURI string         `json:"information_uri,omitempty"`
	Extra          map[string]any `json:"-"`
}

// setUInfoField sets a field in UIInfo	 by matching the JSON tag.
// Falls back to Extra if the field is not found or not assignable.
func (e *CollectedEntity) setUIInfoField(
	entityType, jsonTag string, value any,
) error {
	if e.UIInfos == nil {
		e.UIInfos = make(map[string]UIInfo)
	}

	uiInfo := e.UIInfos[entityType]
	uiInfoValue := reflect.ValueOf(&uiInfo).Elem()
	uiInfoType := uiInfoValue.Type()

	fieldFound := false

	for i := 0; i < uiInfoType.NumField(); i++ {
		structField := uiInfoType.Field(i)
		tag := structField.Tag.Get("json")
		tagName := tag
		if commaIdx := len(tag); commaIdx != -1 {
			tagName = tag[:commaIdx]
		}

		if tagName == jsonTag {
			fieldValue := uiInfoValue.Field(i)
			if fieldValue.CanSet() {
				val := reflect.ValueOf(value)
				if !val.Type().AssignableTo(fieldValue.Type()) {
					return fmt.Errorf(
						"cannot assign value of type %s to field %s of type %s", val.Type(), jsonTag, fieldValue.Type(),
					)
				}
				fieldValue.Set(val)
				fieldFound = true
				break
			}
		}
	}

	if !fieldFound {
		if uiInfo.Extra == nil {
			uiInfo.Extra = make(map[string]any)
		}
		uiInfo.Extra[jsonTag] = value
	}

	e.UIInfos[entityType] = uiInfo
	return nil
}

// MarshalJSON implements the json.Marshaler interface
func (e CollectedEntity) MarshalJSON() ([]byte, error) {
	type Alias CollectedEntity
	explicitFields, err := json.Marshal(Alias(e))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return extraMarshalHelper(explicitFields, e.Extra)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (e *CollectedEntity) UnmarshalJSON(data []byte) error {
	type Alias CollectedEntity
	ee := Alias(*e)

	extra, err := unmarshalWithExtra(data, &ee)
	if err != nil {
		return errors.WithStack(err)
	}
	ee.Extra = extra
	*e = CollectedEntity(ee)
	return nil
}

// MarshalJSON implements the json.Marshaler interface
func (i UIInfo) MarshalJSON() ([]byte, error) {
	type Alias UIInfo
	explicitFields, err := json.Marshal(Alias(i))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return extraMarshalHelper(explicitFields, i.Extra)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (i *UIInfo) UnmarshalJSON(data []byte) error {
	type Alias UIInfo
	ii := Alias(*i)

	extra, err := unmarshalWithExtra(data, &ii)
	if err != nil {
		return errors.WithStack(err)
	}
	ii.Extra = extra
	*i = UIInfo(ii)
	return nil
}

// EntityCollector is an interface that discovers / collects Entities in a
// federation
type EntityCollector interface {
	CollectEntities(req apimodel.EntityCollectionRequest) []*CollectedEntity
}

// SimpleEntityCollector is an EntityCollector that collects entities in a
// federation
type SimpleEntityCollector struct {
	visitedEntities *mutexedStrSet
}

type mutexedStrSet struct {
	set   *strset.Set
	mutex sync.RWMutex
}

func (ms *mutexedStrSet) Has(s ...string) bool {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	return ms.set.Has(s...)
}

func (ms *mutexedStrSet) Add(s ...string) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	ms.set.Add(s...)
}

func newMutexedStrSet() *mutexedStrSet {
	return &mutexedStrSet{
		set: strset.New(),
	}
}

// SimpleOPCollector is an EntityCollector that uses the
// SimpleEntityCollector to collect OPs in a federation
type SimpleOPCollector struct{}

// CollectEntities implements the EntityCollector interface
func (*SimpleOPCollector) CollectEntities(req apimodel.EntityCollectionRequest) (entities []*CollectedEntity) {
	req.EntityTypes = []string{"openid_provider"}
	return (&SimpleEntityCollector{}).CollectEntities(req)
}

// VerifiedChainsEntityCollector is an EntityCollector that compared to
// SimpleEntityCollector additionally verifies that there
// is a valid TrustChain between the entity and one of the specified trust
// anchors
type VerifiedChainsEntityCollector struct{}

// EntityCollectionFilter is an interface to filter discovered entities
type EntityCollectionFilter interface {
	Filter(*CollectedEntity) bool
}

type entityCollectionFilter struct {
	filter func(entity *CollectedEntity) bool
}

// Filter implements the EntityCollectionFilter interface
func (f entityCollectionFilter) Filter(entity *CollectedEntity) bool {
	return f.filter(entity)
}

// NewEntityCollectionFilter returns an EntityCollectionFilter for a filter func
func NewEntityCollectionFilter(filter func(entity *CollectedEntity) bool) EntityCollectionFilter {
	return entityCollectionFilter{filter: filter}
}

type filterableVerifiedChainsEntityCollector struct {
	Collector EntityCollector
	Filters   []EntityCollectionFilter
}

// FilterableVerifiedChainsEntityCollector is a type implementing
// EntityCollector
// that is able to filter the discovered OPs
// through a number of EntityCollectionFilter
type FilterableVerifiedChainsEntityCollector struct {
	Collector EntityCollector
	Filters   []EntityCollectionFilter
}

// CollectEntities implements the EntityCollector interface
func (d *SimpleEntityCollector) CollectEntities(req apimodel.EntityCollectionRequest) (entities []*CollectedEntity) {
	d.visitedEntities = newMutexedStrSet()
	return d.collect(req, NewTrustAnchorsFromEntityIDs(req.TrustAnchor)...)
}

const maxCollectWorkers = 128

func (d *SimpleEntityCollector) collect(
	req apimodel.EntityCollectionRequest, authorities ...TrustAnchor,
) (entities []*CollectedEntity) {
	internal.Logf("Discovering Entities for authorities: %+q", authorities)

	sem := make(chan struct{}, maxCollectWorkers)
	entityChan := make(chan *CollectedEntity)
	doneChan := make(chan struct{})

	var ta *EntityStatement
	var taErr error
	var taOnce sync.Once

	seen := make(map[string]bool)
	var seenMu sync.Mutex

	// Collector goroutine
	go func() {
		for e := range entityChan {
			seenMu.Lock()
			if !seen[e.EntityID] {
				seen[e.EntityID] = true
				entities = append(entities, e)
			}
			seenMu.Unlock()
		}
		doneChan <- struct{}{}
	}()

	var wg sync.WaitGroup

	// Wrapper to acquire worker token
	run := func(task func()) {
		sem <- struct{}{} // acquire
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }() // release
			task()
		}()
	}

	for _, authority := range authorities {
		run(
			func() {
				if d.visitedEntities.Has(authority.EntityID) {
					internal.Logf("Already visited: %s -> skipping", authority.EntityID)
					return
				}
				d.visitedEntities.Add(authority.EntityID)

				stmt, err := GetEntityConfiguration(authority.EntityID)
				if err != nil {
					internal.Logf("Could not get entity configuration: %s -> skipping", err.Error())
					return
				}

				if stmt.Metadata == nil || stmt.Metadata.FederationEntity == nil ||
					stmt.Metadata.FederationEntity.FederationListEndpoint == "" {
					internal.Log("No FederationListEndpoint -> skipping")
					return
				}

				subordinates, err := fetchList(stmt.Metadata.FederationEntity.FederationListEndpoint)
				if err != nil {
					internal.Logf("Could not fetch subordinates: %s", err.Error())
					return
				}

				for _, subordinateID := range subordinates {
					run(
						func() {
							entityConfig, err := GetEntityConfiguration(subordinateID)
							if err != nil {
								internal.Logf("Failed to get entity config for %s: %s", subordinateID, err.Error())
								return
							}
							if entityConfig.Metadata == nil {
								internal.Log("No metadata present -> skipping")
								return
							}

							et := entityConfig.Metadata.GuessEntityTypes()
							displayNames := entityConfig.Metadata.GuessDisplayNames()

							includeEntity := true
							if req.EntityTypes != nil && len(arrays.Intersect(et, req.EntityTypes)) == 0 {
								includeEntity = false
							}
							if req.NameQuery != "" && !matchDisplayName(req.NameQuery, displayNames, MatchModeFuzzy) {
								includeEntity = false
							}

							for _, trustMarkType := range req.TrustMarkTypes {
								trustMarkInfo := entityConfig.TrustMarks.FindByID(trustMarkType)
								if trustMarkInfo == nil {
									includeEntity = false
									break
								}
								taOnce.Do(
									func() {
										ta, taErr = GetEntityConfiguration(req.TrustAnchor)
									},
								)
								if taErr != nil || trustMarkInfo.VerifyFederation(&ta.EntityStatementPayload) != nil {
									includeEntity = false
									break
								}
							}

							if includeEntity {
								collectedEntity := &CollectedEntity{
									EntityID: subordinateID,
								}

								if req.Claims == nil || slices.Contains(req.Claims, "entity_types") {
									collectedEntity.EntityTypes = et
								}

								uiInfoClaims := []string{
									"description",
									"logo_uri",
									"policy_uri",
									"information_uri",
								}
								for _, c := range uiInfoClaims {
									if req.Claims == nil || slices.Contains(req.Claims, c) {
										entityConfig.Metadata.
											IterateStringClaim(
												c, func(entityType, value string) {
													collectedEntity.setUIInfoField(
														entityType, c, value,
													)
												},
											)
									}
								}
								keywordsTag := "keywords"
								if req.Claims == nil || slices.Contains(req.Claims, keywordsTag) {
									entityConfig.Metadata.
										IterateStringSliceClaim(
											keywordsTag,
											func(entityType string, value []string) {
												collectedEntity.setUIInfoField(
													entityType, keywordsTag, value,
												)
											},
										)
								}

								if req.Claims == nil || slices.Contains(req.Claims, "display_name") {
									for entityType, displayName := range displayNames {
										if displayName != "" {
											if err = collectedEntity.setUIInfoField(
												entityType, "display_name", displayName,
											); err != nil {
												log.Error(err.Error())
											}
										}
									}
								}

								if slices.ContainsFunc(
									req.Claims, func(c string) bool {
										return c == "metadata" || c == "trust_chain"
									},
								) {
									resolveRequest := apimodel.ResolveRequest{
										Subject:     subordinateID,
										TrustAnchor: []string{req.TrustAnchor},
									}
									var res ResolveResponsePayload
									switch resolver := DefaultMetadataResolver.(type) {
									case LocalMetadataResolver:
										res, _, err = resolver.resolveResponsePayloadWithoutTrustMarks(resolveRequest)
									default:
										res, err = DefaultMetadataResolver.ResolveResponsePayload(resolveRequest)
									}
									if err == nil {
										if res.TrustMarks != nil && slices.Contains(req.Claims, "trust_marks") {
											collectedEntity.TrustMarks = res.TrustMarks
										}
										if slices.Contains(req.Claims, "metadata") {
											collectedEntity.metadata = res.Metadata
										}
										if slices.Contains(req.Claims, "trust_chain") {
											collectedEntity.TrustChain = res.TrustChain
										}
									} else {
										internal.Logf(
											"Trust chain resolution failed for %s: %s", subordinateID, err.Error(),
										)
									}
								}

								if collectedEntity.TrustMarks == nil && slices.Contains(req.Claims, "trust_marks") {
									taOnce.Do(
										func() {
											ta, taErr = GetEntityConfiguration(req.TrustAnchor)
										},
									)
									if taErr == nil {
										collectedEntity.TrustMarks = entityConfig.TrustMarks.VerifiedFederation(&ta.EntityStatementPayload)
									}
								}

								entityChan <- collectedEntity
							}

							if entityConfig.Metadata.FederationEntity != nil &&
								entityConfig.Metadata.FederationEntity.FederationListEndpoint != "" {
								nested := d.collect(req, NewTrustAnchorsFromEntityIDs(subordinateID)...)
								for _, nestedEntity := range nested {
									entityChan <- nestedEntity
								}
							}
						},
					)
				}
			},
		)
	}

	// Wait and close channels
	go func() {
		wg.Wait()
		close(entityChan)
	}()

	<-doneChan
	return
}

type matchMode string

const (
	MatchModeSubstringCaseInsensitive matchMode = "substring-case-insensitive"
	MatchModeSubstringCaseSensitive   matchMode = "substring-case-sensitive"
	MatchModeExactCaseSensitive       matchMode = "exact-case-sensitive"
	MatchModeExactCaseInsensitive     matchMode = "exact-case-insensitive"
	MatchModeFuzzy                    matchMode = "fuzzy"
)

func matchDisplayName(input string, names map[string]string, mode matchMode) bool {
	collectedNames := make([]string, len(names))
	i := 0
	for _, name := range names {
		collectedNames[i] = name
		i++
	}
	return matchWithMode(input, collectedNames, mode)
}

func matchWithMode(input string, names []string, mode matchMode) bool {
	switch mode {
	case MatchModeFuzzy:
		return len(fuzzy.FindNormalizedFold(input, names)) > 0
	case MatchModeExactCaseSensitive:
		return slices.Contains(names, input)
	case MatchModeExactCaseInsensitive:
		return slices.ContainsFunc(
			names, func(s string) bool {
				return strings.EqualFold(s, input)
			},
		)
	case MatchModeSubstringCaseSensitive:
		return slices.ContainsFunc(
			names, func(s string) bool {
				return strings.Contains(s, input)
			},
		)
	case MatchModeSubstringCaseInsensitive:
		return slices.ContainsFunc(
			names, func(s string) bool {
				return strings.Contains(strings.ToLower(s), strings.ToLower(input))
			},
		)
	default:
		return false
	}
}

// CollectEntities implements the EntityCollector interface
func (VerifiedChainsEntityCollector) CollectEntities(req apimodel.EntityCollectionRequest) (entities []*CollectedEntity) {
	return FilterableVerifiedChainsEntityCollector{}.CollectEntities(req)
}

// CollectEntities implements the EntityCollector interface
func (d *filterableVerifiedChainsEntityCollector) CollectEntities(req apimodel.EntityCollectionRequest) (entities []*CollectedEntity) {
	if d.Collector == nil {
		d.Collector = &SimpleEntityCollector{}
	}
	in := d.Collector.CollectEntities(req)
	for _, e := range in {
		var approved bool
		for _, f := range d.Filters {
			if approved = f.Filter(e); !approved {
				break
			}
		}
		if approved {
			entities = append(entities, e)
		}
	}
	return
}

// CollectEntities implements the EntityCollector interface
func (d FilterableVerifiedChainsEntityCollector) CollectEntities(req apimodel.EntityCollectionRequest) (entities []*CollectedEntity) {
	discoverer := filterableVerifiedChainsEntityCollector{
		Collector: d.Collector,
		Filters: append(
			[]EntityCollectionFilter{
				EntityCollectionFilterVerifiedChains{
					TrustAnchors: NewTrustAnchorsFromEntityIDs(req.TrustAnchor),
				},
			}, d.Filters...,
		),
	}
	return discoverer.CollectEntities(req)
}

// EntityCollectionFilterVerifiedChains is a EntityCollectionFilter that filters the discovered OPs to the one that have a
// valid TrustChain to one of the specified TrustAnchors
type EntityCollectionFilterVerifiedChains struct {
	TrustAnchors TrustAnchors
}

// Filter implements the EntityCollectionFilter interface
func (f EntityCollectionFilterVerifiedChains) Filter(e *CollectedEntity) bool {
	confirmedValid, _ := DefaultMetadataResolver.ResolvePossible(
		apimodel.ResolveRequest{
			Subject:     e.EntityID,
			TrustAnchor: f.TrustAnchors.EntityIDs(),
		},
	)
	return confirmedValid
}

func fetchList(listEndpoint string) ([]string, error) {
	if ids := subordinateListingCacheGet(listEndpoint); ids != nil {
		internal.Log("Obtained listing response from cache")
		return ids, nil
	}
	ids, err := httpFetchList(listEndpoint)
	if err != nil {
		return nil, err
	}
	internal.Log("Obtained listing response from http")
	subordinateListingCacheSet(listEndpoint, ids)
	return ids, nil
}

func httpFetchList(listEndpoint string) ([]string, error) {
	resp, errRes, err := http.Get(listEndpoint, nil, &[]string{})
	if err != nil {
		return nil, err
	}
	if errRes != nil {
		return nil, errRes.Err()
	}
	entities, ok := resp.Result().(*[]string)
	if !ok || entities == nil {
		return nil, errors.New("unexpected response type")
	}
	return *entities, nil
}

func getMetadataForCollectedEntity(e *CollectedEntity, trustAnchors []string) *Metadata {
	if e.metadata != nil {
		return e.metadata
	}
	metadata, _ := DefaultMetadataResolver.Resolve(
		apimodel.ResolveRequest{
			Subject:     e.EntityID,
			TrustAnchor: trustAnchors,
		},
	)
	return metadata
}

// EntityCollectionFilterOPSupportedGrantTypesIncludes returns an
// EntityCollectionFilter that filters to OPs that support the
// passed grant types
func EntityCollectionFilterOPSupportedGrantTypesIncludes(
	trustAnchorIDs []string, neededGrantTypes ...string,
) EntityCollectionFilter {
	return NewEntityCollectionFilter(
		func(e *CollectedEntity) bool {
			if e == nil {
				return false
			}
			metadata := getMetadataForCollectedEntity(e, trustAnchorIDs)
			if metadata == nil || metadata.OpenIDProvider == nil {
				return false
			}
			return utils.ReflectIsSubsetOf(neededGrantTypes, metadata.OpenIDProvider.GrantTypesSupported)
		},
	)
}

// EntityCollectionFilterOPSupportedScopesIncludes returns an
// EntityCollectionFilter that filters to OPs that support the passed
// scopes
func EntityCollectionFilterOPSupportedScopesIncludes(
	trustAnchorIDs []string,
	neededScopes ...string,
) EntityCollectionFilter {
	return NewEntityCollectionFilter(
		func(e *CollectedEntity) bool {
			if e == nil {
				return false
			}
			metadata := getMetadataForCollectedEntity(e, trustAnchorIDs)
			if metadata == nil || metadata.OpenIDProvider == nil {
				return false
			}
			return utils.ReflectIsSubsetOf(neededScopes, metadata.OpenIDProvider.ScopesSupported)
		},
	)
}

// EntityCollectionFilterOPSupportsExplicitRegistration returns an
// EntityCollectionFilter that filters to OPs that support explicit registration
func EntityCollectionFilterOPSupportsExplicitRegistration(
	trustAnchorIDs []string,
) EntityCollectionFilter {
	return NewEntityCollectionFilter(
		func(e *CollectedEntity) bool {
			if e == nil {
				return false
			}
			metadata := getMetadataForCollectedEntity(e, trustAnchorIDs)
			if metadata == nil || metadata.OpenIDProvider == nil {
				return false
			}
			return slices.Contains(
				metadata.OpenIDProvider.ClientRegistrationTypesSupported, oidfedconst.ClientRegistrationTypeExplicit,
			)
		},
	)
}

// EntityCollectionFilterOPSupportsAutomaticRegistration returns an
// EntityCollectionFilter that filters to OPs that support automatic
// registration
func EntityCollectionFilterOPSupportsAutomaticRegistration(
	trustAnchorIDs []string,
) EntityCollectionFilter {
	return NewEntityCollectionFilter(
		func(e *CollectedEntity) bool {
			if e == nil {
				return false
			}
			metadata := getMetadataForCollectedEntity(e, trustAnchorIDs)
			if metadata == nil || metadata.OpenIDProvider == nil {
				return false
			}
			return slices.Contains(
				metadata.OpenIDProvider.ClientRegistrationTypesSupported, oidfedconst.ClientRegistrationTypeAutomatic,
			)
		},
	)
}

// EntityCollectionFilterOPs returns an EntityCollectionFilter that filters to OPs
func EntityCollectionFilterOPs() EntityCollectionFilter {
	return NewEntityCollectionFilter(
		func(e *CollectedEntity) bool {
			if e == nil {
				return false
			}
			return slices.Contains(e.EntityTypes, "openid_provider")
		},
	)
}

func subordinateListingCacheSet(listingEndpoint string, ids []string) {
	if err := cache.Set(
		cache.Key(cache.KeySubordinateListing, listingEndpoint), ids,
		defaultSubordinateListingCacheTime,
	); err != nil {
		internal.Log(err)
	}
}

func subordinateListingCacheGet(listingEndpoint string) []string {
	var ids []string
	set, err := cache.Get(cache.Key(cache.KeySubordinateListing, listingEndpoint), &ids)
	if err != nil {
		internal.Log(err)
		return nil
	}
	if !set {
		return nil
	}
	return ids
}

// SimpleRemoteEntityCollector is a EntityCollector that utilizes a given
// EntityCollectionEndpoint
type SimpleRemoteEntityCollector struct {
	EntityCollectionEndpoint string
}

// CollectEntities queries a remote EntityCollectionEndpoint for the
// collected entities and implements the EntityCollector interface
func (c SimpleRemoteEntityCollector) CollectEntities(req apimodel.EntityCollectionRequest) []*CollectedEntity {
	params, err := query.Values(req)
	if err != nil {
		internal.Logf("error while creating query parameters for entity collection request: %s", err)
		return nil
	}
	var res EntityCollectionResponse
	_, errRes, err := http.Get(
		c.EntityCollectionEndpoint, params,
		&res,
	)
	if err != nil {
		internal.Logf("error while fetching entity collection endpoint: %s", err)
		return nil
	}
	if errRes != nil {
		internal.Logf("error while fetching entity collection endpoint: %s", errRes.Err().Error())
		return nil
	}
	return res.FederationEntities
}

// SmartRemoteEntityCollector is a EntityCollector that utilizes remote
// entity collection endpoints.
// It will iterate through the entity collect endpoints of the
// given TrustAnchors and stop if one is successful,
// if no entity collection endpoint is successful,
// the SimpleEntityCollector is used
type SmartRemoteEntityCollector struct {
	TrustAnchors []string
}

// CollectEntities  implements the EntityCollector interface
func (c SmartRemoteEntityCollector) CollectEntities(req apimodel.EntityCollectionRequest) []*CollectedEntity {
	// construct a list of trust anchors to query; always start with the
	// trust anchor from the request
	trustAnchors := append([]string{req.TrustAnchor}, sliceutils.RemoveFromSlice(c.TrustAnchors, req.TrustAnchor)...)

	for _, tr := range trustAnchors {
		entityConfig, err := GetEntityConfiguration(tr)
		if err != nil {
			internal.Logf("error while obtaining entity configuration: %v", err)
			continue
		}
		var entityCollectionEndpoint string
		if entityConfig != nil && entityConfig.Metadata != nil && entityConfig.Metadata.FederationEntity != nil && entityConfig.Metadata.FederationEntity.Extra != nil {
			entityCollectionEndpoint, _ = entityConfig.Metadata.FederationEntity.Extra["federation_collection_endpoint"].(string)
		}
		if entityCollectionEndpoint == "" {
			continue
		}
		remoteCollector := SimpleRemoteEntityCollector{
			EntityCollectionEndpoint: entityCollectionEndpoint,
		}
		entities := remoteCollector.CollectEntities(req)
		if entities == nil {
			continue
		}
		return entities
	}
	return (&SimpleEntityCollector{}).CollectEntities(req)
}
