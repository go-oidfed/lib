## go-oidfed/lib 0.11.0

### Breaking Changes

- **Go 1.26 is now required** (`go.mod` bumped from `go 1.25.8` to `go 1.26.0`); the build now uses the `jsonv2` experiment.
- **jwx upgraded from v3 → v4** (`github.com/lestrrat-go/jwx/v4`). All internal call sites and public re-exports moved to v4; the v3 module is no longer imported.
- **Logging switched from `logrus` → `zerolog`** (`github.com/rs/zerolog`). `logrus` is now only an indirect dependency. The `internal` package helpers (`WithError`, etc.) were replaced with zerolog-style calls (`internal.Logger().Error().Err(err).Msg(...)`). New helpers: `internal.SetLevel`, `internal.SetOutput`, `internal.Logger()`.
- **KMS signer type changed from `crypto.Signer` to `jwx.SigningKey`** throughout the public API (`RequestObjectProducer.signPayload`, KMS interfaces, etc.). `jwx.SigningKey` is a small interface (`Public() crypto.PublicKey`) satisfied by stdlib private keys and by an internal wrapper for composite-signature keys.
- `SimpleEntityCollector.collect` now takes `...*TrustAnchor` instead of `...TrustAnchor` (`discovery.go`).
- **`crypto11` dependency relocated**: `github.com/ThalesGroup/crypto11` → `github.com/eclipse-keypont/crypto11 v1.6.5` (used by the PKCS#11 KMS).

### Features

#### Cryptography / Signing Algorithms

- New signing algorithms supported in `jwx`:
  - `EdDSAEd25519` (explicit) and `EdDSAEd448` (via `github.com/jwx-go/ed448/v4`), with PEM encoding/decoding (`jwx/ed448_pem.go`).
  - `ES256K` (secp256k1) via `github.com/jwx-go/es256k/v4`, with PEM support (`jwx/secp256k1_pem.go`).
  - Post-quantum **ML-DSA** algorithms `MLDSA44`, `MLDSA65`, `MLDSA87` via `github.com/jwx-go/mldsa/v4` (`filippo.io/mldsa`), with PEM support (`jwx/mldsa_pem.go`).
  - **Composite (hybrid) ML-DSA signatures** via `github.com/jwx-go/compsig/v4`: `MLDSA44ES256`, `MLDSA65ES256`, `MLDSA87ES384`, `MLDSA44Ed25519`, `MLDSA65Ed25519`, `MLDSA87Ed448` (`jwx/compsig_pem.go`, `jwx/signingkey.go`).
- New `jwx.SupportedAlgs()` / `SupportedAlgsStrings()` and a curated **`DefaultAlgs()` / `DefaultAlgsStrings()`** list (`jwx/algs.go`).

#### JWKS Handling

- `jwx.JWKS.WithoutExpired(now)` returns a filtered JWKS containing only non-expired keys (`jwx/jwks.go`).
- `jwx.MergeJWKS(primary, secondary)` merges two JWKS, deduplicating by KID with `primary` winning (`jwx/jwks.go`).
- New `SignedJWKS` type and `ParseSignedJWKS` for the `application/jwk-set+jwt` (typ `jwk-set+jwt`) format from OpenID Federation §5.2.1, including structural validation (typ, kid, `keys`, `iss`, `sub`, unique kids) and `Verify(keys)` (`signed_jwks.go`).
- New `JWKStorage` interface and `FileJWKStorage` filesystem implementation for persisting per-entity JWKS, with `RegisterEntityJWKSFile` symlink support (`jwk_storage.go`).
- Helpers `ExtractKIDs` and `HasJWKSChanged` for diffing JWKS by KID (`jwks_diff.go`).

#### Trust Anchor / Subordinate JWKS Refreshing

- New `TAJWKSRefresher` (`ta_jwks_refresher.go`): polls trust anchors for JWKS changes and updates them automatically. Concurrency-safe; supports dynamic `Add`/`Remove`/`Update` of trust anchors, per-TA backoff, and seeding JWKS from storage. Configurable via `TAJWKSRefresherConfig` and `TrustAnchor.KeyPollInterval` / `EnableJWKSUpdate`.
- `TrustAnchor` is now thread-safe (`atomic.Pointer[jwx.JWKS]` via `JWKS()` / `SetJWKS()`), with custom YAML (un)marshaling that accepts both legacy inline `jwks` and `jwks_file` (`trustanchor.go`).
- New `SubordinateJWKSRefresher` (`subordinate_jwks_refresher.go`): periodically polls the Entity Configuration of enabled subordinates and updates their stored JWKS when the EC's `jwks` changes. Configurable poll interval, exponential backoff with `SubMinPollInterval` floor, and a `SubordinateJWKSRefreshStorage` interface.

#### Key Rotation Hooks (KMS)

- New `kms.KeyRotationHook` and `kms.KeyRotationEvent` types, fired concurrently (each in its own goroutine, panic-recovered, errors logged) after a key is generated/rotated (`jwx/keymanagement/kms/hooks.go`).
- `KeyRotationConfig.Hooks` field registers hooks on the KMS; `KMSConfig.EntityID` is propagated into events.
- Multiple hook implementations:
  - **`CmdHook`** (`key_rotation_hook_cmd.go`): spawns an external command and pipes the new JWKS JSON to its stdin.
  - **`HTTPHook`** (`key_rotation_hook_http.go`): POSTs to a URL with configurable body mode (`none`, `entity_id`, `jwks`, `signed_jwks`) and optional `private_key_jwt` client auth via `HTTPHookClientAuth` + `RequestObjectProducer`. URL can be static or resolved dynamically per invocation via `URLFunc`.
  - **`TriggerUpdateHook`** and **`JWKSUpdateHook`** (`key_rotation_hook_endpoints.go`): convenience wrappers that resolve the target's `federation_jwks_update_trigger_endpoint` / `federation_jwks_update_endpoint` (and auth requirement / signing algs) from its Entity Configuration on each rotation.
- New `oidfedconst` constants for the federation entity metadata Extra keys: `FederationJWKSUpdateEndpoint`, `FederationJWKSUpdateTriggerEndpoint`, `FederationJWKSUpdateTriggerEndpointAuthMethods`, plus `AuthMethodPrivateKeyJWT` and `OAuthClientAssertionJWTBearer`.

#### KMS / Key Management

- **Key announcement lead time** is now configurable via `KeyRotationConfig.KeyAnnouncementLeadTime` and `KeyAnnouncementLeadTimeECMultiplier`; resolved by `KeyAnnouncementLeadTimeDuration()` with sensible defaults (max(5×EC lifetime, 24h)) and clamping to EC lifetime (`kms.go`).
- Scheduled algorithm changes: new `ChangeAlgsAt` / `ChangeDefaultAlgorithmAt` KMS methods, `PendingAlgChange` / `PendingDefaultChange` / `ScheduledState` types, and `KMSStateStorer` interface for persisting scheduled changes across restarts.

#### Metadata Policy

- New **`except` policy operator** (`PolicyOperatorExcept`, `policyoperators.go`) with merge/apply semantics and `MayCombineWith` wiring across all existing operators.
- New policy verifiers in `policyverifiers.go` validating `except` interactions: `policyVerifyValueNotInExcept`, `policyVerifyAddNotInExcept`, `policyVerifySupersetOfNotInExcept`.
- New reflection utilities in `internal/utils/slices.go`: `ReflectDifference`, `ReflectDisjoint` (plus existing union/intersect/subset helpers used by the new operator).

### Dependency Updates

- `github.com/coreos/go-oidc/v3` 3.18.0 → 3.20.0
- `github.com/gofiber/fiber/v2` 2.52.13 → 2.52.14
- `github.com/redis/go-redis/v9` 9.20.1 → 9.21.0
- `golang.org/x/crypto` 0.53.0 → 0.54.0
- `golang.org/x/text` 0.38.0 → 0.40.0
- `golang.org/x/net` 0.55.0 → 0.56.0 (indirect)
- `golang.org/x/sys` 0.46.0 → 0.47.0 (indirect)
- `github.com/zachmann/go-utils` bumped
- `github.com/lestrrat-go/dsig` 1.2.1 → 1.3.0; added `github.com/lestrrat-go/dsig-circl-ed448`
- New direct deps: `filippo.io/mldsa`, `github.com/cloudflare/circl`, `github.com/decred/dcrd/dcrec/secp256k1/v4`, `github.com/jwx-go/compsig/v4`, `github.com/jwx-go/ed448/v4`, `github.com/jwx-go/es256k/v4`, `github.com/jwx-go/mldsa/v4`, `github.com/rs/zerolog`
- Removed direct dep on `github.com/sirupsen/logrus` (now indirect).

### Tests

Substantial new test coverage added: `jwk_storage_test.go`, `policyoperators_test.go`, `policyverifiers_test.go`, `subordinate_jwks_refresher_test.go`, `ta_jwks_refresher_test.go`, `key_rotation_hook_{cmd,endpoints,http}_test.go`, `kms/hooks_test.go`, `internal/utils/slices_test.go`, plus major expansions of `jwx/jwx_test.go`, `kms/pem_storage_test.go`, and `trustresolver_test.go`.

## go-oidfed/lib 0.10.12

### Features
- Add `*_auth_methods` to FederationEntityMetadata
- Add `endpoint_auth_signing_alg_values_supported`
- Add constant for auth method `private_key_jwt`
- Define constant for client assertion

### Bug Fixes
- Fix possible panic in trust resolver if resolved entity does not have metadata
- Fix sub-optimal process in KMSs: If the public key storage contained keys that do not have a corresponding private key (e.g. because KMS was switched) the KMS would create new keys but was not able to use them because another key (that does not have a private key) was selected from the public key storage

### Dependencies
- Bump github.com/redis/go-redis/v9 from 9.20.0 to 9.20.1

## go-oidfed/lib 0.10.11

- Refactored the KMS package: extracted `PEMStorageKMS` from `FilesystemKMS` with pluggable `PEMStorer` and `KMSStateStorer` interfaces
- Fixed a nil pointer dereference in `shortenExpirationUntilFuture` that occurred when a key had no expiration
- Fixed a bug where errors from `x509.MarshalECPrivateKey` / `x509.MarshalPKCS8PrivateKey` were silently discarded
- Bumped golang.org/x/crypto from v0.52.0 to v0.53.0
- Bumped golang.org/x/text from v0.37.0 to v0.38.0
- Bumped github.com/redis/go-redis/v9 from v9.19.0 to v9.20.0

## go-oidfed/lib 0.10.10

- Added the `oauth_authorization_server` entity type constant
- Fixed a bug that prevented correct unmarshalling of metadata policies if there was a custom entity type
- Bumped github.com/ThalesGroup/crypto11 from v1.6.0 to v1.6.1
- Bumped golang.org/x/crypto from v0.51.0 to v0.52.0

## go-oidfed/lib 0.10.9

- Fix/essential metadata policy with arrays

## go-oidfed/lib 0.10.8

- Add explicit support for RP Metadata Choices in RelyingPartyMetadata

## go-oidfed/lib 0.10.7

- Bump golang.org/x/text from 0.36.0 to 0.37.0
- Bump golang.org/x/crypto from 0.50.0 to 0.51.0
- Add options to `StaticFederationEntity` and `DynamicFederationEntity` to make it optional and configurable to copy informational metadata claims to `federation_entity`. Previous and still default behavior is to copy informational metadata claims for other entity types to `federation_entity` if the claims are not yet defined on `federation_entity` and it is the same for all entity types that define the claim.

## go-oidfed/lib 0.10.6

- Bump github.com/lestrrat-go/jwx/v3 from 3.1.0 to 3.1.1
- Fixed a bug in the trust chain caching that would produce outdated resolve responses when the Trust Anchor's Entity Configuration would have the minimal expiration in the chain.

## go-oidfed/lib 0.10.5

- Fixed a bug with applying metadata policies on `scope`.

## go-oidfed/lib 0.10.4

- [Entity Collection] Rename language_tags to language_tag
- Bump github.com/redis/go-redis/v9 from 9.18.0 to 9.19.0
- Bump github.com/gofiber/fiber/v2 from 2.52.12 to 2.52.13

## go-oidfed/lib 0.10.3

### Spec Alignments (Breaking Changes, if you depend on those)
- **Entity Collection:** Renamed the returned entities field from `federation_entities` to `entities` to align with the Entity Collection specification.
- **Entity Collection:** Renamed the pagination pointer fields to `from`/`next` to align with the updated Entity Collection specification

### Dependencies
- **jwx:** Bumped `github.com/lestrrat-go/jwx/v3` from `3.0.13` to `3.1.0`.

## go-oidfed/lib 0.10.2

- Bump golang.org/x/text from 0.35.0 to 0.36.0
- Bump golang.org/x/crypto from 0.49.0 to 0.50.0
- Bump github.com/coreos/go-oidc/v3 from 3.17.0 to 3.18.0
- Bump github.com/ThalesGroup/crypto11 from 1.2.6 to 1.6.0

## go-oidfed/lib 0.10.0

### Breaking Changes

- New Key Management System: Complete rewrite of the key management subsystem. The old keystorage.go, privateKeyStorage.go, privateKeyStorageSingleAlg.go, and publicKeyStorage.go have been removed and replaced with a new modular architecture under jwx/keymanagement/ with separate kms/ and public/ packages. Legacy support is available via dedicated migration helpers.
- Logging: Replaced logrus with an internal logger across all modules. Log call sites have been updated for consistency.
- FederationEntity refactor: Introduced Static and Dynamic FederationEntity interfaces, changing how federation entities are configured and collected.
- Trust Mark refactor: TrustMarkIssuer now requires a TrustMarkSpecProvider instead of static configuration. A thread-safe in-memory implementation is provided.

### Features

- TrustAnchorHints support: Add support for trust_anchor_hints in federation entity configuration and processing.
- Dynamic TrustMarkSpecProvider: Introduce a TrustMarkSpecProvider interface with a thread-safe in-memory implementation, allowing dynamic trust mark specification management.
- Atomic trust mark refresh: Implement atomic trust mark refresh with rate limiting and exponential backoff.
- Improved expiration logic: Refine entity configuration expiration to factor in trust marks and JWKS expiration timestamps.
- Key management enhancements:
  - Add support for scheduling algorithm and default algorithm changes with future-dated keys.
  - Add dynamic configuration update methods for KMS.
  - Add JSON struct tags to KeyRotationConfig for serialization support.
  - Add support for additional crypto11 configuration options (SlotNumber, MaxSessions, UserType, LoginNotSupported, PoolWaitTimeout).
  - Introduce NotFoundError for clearer error handling in public key storage operations.
  - Update Unixtime handling to use pointers for nullable fields and improve SQL compatibility.
- Entity collection: Include organization_name, organization_uri, and contacts in entity collection (fixes #135).
- Constants: Add constants for trust mark status response content type and JWT type.

### Other

- Remove edugain-pilot example setup.
- Update go-utils dependency.

### Dependency Updates

- Bump github.com/go-jose/go-jose/v4 from 4.1.3 to 4.1.4 (#153)
- Bump golang.org/x/oauth2 from 0.35.0 to 0.36.0 (#150)
- Bump golang.org/x/text from 0.34.0 to 0.35.0 (#151)
- Bump golang.org/x/crypto from 0.48.0 to 0.49.0 (#152)

## go-oidfed/lib 0.9.1

- Bumped various dependencies

## go-oidfed/lib 0.9.0

- Added `trust_anchor_hints` to entity configuration
- `trust_chain` and `peer_trust_chain` header parameters are now used in explicit registration and can be used in automatic registration.
- Added option to disable cache (for testing!)
- Added option to set a max lifetime for cache entries.
- Bumped several dependencies

## go-oidfed/lib 0.8.4

- Bump github.com/gofiber/fiber/v2 from 2.52.9 to 2.52.10
- Bump github.com/redis/go-redis/v9 from 9.16.0 to 9.17.0
- Bump golang.org/x/crypto from 0.44.0 to 0.45.0

## go-oidfed/lib 0.8.3

### Enhancements
- Improved logging

### Bug Fixes
- Fixed a bug in the TrustResolver that could prevent caching
- Improved parsing of resolve responses

### Dependencies
- Bump golang.org/x/oauth2 0.32.0 → 0.33.0
- Bump golang.org/x/crypto 0.43.0 → 0.44.0

## go-oidfed/lib 0.8.2

- Replace tideland.dev/go/slices

## go-oidfed/lib 0.8.1

- Changed the parameter order in FederationLeaf.GetExplicitRegistrationOIDCRP so that context.Context is the first parameter.

## go-oidfed/lib 0.8.0

- Updated various dependencies
- Fixed some metadata claim names
- Added support for explicit client registration
- Added periodic collection support for entity collection
- Added pagination support for entity collection
- Added proactive resolver mode
- Resolver and Entity Collector can be limited which trust anchors are allowed to be used

## go-oidfed/lib 0.7.1

- Resolving Metadata now also applies metadata from the direct superior not only metadata policies
- Fixes to the trust chain signature verification:
  - Fixed a bug where trust chains would still be considered valid, even though the signature of the leaf entity configuration failed
  - Fixed signature verification for single entity trust chains.

## go-oidfed/lib 0.7.0

### Entity Collection
- Update request to latest draft
- Fix trust marks claims request parameter
- Added multi language support
- Fixed handling of string slices

### Metadata

- Fixed implementation of FindEntityMetadata
- Copy informational metadata to federation entity if
  - not set in federation entity
  - set in other entity type(s) and if set in multiple they do not conflict

### Other
- Code Refactoring
- Updated dependencies

## go-oidfed/lib 0.6.0

- Bump github.com/redis/go-redis/v9 from 9.10.0 to 9.11.0
- Bump golang.org/x/crypto from 0.39.0 to 0.40.0
- Bump github.com/lestrrat-go/jwx/v3 from 3.0.7 to 3.0.8
- Feat/support key rotation
- Bump github.com/lestrrat-go/jwx/v3 from 3.0.8 to 3.0.9

## go-oidfed/lib 0.5.0

### Renamed to go-oidfed/lib

- The repo was moved to the go-oidfed organization
- The go module was renamed to go-oidfed/lib
  - This needs a manual update if you used the previous module.
- A major restructuring was done. As part of this some content moved to other repos. See the Readme.md for an overview.

### Spec Changes
- Renamed `trust_mark_id` to `trust_mark_type`

### Other Changes
- Allow resolver cache grace period to be set externally
- Extend that mechanism to include a elapsed lifetime factor

## go-oidfed/lib 0.4.0

### Heads up
This is the last release under zachmann/go-oidfed. The repo will shortly be restructured and transferred to the `go-oidfed` organization. The restructuring will also split the repo and contain other breaking restructuring. Also configuration of RP / TA will break with the next release.

### General

- Updated dependencies
- Removed `iss` parameter from fetch entity statement request, since it was removed some time ago in the spec
- Fixed metadata policies for `scope` potentially failing
- Allow arbitrary extra metadata (for other entity types); thanks to @tgeoghegan for this
- (Partly) adapt to draft 43: Add new ui related metadata claims
  - Renaming of `trust_mark_id` to `trust_mark_type` is not yet done

### Example TA

- Improvements to the entity collection endpoint
- Updating entity collection endpoint to new draft

## go-oidfed/lib 0.3.1

### General

- Updated dependencies
- Added `resource_name` to PR metadata
- Fixed problems with cached metadata
- Fixed jwt verification if multiple keys are in a jwks but no `alg` given
- Fixed an error message
- Resolve can now resolve single EC trust chains, i.e. it can now resolve itself
- Fixed some problems with the resolver

### Example TA

- Added config option to enable debug log
- First (outdated) implementation of an entity collection endpoint

### Example RP

- Added some styling to the html
- Allow RP to use new entity collection endpoint

## go-oidfed/lib 0.3.0

This release mainly updates the lib to the latest spec.

This includes some changes to the metadata policies. The test vectors on https://connect2id.com/blog/metadata-policy-test-vectors-openid-federation are passing with the updated implementation.

Custom metadata policy operator would need to be updated.

Some smaller changes include:
- Updating dependencies
- Allow `logo_uri` config option for the example TA and RP
- Allow `client_name` config option for the example RP
- Allow self-issued trust marks in the trust mark refresher.

## go-oidfed/lib 0.2.1

- Increases the go-set dependency version to fix builds on some architectures

## go-oidfed/lib 0.2.0

A lot of new features have been added and most of the spec should be implemented.

We also implemented a federation entity that can be used to build trust anchors, intermediates, and trust mark issuers.
The examples contain an example RP as well as configurable federation entity.

Here is an overview of what is supported:

- Issuing OpenID Configuration
- Trust Chain Building
- Trust Chain Verification
- Use Constraints
- Applying Metadata Policies
- Support for Custom Metadata Policy Operators
- Filter Trust Chains
- Configure Trust Anchors
- Set Authority Hints
- Use a resolve endpoint for resolving
- Resolve Endpoint
- IA Fetch Endpoint
- IA Listing Endpoint
- Trust Mark Endpoint
- Trust Marked Entities Endpoint
- Trust Mark Status Endpoint
- Trust Mark Owner Delegation
- Trust Mark JWT Verification including Delegation
- JWT Type Verification
- Automatic Client Registration
- Authorization Code Flow with Automatic Client Registration using oidc key from jwks
- Automatic enrollment of Entities using configurable checks
- Request Enrollment
- Automatic issuance of Trustmarks using configurable checks
- Request to become entitled for a Trust Mark
- Automatically refresh trust marks in Entity Configuration

## go-oidfed/lib 0.1.0

This is the first release of go-oidcfed, a (WIP) implementation of [OpenID Connect Federation](https://openid.bitbucket.io/connect/openid-connect-federation-1_0.html) in the go language with the goal to enable go applications to make use of OIDC federations.

The implementation mainly focuses on the Relying Party side, but can also be utilized for other entity types. The [examples](https://github.com/zachmann/go-oidcfed/tree/master/examples) directory contains example implementations for a [Relying Party](https://github.com/zachmann/go-oidcfed/tree/master/examples/rp) and an [Intermediate Authority / Trust Anchor](https://github.com/zachmann/go-oidcfed/tree/master/examples/ta). Those serve as examples, they are by no means production ready, but can serve as a good starting point on how the oidcfed library can be used to implement such entities.

The library is not considered stable and some features might be missing. We encourage everybody to give feedback on things that are missing, not working, or weird, also suggestions for improvements and of course we are open for pull requests.
