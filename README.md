# Implementation of OpenID Federations for Golang

[![License](https://img.shields.io/github/license/go-oidfed/lib.svg)](https://github.com/go-oidfed/lib/blob/main/LICENSE)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/go-oidfed/lib)
[![Go Report](https://goreportcard.com/badge/github.com/go-oidfed/lib)](https://goreportcard.com/report/github.com/go-oidfed/lib)
[![DeepSource](https://deepsource.io/gh/go-oidfed/lib.svg/?label=active+issues&show_trend=true)](https://deepsource.io/gh/go-oidfed/lib/?ref=repository-badge)
[![DeepSource](https://app.deepsource.com/gh/go-oidfed/lib.svg/?label=code+coverage&show_trend=true&token=tg4V3nrOjmjOHR6b7yJxHzfx)](https://app.deepsource.com/gh/go-oidfed/lib/)

This repository holds a work-in-process implementation of
[OpenID Federation](https://openid.github.io/federation/main.html) in the `go` language with the goal to enable go applications to make 
use of OpenID federation.

The implementation mainly focuses on the Relying Party and Intermediate / Trust Anchor side, but not on the OP side. However, building blocks can also be utilized for OPs or other entity types.
We provide a basic library as well as a configurable and flexible 
federation entity to support higher level functionality.

- This repository contains:
    - The basic go-oidfed library with the core oidfed functionalities.
    - It can be used to build all kind of oidfed capable entities.
- The LightHouse repository at https://github.com/go-oidfed/lighthouse contains:
    - Higher level implementation for various federation endpoints
    - The LightHouse federation entity. This is a configurable and flexible 
      federation entity that can be used as a
        - Trust Anchor
        - Intermediate Authority
        - Trust Mark Issuer
        - Resolver
        - Entity Collector
        - Everything at the same time.
- The whoami-rp repository at https://github.com/go-oidfed/whoami-rp contains:
    - A simple - but not very useful - example RP.
- The OFFA repository at https://github.com/go-oidfed/offa:
    - OFFA stands for Openid Federation Forward Auth
    - OFFA can be deployed next to existing services to add oidfed 
      authentication to services that do not natively support it.
    - OFFA can be used with Apache, Caddy, NGINX, and Traefik.


### Implementation State

The library is not considered stable and some features might be missing. We encourage everybody to give feedback on 
things that are missing, not working, or weird, also suggestions for improvements and of course we are open for pull 
requests.

We try to be up-to-date with the latest version of the spec, but this might not
always be the case.


Here we try to sum up the current implementation state, (but it's very likely
that the list is not complete)

| Feature                                                                                        | Library | Entity      |
|------------------------------------------------------------------------------------------------|---------|-------------|
| OpenID Configuration                                                                           | Yes     | Yes         |
| Trust Chain Building                                                                           | Yes     | When needed |
| Trust Chain Verification                                                                       | Yes     | Yes         |
| Applying Metadata Policies                                                                     | Yes     | Yes         |
| Applying Metadata from Superiors                                                               | Yes     | Yes         |
| Support for Custom Metadata Policy Operators                                                   | Yes     | Yes         |
| Filter Trust Chains                                                                            | Yes     | Yes         |
| Configure Trust Anchors                                                                        | Yes     | Yes         |
| Set Authority Hints                                                                            | N/A     | Yes         |
| Resolve Endpoint                                                                               |         | Yes         |
| IA Fetch Endpoint                                                                              |         | Yes         |
| IA Listing Endpoint                                                                            |         | Yes         |
| Trust Mark Endpoint                                                                            |         | Yes         |
| Trust Marked Entities Endpoint                                                                 |         | Yes         |
| Trust Mark Status Endpoint                                                                     |         | Outdated    |
| Trust Mark Owner Delegation                                                                    | Yes     | Yes         |
| Trust Mark JWT Verification                                                                    | Yes     | Yes         |
| Trust Mark JWT Verification including Delegation                                               | Yes     | Yes         |
| Trust Mark Verification through Trust Mark Status Endpoint                                     | No      | No          |
| JWT Type Verification                                                                          | Yes     | Yes         |
| Requests using GET                                                                             |         | Yes         |
| Requests using POST                                                                            |         | No          |
| Client Authentication                                                                          |         | No          |
| Automatic Client Registration                                                                  | Yes     | Yes         |
| Authorization Code Flow with Automatic Client Registration using oidc key from jwks            |         | Yes         |
| Authorization Code Flow with Automatic Client Registration using oidc key from jwks_uri        |         | No          |
| Authorization Code Flow with Automatic Client Registration using oidc key from signed_jwks_uri |         | No          |
| Explicit Client Registration                                                                   | Yes     | Yes         |
| Constraints                                                                                    | Yes     | Yes         |
| Federation Historical Keys Endpoint                                                            | Yes     | Yes         |
| Automatic Key Rollover                                                                         |         | Yes         |
| Enrollment of Entities                                                                         |         | Yes         |
| Configurable Checks for Enrollment                                                             |         | Yes         |
| Custom Checks for Enrollment                                                                   |         | Yes         |
| Request Enrollment                                                                             |         | Yes         |
| Configurable Checks for Trust Mark Issuance                                                    |         | Yes         |
| Custom Checks for Trust Mark Issuance                                                          |         | Yes         |
| Request to become entitled for a Trust Mark                                                    |         | Yes         |
| Automatically refresh trust marks in Entity Configuration                                      |         | Yes         |



---


This work was started in and supported by the
[Geant Trust & Identity Incubator](https://connect.geant.org/trust-and-identity-incubator).

<img src="https://wiki.geant.org/download/attachments/120500419/incubator_logo.jpg" alt="Trust & Identity Incubator logo" height="75"/>
