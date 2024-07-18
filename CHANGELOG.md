# Changelog

## 1.8.4 (2024-03-25)

### Added
* Add property to show SQL queries (default to false) https://github.com/indigo-iam/iam/pull/702
* Add refresh token value index on database https://github.com/indigo-iam/iam/pull/722
* Add support for admin to customize login layout https://github.com/indigo-iam/iam/pull/668

### Fixed
* Encode/decode token value hash with Charset UTF-8 to match the MySQL algorithm https://github.com/indigo-iam/iam/pull/694
* Update the email address/username without needs to refresh the web UI https://github.com/indigo-iam/iam/pull/686
* Allow Chinese characters to be shown on user's info column https://github.com/indigo-iam/iam/pull/701
* Update login form display strategy https://github.com/indigo-iam/iam/pull/669

### Changed
* Only registered users can get client credentials grant type https://github.com/indigo-iam/iam/pull/683
* Remove possibility to add a client logo URI https://github.com/indigo-iam/iam/pull/697
* Disable client editing through MitreID endpoint (`/api/clients/*`) https://github.com/indigo-iam/iam/pull/703
* Request for an optional "Apply for an account with eduGAIN" button https://github.com/indigo-iam/iam/pull/665

## 1.8.3 (2023-10-30)

### Recommendations
It is **strongly** recommended to **make a backup of your database** before upgrading to v1.8.3 because several migrations are planned. Also, remember that for updates from versions prior to v1.7.2 you **must** first upgrade to v1.7.2.
The migration to v1.8.3 will take an amount of time which will be proportional to the amount of currently active access tokens. This means that if you are deploying IAM with some kind of liveness and readiness probes, it's probably better to **switch them off** before upgrading. This migration may take a long **time.**

### Changed
* Save access token value as an hash in order to use lighter db indexes and avoid conflicts by @rmiccoli in https://github.com/indigo-iam/iam/pull/613
* Avoid upper case characters into VO names by @SteDev2 in https://github.com/indigo-iam/iam/pull/616
* Enable Redis scope matchers and well-known endpoint caching by @federicaagostini in https://github.com/indigo-iam/iam/pull/633
* Consider scope matcher based on string equality for custom scopes by @rmiccoli in https://github.com/indigo-iam/iam/pull/642

### Added
* Add SCIM endpoint entry to well-known endpoint by @federicaagostini in https://github.com/indigo-iam/iam/pull/631
* Update account AUP signature time via API by @rmiccoli in https://github.com/indigo-iam/iam/pull/608
* Add new JWT profile that rename 'groups' claim with 'roles' by @enricovianello in https://github.com/indigo-iam/iam/pull/637
* Add support for displaying specific language name in federation Metadata by @Sae126V in https://github.com/indigo-iam/iam/pull/640
* Add missing "Reuse refresh token" box within client management page  by @rmiccoli in https://github.com/indigo-iam/iam/pull/650
* Add missing foreign keys to the database by @enricovianello, @rmiccoli in https://github.com/indigo-iam/iam/pull/632, https://github.com/indigo-iam/iam/pull/659
* Add OpenID Connect standard claims in ATs for WLCG JWT profile by @rmiccoli in https://github.com/indigo-iam/iam/pull/651

### Fixed
* Allow to add certificates with the same subject DN by @rmiccoli in https://github.com/indigo-iam/iam/pull/624
* Delete unsupported response types by @rmiccoli in https://github.com/indigo-iam/iam/pull/610
* Fix management of tokens lifetime following RFC9068 by @federicaagostini in https://github.com/indigo-iam/iam/pull/620
* Fix CERN Restore workflow by @hannahshort in https://github.com/indigo-iam/iam/pull/645
* Fix authz code flow with PKCE for IAM test client application by @rmiccoli in https://github.com/indigo-iam/iam/pull/653
* Fix authorization on IAM APIs such to avoid cases where access is granted to already approved scopes instead of effective token scopes by @enricovianello in https://github.com/indigo-iam/iam/pull/664

## 1.8.2p2 (2023-09-21)

This release fixes a privilege escalation present in all previous IAM releases. See https://advisories.egi.eu/Advisory-EGI-SVG-2023-53.

## 1.8.2p1 (2023-07-04)

### Fixes

This release fixes an XSS vulnerability in 1.8.2. See https://advisories.egi.eu/Advisory-EGI-SVG-2023-20.

## 1.8.2 (2023-05-31)

### Added

* Introduced new admin scopes in order to access IAM API endpoints #562
    * **Note**: From this release, an administrator access token is not enough to have full access to IAM API endpoints. The added scopes (`iam:admin.read` and `iam:admin.write`) are now needed.
* Bump Spring-Boot version to 2.6.14 #593 

### Fixed

* Fix refresh token lifetime value in case of client credentials or implicit grant types #582
* Add missing check on challenge code method for PKCE #583 
* Fix lifecycle end-time for suspended account #585
* Cosmetic Group Manager dashboard fix #587
* Properly update OAuth scope list in model after scope policies evaluation #588


## 1.8.1p2 (2023-09-21)

This release fixes a privilege escalation present in all previous IAM releases. See https://advisories.egi.eu/Advisory-EGI-SVG-2023-53.

## 1.8.1p1 (2023-07-04)

### Fixes

This release fixes an XSS vulnerability in 1.8.1. See https://advisories.egi.eu/Advisory-EGI-SVG-2023-20.

## 1.8.1 (2023-02-28)

### Added

* Add scope management to IAM dashboard https://github.com/indigo-iam/iam/pull/500
* Add the groups view for the group managers https://github.com/indigo-iam/iam/pull/536
* Support for AARC-G069 guideline https://github.com/indigo-iam/iam/pull/553

### Fixed

* Fix /devicecode endpoint in cors endpoint matchers https://github.com/indigo-iam/iam/pull/535
* Do not raise exception when incorrect scope policy https://github.com/indigo-iam/iam/pull/526
* Fix bug when updating user fields https://github.com/indigo-iam/iam/pull/512
* Do not allow IAM to issue RT to users with expired AUP https://github.com/indigo-iam/iam/pull/503
* Remove orphans from database https://github.com/indigo-iam/iam/pull/547
* Prevent VOMS aa from issuing ACs when AUP has expired https://github.com/indigo-iam/iam/pull/552
* Do not allow token refresh for disabled users https://github.com/indigo-iam/iam/pull/570
* Do not allow disabled users to log in with x509 certificate https://github.com/indigo-iam/iam/pull/571
* Apply the UsernameValidator whenever a username can be updated (e.g. SCIM API) https://github.com/indigo-iam/iam/pull/572
* Fix unnamed clients and add missing edit button into clients view https://github.com/indigo-iam/iam/pull/573

### Changed

* Remove health endpoints forward https://github.com/indigo-iam/iam/pull/567
* Disable register MITREid endpoint for Dynamic Client Registration https://github.com/indigo-iam/iam/pull/567
* Change default refresh token lifetime from infinity to 30 days https://github.com/indigo-iam/iam/pull/567
* Add '@' and '.' as allowed characters for a registered username https://github.com/indigo-iam/iam/pull/572

### Notes

The `/health` endpoint and its children have been moved to `/actuator/health` base path since IAM v1.8.0. Since IAM v1.8.1 the forward to the old endpoints has been removed.

## 1.8.0 (2022-09-08)

This release introduces several new supported features and
fixes several bugs for the IAM login service.

### Added

* Spring boot migration to version 2.6.6
* Upgrade flyway to version 7.15.0
* New clients management page for administrators on IAM dashboard
* New clients registration page for users on IAM dashboard
* Support for JWT-based client-authN
* New Cache-Control to `/jwk` endpoint
* Support for AARC G021 guideline
* Support for AARC G025 guideline
* Persistence layer migrations for MFA support
* Group labels in user home page
* New consent page

### Fixed

* Fix group names according to AARC G002
* Fix update button bug
* Fix tokens page failure following a username update
* Fix tokens page failure due to a client deletion
* Fix pagination in tokens component in IAM dashboard
* Fix scope caching on client update
* Fix validation for user's image URL
* Fix support for JWK configuration
* Fix missing `wlcg.groups` in userinfo response

### Changed

* `IAM_USE_FORWARDED_HEADERS` configuration variable has been deprecated due to the Spring update and replaced by `IAM_FORWARD_HEADERS_STRATEGY`. It can be set to ```native``` or ```none```. The same for the Test Client application, where `IAM_CLIENT_USE_FORWARDED_HEADERS` becomes `IAM_CLIENT_FORWARD_HEADERS_STRATEGY`
* The `/health` endpoint has been moved to `/actuator/health`. It is still duplicated in the former endpoint, but well be removed in future releases

### Deprecated

* Manage Clients MitreID page for administartors
* Self-service Client Registration MitreID page for users

## 1.7.2 (2021-12-03)

This release provides a single dependency change for the IAM login service
application.

### Added

* Upgrade flyway to version 4.2.0. This is needed to enable a smooth transition to the flyway version that will come with IAM v1.8.0 (which moves to Spring boot 2.5.x) (#443)

## 1.7.1 (2021-09-13)

This release provides changes and bug fixes to the IAM test client application.

### Added

- The IAM test client application, in its default configuration, no longer
  exposes tokens, but only the claims contained in tokens. It's possible to
  revert to the previous behavior by setting the `IAM_CLIENT_HIDE_TOKENS=false`
  environment variable (#414)

### Fixed

- A problem that prevented the correct behaviour of the IAM test client has
  been fixed (#415)

## 1.7.0 (2021-09-02)

### Added

- IAM now enforces intermediate group membership (#400)

- Support for X.509 managed proxies (#356)

- Characters allowed in username are now restricted to the UNIX valid username
  characters (#347)

- Support for including custom HTML content at the bottom of the login page has
  been added (#341)

- Improved token exchange flexibility (#306)

- CI has been migrated from travis to Github actions (#340)

- IAM now allows to link ssh keys to an account (#374)

### Fixed

- A problem that prevented the deletion of dynamically registered clients under
  certains conditions has been fixed (#397)

- Token exchange is no longer allowed for single-client exchanges that involve
  the `offline_access` scope (#392)

- More flexibility in populating registration fields from SAML authentication
  assertion attributes (#371)

- A problem with the userinfo endpoint disclosing too much information has been
  fixed (#348)

- A problem which allowed to submit multiple group requests for the same group
  has been fixed (#351)

- A problem with the escaping of certificate subjects in the IAM dashboard has
  been fixed (#373)

- A problem with the refresh of CRLs on the test client application has been
  fixed (#368)

### Documentation

- The IAM website and documentation has been migrated to a site based on
  [Google Docsy][docsy], including improved documentation for the SCIM, Scope
  policy and Token exchange IAM APIs (#410)

## 1.6.0 (2020-07-31)

### Added

- IAM now supports multiple token profiles (#313)

- IAM now implements basic account lifecycle management (#327)

- It is now possible to disable local authentication and only rely on brokered
  authentication (#330)

- The editing of user profile information can now be disabled (#329)

- IAM can now be configured to require authentication through an external
  identity provider at registration time (#328)

- IAM now stores and manages a URL pointing to the AUP document instead of
  storing the AUP text in the database (#287)

- IAM now allows to customize the organization logo size presented in login and
  other pages (#280)

### Fixed

- A race condition that could lead to SAML login being blocked has been fixed
  (#334)

- The applicant username is now included in the registration confirmation email
  (#325)

- The "link external account" button is now disabled when no external IdP is
  configured (#323) and the registration page does not mention external IdPs
  when none are configured (#322)

- A bug in the pagination handling of "Add to group" dialog has been fixex
  (#318)

- The token management API no longer shows registration tokens (#312)

- The token management API no longer exposes token values to privileged users
  (#308)

- IAM no longer requires client authentication for the device code grant (#316)

- A bug that prevented adding users to an IAM instance from the dashboard when
  registration is disabled has been fixed (#326)

## 1.5.0 (2019-10-25)

### Added

- It is now possible to configure multiple external OpenID Connect providers
  (#229)

- IAM now supports group managers (#231). Group managers can approve group
  membership requests.

- It is now possible to define validation rules on external SAML and OpenID
  Connect authentications, e.g., to limit access to IAM based on entitlements
  (#277)

- Real support for login hint on authorization requests: this feature allows a
  relying party to specify a preference on which external SAML IdP should be
  used for authentication (#230)

- Improved scalability on user and group search APIs (#250)

- IAM supports serving static local resources (#288); this support can be used,
  for instance, to locally serve custom logo images (#275)

- Actuator endpoints can now be secured more effectively, by having dedicated
  credentials for IAM service deployers (#244)

- It is now possible to configure IAM to include the scope claim in issued
  access tokens (#289)

- Support for custom local SAML metadata configuration (#273)

- Improved SAML configuration flexibility (#292)

### Fixed

- Stronger validation logic on user-editable account information (#243)

- EduPersonTargetedID SAML attribute is now correctly resolved (#253)

- The token management API now supports sorting (#255)

- Orphaned tokens are now cleaned up from the database (#263)

- A bug that prevented the deployment of the IAM DB on MySQL 5.7 has been
  resolved (#265)

- Support for the OAuth Device Code flow is now correctly advertised in the IAM
  OpenID Connect discovery document (#268)

- The device code default expiration is correctly set for dynamically
  registered clients (#267)

- The `updated_at` user info claim is now correctly encoded as an epoch second
  (#272)

- IAM now defaults to transient NameID in SAML authentication requests (#291)

- A bug in email validation that prevented the use of certain email addresses
  during registration has been fixed (#302)

## 1.4.0 (2018-05-18)

### Added

- New paginated user and group search API (#217)

- Support for login hint on authorization requests: this feature allows a
  relying party to specify a preference on which external SAML IdP should be
  used for authentication (#230)

- Doc: documentation for the IAM group request API (#228)

### Fixed

- A problem that caused the device code expiration time setting to 0 seconds
  for dynamically registered clients has been fixed (#236)

- Dashboard: the tokens management section now shows a loading modal when
  loading information (#234)

- Notification: a problem that caused the sending of a "null" string instead of
  the IAM URL in notification has been fixed (#232)

## 1.3.0 (2018-04-12)

### Added

- New group membership requests API: this API allows user to submit requests
  for membership in groups, and provide administrators the ability to
  approve/reject such requests. Support for the API will be included in the IAM
  dashboard in a future release (#200)

- IAM now includes additional claims in the issued ID token:
  `preferred_username`, `email`, `organisation_name`, `groups` (#202)

- IAM now can be configured to include additional claims in the issued access
  tokens: `preferred_username`, `email`, `organisation_name`, `groups`. This
  behaviour is controlled with the `IAM_ACCESS_TOKEN_INCLUDE_AUTHN_INFO`
  environment variable (#208)

### Fixed

- Dashboard: a problem that prevented the correct setting of the token exchange grant for
  clients has been fixed (#223)

- Dashboard: protection against double clicks has been added to approve/reject requests
  buttons (#222)

- Dashboard: a broken import has been removed from the IAM main page (#215)

- A problem in the tokens API that prevented the filtering of expired tokens
  has been fixed (#213)

- Dashboard: token pagination is now correctly leveraged by the IAM dashboard
  in the token management page (#211)

- Dashboard: OpenID connect account manangement panel is now hidden when Google
  authentication is disabled (#206)

- Dashboard: SAML account management panel is now hidden when SAML
  authentication is disabled (#203)

## 1.2.1 (2018-03-01)

### Changed

The token management section in the dashboard introduced in 1.2.0 has been
disabled due to performance issues in the token pagination code. We will add
the interface back as soon as these issues are resolved (#211). 

## 1.2.0 (2018-03-01)

### Added

- IAM documentation has been migrate from Gitbook to its [own dedicated
  site][iam-docs] on Github pages

- IAM now provides a token management section in the dashboard that can be used
  by administrators to view active tokens in the system, filter tokens (by user
  and client) and revoke tokens (#161)

- IAM now provides an Acceptable Usage Policy (AUP) API that can be used to require
  that users accept the AUP terms at registration time or later (#86)

- IAM now exposes the 'iss' claim in the response retuned by the token
  introspection endpoint (#58)

### Fixed

- IAM now provides user-friendlier X.509 authentication support. When a client
  certificate is found linked to the TLS session, IAM  displays
  certificate information and a button that can be used to sign in
  with the certificate (#193)
- Admin-targeted email notifications that result from membership requests now
  include the contents of the _Notes_ field (#190)
- Tokens linked to an account are now removed when the account is removed
  (#204)

### Changed

- IAM now depends on MitreID connect v. 1.3.2.cnaf.rc0 (#180)

[iam-docs]: https://indigo-iam.github.io/docs

## 1.1.0 (2017-9-29)

### Added

- The login button text can now be customised for local (#185) and SAML
  login (#177)
- A privacy policy can now be linked to the IAM login page (#182)
- Improved error pages rendering (#178)
- SAML metadata can now be filtered according to certain conditions (e.g.,
  SIRTFI compliance)
- The organisation name is now included in the IAM dashboard top bar (#186)
- IAM now implements a scope policy management API that allows to restrict the
  use of OAuth scopes only to selected users or group of users (#80)

### Fixed

- IAM now correctly enforces SAML metadata signature checks (#175)
- The subject of IAM notification messages now includes the organisation name
  (#163)
- EPPN is used as username for users registered via SAML (#188)

## 1.0.0 (2017-8-31)

This release provides improvements, bug fixes and new features:

- IAM now supports hierarchical groups. The SCIM group management API has been
  extended to support nested group creation and listing, and the IAM dashboard
  can now leverage these new API functions (#88)
- IAM now supports native X.509 authentication (#119) and the ability to
  link/unlink X.509 certificates to a user membership (#120)
- IAM now supports configurable on-demand account provisioning for trusted SAML
  IDPs; this means that the IAM can be configured to automatically on-board
  users from a trusted IdP/federation after a succesfull external
  authentication (i.e. no former registration or administration approval is
  required to on-board users) (#130)
- IAM now provides an enhanced token management and revocation API that can be
  used by IAM administrators to see and revoke active tokens in the system (#121)
- Account linking can be now be disabled via a configuration option (#142)
- IAM dashboard now correctly displays valid active access tokens for a user
  (#112) 
- A problem that caused IAM registration access tokens to expire after the
  first use has been fixed (#134)
- IAM now provides an endpoint than can be used to monitor the service
  connectivity to external service (ie. Google) (#150)
- Improved SAML metadata handling (#146) and reloading (#115)
- Account linking can now be disabled via a configuration option (#142)
- The IAM audit log now provides fine-grained information for many events
  (#137)
- The IAM token introspection endpoint now correctly supports HTTP form
  authentication (#149)
- Notes in registration requests are now required (#114) to make life easier
  for VO administrators that wants to understand the reason for a registration
  request
- Password reset emails now contain the username of the user that has requested
  the password reset (#108)
- A stronger SAML account linking logic is now in place (#116)
- Starting from this release, we provide RPM and Deb packages (#110) and a
  puppet module to configure the IAM service (#109)
- The spring-boot dependency has been updated to version 1.3.8.RELEASE (#144)
- An issue that prevented access to the token revocation endpoint has been
  fixed (#159)

## 0.6.0 (2017-3-31)

This release provides improvements and bug fixes:

- IAM now implements an audit log that keeps track of all interesting security
  events (#79)
- Password grant logins are now correctly logged (#98)
- The MitreID logic for resolving user access and refresh token has been
  replaced with a more efficient implementation (#94)
- Audience restrictions can be enforced on tokens obtained through all
  supported OAuth/OIDC flows (#92)
- The tokens and site approval cleanup periods are now configurable (#96)

## 0.5.0 (2016-12-6)

This release provides new functionality and bug fixes:

- It is now possible for users to link external authentication accounts
  (Google, SAML) to the user IAM account (#39)
- It is now possible to register at the IAM starting from an external
  authentication (#44)
- The IAM now exposes an authority management endpoint (integrated in the
  dashboard) that allows to assign/remove administrative rights to/from users
  (#46)
- The token exchange granter now enforces audience restrictions correctly (#32)
- It is now possible to set custom SAML maxAssertionTime and
  maxAuthenticationAge to customize how the SAML filter should check incoming
  SAML responses and assertions (#65)
- Improved token exchange documentation (#51,#52)
- The IAM now includes spring boot actuator endpoints that allow fine-grained
  monitoring of the status of the service (#62)
- Group creation in the dashboard now behaves as expected (#34)
- Editing first name and other information from the dashboard now behaves as
  expected (#57)
- The IAM now provides a refactored SAML WAYF service that remembers the identity
  provider chosen by the user (#59)
- The overall test coverage has been improved

## 0.4.0 (2016-09-30)

This release provides new functionality and some fixes:

- Groups are now encoded in the JSON returned by the IAM /userinfo
  endpoint as an array of group names.
- Group information is also exposed by the token introspection endpoint
- External authentication information (i.e. when a user authenticates with
  Google or SAML instead of username/password) is now provided in the JSON
  returned by the /userinfo endpoint
- The first incarnation of the administrative dashboard is now included in the
  service 
- The first incarnation of the registration service is now included. The
  registration service implements a "self-register with admin approval"
  registration flow 
- User passwords are now encoded in the database using the Bcrypt encoder
- A password forgotten service is now provided

More information about bug fixes and other developments can be found on
our [JIRA release board][jira-v0.4.0]

## 0.3.0 (2016-07-12)

This is the first public release of the INDIGO Identity and Access Management
Service.

The IAM is an OpenID-connect identity provider which provides:

- OpenID-connect and OAuth client registration and management (leveraging and
  extending the [MitreID connect server][mitre] functionality
- [SCIM][scim] user and group provisioning and management
- A partial implementation of the [OAuth Token Exchange draft
  standard][token-exchange] for OAuth token delegation and impersonation

The IAM is currently released as a [Docker image][iam-image] hosted on
Dockerhub.

Documentation on how to build and run the service can be found in the [IAM
GitBook manual][gitbook-manual] or on [Github][github-doc].

[iam-image]: https://hub.docker.com/r/indigodatacloud/iam-login-service
[mitre]: https://github.com/mitreid-connect/OpenID-Connect-Java-Spring-Server
[scim]: http://www.simplecloud.info
[token-exchange]: https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-05
[gitbook-manual]: https://www.gitbook.com/book/andreaceccanti/iam/details
[github-doc]: https://github.com/indigo-iam/iam/blob/master/SUMMARY.md
[jira-v0.4.0]: https://issues.infn.it/jira/browse/INDIAM/fixforversion/13811 
[docsy]: https://github.com/google/docsy
