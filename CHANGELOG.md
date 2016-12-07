# Changelog

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
