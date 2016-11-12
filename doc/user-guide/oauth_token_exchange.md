## OAuth Token exchange support

The current release of the INDIGO IAM implements part of the [Token Exchange
OAuth
specification](https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-05).
The Token Exchange OAuth specification defines "a lightweigth protocol that
enables clients to request and obtain security tokens from authorization
servers".

OAuth 2.0 was designed to solve the problem of a delegated access to resources
across services, mediated by an authorization server, as shown in the following
picture:

<img src="./images/oauth-delegation-1.png" alt="OAuth delegation" height="200">

In the picture above we have the usual OAuth roles:
- The user (or *resource owner*, in OAuth terminology);
- A resource server, ie. a service hosting user resources, capable of
  accepting and responding to protected resource requests using access tokens.
- A client: this is an agent that has received a permission from the user to
  act on his behalf on his resources hosted on a resource server;
- An authorization server: a service that issues access token to clients after
  having authenticated the user and obtained an authorization from the user
  that the client is entitled to act on user's resources

There are scenarios when a resource server, in order to satisfy a client
request, needs to access resources hosted by other downstream services on
behalf of the user, like in the following picture:

<img src="./images/oauth-token-exchange-1.png" alt="OAuth delegation" height="200">

In OAuth, access tokens are bearer tokens, so the first resource server could
simply use the access token received from the client to interact, on behalf
of the user, with the downstream resource server.

There are, however, situations in which just using the received access token
against the downstream service is not possible, like for instance if the token
audience was scoped to be valid only on the first resource server. 

Moreover, the resource server could need the ability to act on behalf of the
user for an unbounded amount of time (e.g., to implement long-running
computations), not limited by the validity of the received access token.

The token exchange specification was designed to provide a protocol in support
of these scenarios, where a client can exchange an access token received from
antoher client with a new token (or a set of tokens, as we will see) by
interacting with a trusted OAuth authorization server.

#### Impersonation vs delegation

As specified in the [Token Exchange OAuth
specification](https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-05),
when a subject A impersonates B, A has all the rights of B and it is
indistinguishable from B. So, when A interacts within any other entity, A is B.

With delegation A still has its own identity, separate from B. So when A
interacts within another entity, it is explicit that A is representing B,
because B has delegated some of its rights to A.  

More details about the difference from this two semantics can be found in
[this section of the specification](https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-05#section-1.1).

The INDIGO IAM token exchange implementation currently supports only
impersonation semantics.

### Configuration

In order to request a token exchange, a client must be configured with the
`urn:ietf:params:oauth:grant-type:token-exchange` grant type enabled. The token
exchange grant type is **disabled** by default for dynamically registered
clients, and can be enabled only by users with administrative privileges on the
IAM.

### The token exchange request

A client who wants to exchange an access token with a new one (or a couple of
new tokens, in case a refresh token is requested), must send an authenticated
request to the IAM `/token` endpoint, specifying the following properties:

| Parameter          | Value |
|--------------------|-------|
| grant_type         | `urn:ietf:params:oauth:grant-type:token-exchange` |
| subject_token      | The subject access token that the client wants to exchange |
| scope              | The set of scopes requested for the new access token |
| audience           | Optional. A space-separated list of resource identifiers that will be used to limit the audience of the issued token |

#### Scopes in exchanged tokens 

A client, when requesting a token exchange, can request any of the scopes
enabled by its client configuration. IAM system scopes are however handled in a
special way. These scopes, in order to be "exchanged" across clients, need to
be 

- enabled for the client requesting the token exchange
- linked to the subject token presented for the token exchange

The list of system scopes currently defined in the IAM can be obtained by
registered users by issuing a request to the IAM system scopes API: 

```
curl -H "Authorization: Bearer ..." https://iam.example/api/scopes
```

### Token Exchange example

This section describes a token exchange flow.

We start with a normal OAuth flow where a client, `token-exchange-subject`,
requests an access token from the IAM using the resource owner password
credential flow. The `token-exchange-subject` client is configured to use HTTP
basic authentication against the IAM token endpoint, and in this example acts
on behalf of the `test` user. We use the resource owner password credentials
flow for convenience, but any other OAuth or OpenID connect flow that involves
a user identity would be fine (i.e., authorization code).

```bash
$ export IAM_TOKEN_ENDPOINT=https://iam.local.io/token
$ export SUBJECT_ID=token-exchange-subject
$ export SUBJECT_SECRET=...
$ export USERNAME=test
$ export PASSWORD=...

$ curl -s -u $SUBJECT_ID:$SUBJECT_SECRET \
  -d username=$USERNAME \
  -d password=$PASSWORD \
  -d grant_type=password \
  -d scope="openid profile" \
  $IAM_TOKEN_ENDPOINT | tee /tmp/response | jq
```

Note that the only scopes requested in this first request are `openid` and
`profile`, i.e. the scopes required to access user identity information. IAM
token endpoint returns a JSON containing an access token and other info:

```json
{
  "access_token": "eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJhY2JjY2QwOC1kNzNkLTQxZjItODk3MS1iNjA4ZmNjNjYyNmQiLCJpc3MiOiJodHRwczpcL1wvaWFtLmxvY2FsLmlvXC8iLCJleHAiOjE0NzY5NTcxMDIsImlhdCI6MTQ3Njk1MzUwMiwianRpIjoiMjBiZThlNjYtNmNmOS00YzE0LWI4ZDEtZjJmZTc0NDk0YjAxIn0.kqAhZ2MNmBLYIA_-xW9356kD-ndqJ7jKUZRPb7ox_4iXbjcnV6oZYAHZzTH_uBTXA2WsVIJJ-Qicm5JQ0ydb2ewgECAmGkKfL3X4qnnRq2_GgZZof3zlM_rIz3QrDB3v1eIt42YeMdUgODUYGKeDwntT5a7wPDtxe-GM2uL5fik",
  "token_type": "Bearer",
  "expires_in": 3599,
  "scope": "openid profile",
  "id_token": "eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJhY2JjY2QwOC1kNzNkLTQxZjItODk3MS1iNjA4ZmNjNjYyNmQiLCJhdWQiOiIzMmMzMTUyOS05YmM2LTQ1ZWQtYjU0YS0wNGEyNThiMDRmYmYiLCJraWQiOiJyc2ExIiwiaXNzIjoiaHR0cHM6XC9cL2lhbS5sb2NhbC5pb1wvIiwiZXhwIjoxNDc2OTU0MTAyLCJpYXQiOjE0NzY5NTM1MDIsImp0aSI6IjhhMzk1OTM5LTM1N2QtNGY5My04MmEzLTJkMTBkM2ZhMzgzZCJ9.DtNR-ob8kMIUMa2x6TW7krSYMt78tfr5fnTK4aeoIY-wmEWcjPRx1_vT6_lesjMr9w0B_OCALXfOoDBfbF7DhmV7vpbotirkMxvowFBzgppmtBTZNAzLc_Wiwr4IAiGydwjy_UbYrxx6qlWJAKRwzSbDDd3oDVpU-KM8gtLIEa8"
}
```
We put this access token in an environment variable:

```bash
 $ export SUBJECT_TOKEN=$(cat /tmp/response | jq -r .access_token)
```

We use this access token to access the `app` API, which only requires access to
user identity to grant access:

```
curl -H "Authorization: Bearer $SUBJECT_TOKEN" https://app.example.org/api
```

Suppose now that the `app` API needs, to properly answer the request from the
client, to interact with another downstream service, https://tasks.example.org,
on behalf of the user. Unfortunately the set of scopes linked to the access
token received are not sufficient to do this, and so `app` decides to exchange
the token received with another one granting enough privileges.

In Token Exchange terms, here `app` is the `actor`, the subject identity linked
to the token is the `test` user, and the audience for the new token being
requested would be the `https://tasks.app.example.org/api` API.

So `app` would do a request like the following:

```bash
$ export ACTOR_ID=https://app.example.org/api
$ export ACTOR_SECRET=...
$ export AUDIENCE=https://tasks.example.org/api

$ curl -s -u $ACTOR_ID:$ACTOR_SECRET \
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    -d audience=$AUDIENCE \
    -d subject_token=$SUBJECT_TOKEN \ # This token was received from the initial client 
    -d scope="openid profile read-tasks" \
    $IAM_TOKEN_ENDPOINT | tee /tmp/response | jq


```

Note that `app` requests an additional scope, `read-tasks`, to interact with
the downstream service.

Since `app` is a trusted client for token exchange, the IAM responds with the
following JSON:

```json
{
  "access_token": "eyJra...",
  "token_type": "Bearer",
  "expires_in": 3599,
  "scope": "openid profile read-tasks",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt"
}
```

And `app` can use the newly issued access token to invoke services on
https://task-app.example.org/api on behalf of user `test`:

```
$ curl -H "Authorization: Bearer eyJra..." http://tasks.example.org/api

```

### Trust 

Clients that have the token exchange grant enabled are considered trusted
clients i.e., no explicit grant from the user is needed to grant access to
client scopes. For IAM system scopes, however, these can be "exchanged" only if
linked to the original subject token.

### Limitation and known issues

The current implementation of Token Exchange in Indigo IAM has the following limitations:

- Delegation is not yet supported: if `actor_token` or the `want_composite`
  parameters are specified within the request, an error response is returned by
  the authorization server;
- The `resource` field is ignored.
