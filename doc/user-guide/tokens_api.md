# Tokens API reference

The IAM server has a RESTful API used to list and revoke active access and refresh tokens.

This API may be accessed by administrators through an active web session within the application or 
through authorizing a client application through OAuth. All examples assume OAuth2 bearer token; e.g.

```
GET /access-tokens/13 HTTP/1.1
Host: example.com
Authorization: Bearer h480djs93hd8
```

These are the tokens REST API endpoints:

**GET**:

- [GET /access-tokens/:id](#get-access-tokensid)
- [GET /access-tokens](#get-access-tokens)
- [GET /refresh-tokens/:id](#get-refresh-tokensid)
- [GET /refresh-tokens](#get-refresh-tokens)

**DELETE**:

- [DELETE /access-tokens/:id](#delete-access-tokensid)
- [DELETE /refresh-tokens/:id](#delete-refresh-tokensid)

## GET /access-tokens/:id

Retrieves all the information about the access token identified by **id** and returns results in _application/json_.

Requires **ROLE_ADMIN**.

```
GET http://example.com:8080/access-tokens/6
```

```json
{
  "id": 6,
  "value": "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MDEzMTQ1MjksImF1ZCI6WyJhOGFmNzUzYy1mMzI0LTRlNDAtYTE3Ny04N2RmYzA2MjQ5YjciXSwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL29wZW5pZC1jb25uZWN0LXNlcnZlci13ZWJhcHBcLyIsImp0aSI6Ijg4ZjM4OGE4LTk1NzctNGQyMC1hZTZjLWMyMDMxOGQ1OWJjNiIsImlhdCI6MTQwMTMxMDkyOX0.HYnNxRvGRdKFykVChL-hdxszcFBvygkeUmc8_iv2Jl4MU-jPJVzMnTwKJbCMWBjeBp8hrb0Dgd9XbnHUDyXxwj8MDrWQEH3QnwYJGRW9JFWjHMGfKDQDFY6Ffl3OFERVbyoB2ObiGTUgbw4Nkl1L1ihuMpMAc5nKi0rk3QXcS1M",
  "scopes": [
    "openid",
    "phone",
    "email",
    "address",
    "profile"
  ],
  "expiration": "2014-05-28T18:02:09-0400",
  "client": {
    "id": 2,
    "clientId": "iam-test-client",
    "contacts": [
      "andrea.ceccanti@cnaf.infn.it"
    ],
    "ref": "https://iam-test.indigo-datacloud.eu/api/clients/2"
  },
  "user": {
    "id": "e1eb758b-b73c-4761-bfff-adc793da409c",
    "userName": "andrea",
    "ref": "https://iam-test.indigo-datacloud.eu/scim/Users/e1eb758b-b73c-4761-bfff-adc793da409c"
  },
  "idToken": {
    "id": 5,
    "ref": "https://iam-test.indigo-datacloud.eu/access-tokens/5"
  }
}
```

## GET /access-tokens

Retrieves the paginated list of all the active access tokens. Returns results in _application/json_.

Requires **ROLE_ADMIN**.

Parameters:

| Name | Description |
|:------------:|-------------|
| `count`<br/>**integer**| Specifies the desired maximum number of query results per page. |
| `startIndex`<br/>**integer**| The 1-based index of the first query result. |
| `userId`<br/>**string**| Filters by userId. |
| `clientId`<br/>**string**| Filters by clientId. |

Example:

```
GET http://example.com:8080/access-tokens
```

```json
{
  "totalResults": 1,
  "itemsPerPage": 1,
  "startIndex": 1,
  "resources": [
    {
      "id": 6,
      "value": "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MDEzMTQ1MjksImF1ZCI6WyJhOGFmNzUzYy1mMzI0LTRlNDAtYTE3Ny04N2RmYzA2MjQ5YjciXSwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL29wZW5pZC1jb25uZWN0LXNlcnZlci13ZWJhcHBcLyIsImp0aSI6Ijg4ZjM4OGE4LTk1NzctNGQyMC1hZTZjLWMyMDMxOGQ1OWJjNiIsImlhdCI6MTQwMTMxMDkyOX0.HYnNxRvGRdKFykVChL-hdxszcFBvygkeUmc8_iv2Jl4MU-jPJVzMnTwKJbCMWBjeBp8hrb0Dgd9XbnHUDyXxwj8MDrWQEH3QnwYJGRW9JFWjHMGfKDQDFY6Ffl3OFERVbyoB2ObiGTUgbw4Nkl1L1ihuMpMAc5nKi0rk3QXcS1M",
      "scopes": [
        "openid",
        "phone",
        "email",
        "address",
        "profile"
      ],
      "expiration": "2014-05-28T18:02:09-0400",
      "client": {
        "id": 2,
        "clientId": "iam-test-client",
        "contacts": [
          "andrea.ceccanti@cnaf.infn.it"
        ],
        "ref": "https://iam-test.indigo-datacloud.eu/api/clients/2"
      },
      "user": {
        "id": "e1eb758b-b73c-4761-bfff-adc793da409c",
        "userName": "andrea",
        "ref": "https://iam-test.indigo-datacloud.eu/scim/Users/e1eb758b-b73c-4761-bfff-adc793da409c"
      },
      "idToken": {
        "id": 5,
        "ref": "https://iam-test.indigo-datacloud.eu/access-tokens/5"
      }
    }
  ]
}
```

## GET /refresh-tokens/:id

Retrieves all the information about the refresh token identified by **id** and returns results in _application/json_.

Requires **ROLE_ADMIN**.

```
GET http://example.com:8080/refresh-tokens/1083
```

```json
{
  "id": 1083,
  "value": "eyJhbGciOiJub25lIn0.eyJqdGkiOiIxMTdmMWRkOS1iOWViLTQ5MjctYThkMS1hYzQ4NjIwYWQzOWYifQ.",
  "scopes": [
    "openid",
    "phone",
    "email",
    "address",
    "profile"
  ],
  "expiration": "2014-05-28T18:02:09-0400",
  "client": {
    "id": 2,
    "clientId": "iam-test-client",
    "contacts": [
      "andrea.ceccanti@cnaf.infn.it"
    ],
    "ref": "https://iam-test.indigo-datacloud.eu/api/clients/2"
  },
  "user": {
    "id": "e1eb758b-b73c-4761-bfff-adc793da409c",
    "userName": "andrea",
    "ref": "https://iam-test.indigo-datacloud.eu/scim/Users/e1eb758b-b73c-4761-bfff-adc793da409c"
  }
}
```

## GET /refresh-tokens


Retrieves the paginated list of all the active refresh tokens. Returns results in _application/json_.

Requires **ROLE_ADMIN**.

Parameters:

| Name | Description |
|:------------:|-------------|
| `count`<br/>**integer**| Specifies the desired maximum number of query results per page. |
| `startIndex`<br/>**integer**| The 1-based index of the first query result. |
| `userId`<br/>**string**| Filters by userId. |
| `clientId`<br/>**string**| Filters by clientId. |

Example:

```
GET http://example.com:8080/refresh-tokens
```

```json
{
  "totalResults": 1,
  "itemsPerPage": 1,
  "startIndex": 1,
  "resources": [
  	 {
	  "id": 1083,
	  "value": "eyJhbGciOiJub25lIn0.eyJqdGkiOiIxMTdmMWRkOS1iOWViLTQ5MjctYThkMS1hYzQ4NjIwYWQzOWYifQ.",
	  "scopes": [
	    "openid",
	    "phone",
	    "email",
	    "address",
	    "profile"
	  ],
	  "expiration": "2014-05-28T18:02:09-0400",
	  "client": {
	    "id": 2,
	    "clientId": "iam-test-client",
	    "contacts": [
	      "andrea.ceccanti@cnaf.infn.it"
	    ],
	    "ref": "https://iam-test.indigo-datacloud.eu/api/clients/2"
	  },
	  "user": {
	    "id": "e1eb758b-b73c-4761-bfff-adc793da409c",
	    "userName": "andrea",
	    "ref": "https://iam-test.indigo-datacloud.eu/scim/Users/e1eb758b-b73c-4761-bfff-adc793da409c"
	  }
	}
  ]
}
```

## DELETE /access-tokens/:id

Revoke the access token identified by **id**.

Requires **ROLE_ADMIN**.

```
DELETE http://example.com:8080/access-tokens/6
```

```
204  AccessToken revoked
```


## DELETE /refresh-tokens/:id

Revoke the access token identified by **id**.

Requires **ROLE_ADMIN**.

```
DELETE http://example.com:8080/refresh-tokens/1083
```

```
204  RefreshToken revoked
```

More details can be read at the [complete API Reference](tokens_api/index.html).