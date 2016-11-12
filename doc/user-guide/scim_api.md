## SCIM API reference

The IAM server has a RESTful API that is used to manage users, change their personal information, add or remove them from a group, add Open ID Connect accounts, x509 certificates, ssh keys, ecc.

The API may be accessed through an active web session within the application or through authorizing a client application through OAuth. The SCIM protocol, in fact, does not define a scheme for authentication and authorization therefore implementers are free to choose mechanisms appropriate to their use cases. All examples assume OAuth2 bearer token; e.g.

```
GET /Users/2819c223-7f76-453a-919d-413861904646 HTTP/1.1
Host: example.com
Authorization: Bearer h480djs93hd8
```

The SCIM protocol specifies well known endpoints and HTTP methods for managing Resources defined in the [core schema](https://tools.ietf.org/html/rfc7643) i.e., User and Group Resources correspond to /Users and /Groups respectively.

### IAM SCIM Endpoints

IAM maps User and Group resource endpoints to:

- `/scim/Users`
- `/scim/Groups`

For each endpoint, the following methods are allowed:

| HTTP Method | Description |
|-------------|-------------|
| GET | Retrieves a complete or partial Resource. |
| POST | Create new Resource or bulk modify Resources. |
| PUT | Replace completely a Resource. |
| PATCH | Modifies a Resource with a set of specified changes \(partial update\). |
| DELETE | Deletes a Resource. |

#### GET `/scim/Users/{id}`

Retrieves all the information about the user identified by `id` and returns results in application/json.

Requires `ROLE_ADMIN` or scope `scim:read`.

```
GET http://localhost:8080/scim/Users/2cb10ac5-5b1a-47a0-8f60-48995999f18d
```

```
{
    "id": "2cb10ac5-5b1a-47a0-8f60-48995999f18d",
    "meta": {
        "created": "2016-07-13T18:38:16.314+02:00",
        "lastModified": "2016-07-13T18:38:16.314+02:00",
        "location": "http://localhost:8080/scim/Users/2cb10ac5-5b1a-47a0-8f60-48995999f18d",
        "resourceType": "User"
    },
    "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:User",
        "urn:indigo-dc:scim:schemas:IndigoUser"
    ],
    "userName": "paul_mccartney",
    "name": {
        "givenName": "Paul",
        "familyName": "McCartney",
        "formatted": "Paul McCartney"
    },
    "displayName": "paul_mccartney",
    "active": false,
    "emails": [
        {
            "type": "work",
            "value": "paul@beatles.uk",
            "primary": true
        }
    ]
}
```

#### POST `/scim/Users`

Creates a new user, using the info specified within the request body, sent as application/json.

Requires `ROLE_ADMIN` or scope `scim:write`.

```
POST http://localhost:8080/scim/Users/
```

```
{
    "userName": "paul_mccartney",
    "name": {
        "givenName": "Paul",
        "familyName": "McCartney",
        "formatted": "Paul McCartney"
    },
    "emails": [
        {
            "type": "work",
            "value": "paul@beatles.uk",
            "primary": true
        }
    ]
}
```

Successful Resource creation is indicated with a 201 ("Created") response code. Upon successful creation, the response body contains the newly created User.

```
{
    "id": "2cb10ac5-5b1a-47a0-8f60-48995999f18d",
    "meta": {
        "created": "2016-07-13T18:38:16.314+02:00",
        "lastModified": "2016-07-13T18:38:16.314+02:00",
        "location": "http://localhost:8080/scim/Users/2cb10ac5-5b1a-47a0-8f60-48995999f18d",
        "resourceType": "User"
    },
    "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:User",
        "urn:indigo-dc:scim:schemas:IndigoUser"
    ],
    "userName": "paul_mccartney",
    "name": {
        "givenName": "Paul",
        "familyName": "McCartney",
        "formatted": "Paul McCartney"
    },
    "displayName": "paul_mccartney",
    "active": false,
    "emails": [
        {
            "type": "work",
            "value": "paul@beatles.uk",
            "primary": true
        }
    ]
}
```

#### GET `/scim/Users`

Requires `ROLE_ADMIN` or scope `scim:read`.

SCIM defines a standard set of operations that can be used to filter, sort, and paginate response results. The operations are specified by adding query parameters to the Resource's endpoint.

**Pagination** parameters can be used together to "page through" large numbers of Resources. Pagination is not session based so clients must never assume repeatable results.

The following table describes the URL pagination parameters.

| Parameter | Description | Default |
|-----------|-------------|---------|
|startIndex | The 1-based index of the first search result. | 1 |
| count     | Non-negative Integer. Specifies the desired maximum number of search results per page; e.g., 10. | None. |

The following table describes the query response pagination attributes.

| Element | Description |
|---------|-------------|
| itemsPerPage | Non-negative Integer. Specifies the number of search results returned in a query response page; e.g., 10. |
| totalResults | Non-negative Integer. Specifies the total number of results matching the client query; e.g., 1000. |
| startIndex | The 1-based index of the first result in the current set of search results; e.g., 1. |

The below example returns the first 10 users (implicit startIndex as 1):

```
GET /scim/Users?count=10
```

```
{
    "totalResults": 250,
    "itemsPerPage": 10,
    "startIndex": 1,
    "schemas": [
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    ],
    "Resources": [
        {
            "id": "80e5fb8d-b7c8-451a-89ba-346ae278a66f",
            "meta": {
                "created": "2016-07-14T12:22:46.376+02:00",
                "lastModified": "2016-07-14T12:22:46.376+02:00",
                "location": "http://localhost:8080/scim/Users/80e5fb8d-b7c8-451a-89ba-346ae278a66f",
                "resourceType": "User"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:indigo-dc:scim:schemas:IndigoUser"
            ],
            "userName": "test",
            "name": {
                "givenName": "Test",
                "familyName": "User",
                "formatted": "Test User"
            },
            "displayName": "test",
            "active": true,
            "emails": [
                {
                    "type": "work",
                    "value": "test@iam.test",
                    "primary": true
                }
            ],
            "groups": [
                {
                    "display": "Production",
                    "value": "c617d586-54e6-411d-8e38-64967798fa8a",
                    "$ref": "http://localhost:8080/scim/Groups/c617d586-54e6-411d-8e38-64967798fa8a"
                },
                {
                    "display": "Analysis",
                    "value": "6a384bcd-d4b3-4b7f-a2fe-7d897ada0dd1",
                    "$ref": "http://localhost:8080/scim/Groups/6a384bcd-d4b3-4b7f-a2fe-7d897ada0dd1"
                }
            ],
            "urn:indigo-dc:scim:schemas:IndigoUser": {
                "oidcIds": [
                    {
                        "issuer": "https://accounts.google.com",
                        "subject": "105440632287425289613"
                    }
                ],
                "samlIds": [
                    {
                        "idpId": "https://idptestbed/idp/shibboleth",
                        "userId": "andrea.ceccanti@example.org"
                    }
                ]
            }
        },
        [...]
    ]
}
```

The details of the returned users can be reduced/filtered by specifying the needed attribute(s).
The below example returns only the userName for all Users:

```
GET http://localhost:8080/scim/Users?attributes=userName
```

```
{
    "totalResults": 250,
    "itemsPerPage": 100,
    "startIndex": 1,
    "schemas": [
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    ],
    "Resources": [
        {
            "id": "80e5fb8d-b7c8-451a-89ba-346ae278a66f",
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:indigo-dc:scim:schemas:IndigoUser"
            ],
            "userName": "test"
        },
        {
            "id": "73f16d93-2441-4a50-88ff-85360d78c6b5",
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:indigo-dc:scim:schemas:IndigoUser"
            ],
            "userName": "admin"
        },
        [...]
    ]
}
```

Multiple attributes are also supported:

```
GET http://localhost:8080/scim/Users?count=2&attributes=userName%2Cemails%2Curn%3Aindigo-dc%3Ascim%3Aschemas%3AIndigoUser
```

Request params:

- `count=2`
- `attributes=userName,emails,urn:indigo-dc:scim:schemas:IndigoUser`

```
{
    "totalResults": 250,
    "itemsPerPage": 2,
    "startIndex": 1,
    "schemas": [
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    ],
    "Resources": [
        {
            "id": "80e5fb8d-b7c8-451a-89ba-346ae278a66f",
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:indigo-dc:scim:schemas:IndigoUser"
            ],
            "userName": "test",
            "emails": [
                {
                    "type": "work",
                    "value": "test@iam.test",
                    "primary": true
                }
            ],
            "urn:indigo-dc:scim:schemas:IndigoUser": {
                "oidcIds": [
                    {
                        "issuer": "https://accounts.google.com",
                        "subject": "105440632287425289613"
                    }
                ],
                "samlIds": [
                    {
                        "idpId": "https://idptestbed/idp/shibboleth",
                        "userId": "andrea.ceccanti@example.org"
                    }
                ]
            }
        },
        {
            "id": "73f16d93-2441-4a50-88ff-85360d78c6b5",
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:indigo-dc:scim:schemas:IndigoUser"
            ],
            "userName": "admin",
            "emails": [
                {
                    "type": "work",
                    "value": "admin@iam.test",
                    "primary": true
                }
            ],
            "urn:indigo-dc:scim:schemas:IndigoUser": {
                "oidcIds": [
                    {
                        "issuer": "https://accounts.google.com",
                        "subject": "114132403455520317223"
                    }
                ],
                "samlIds": [
                    {
                        "idpId": "https://idptestbed/idp/shibboleth",
                        "userId": "ciccio.paglia@example.org"
                    }
                ]
            }
        }
    ]
}
```

**Filtering** and **sorting** are not supported.

#### PUT `/scim/Users/{id}`

Requires `ROLE_ADMIN` or scope `scim:write`.

PUT performs a full update.
Clients should retrieve the entire resource and then PUT the desired modifications as the operation
overwrites all previously stored data.
A successful PUT operation returns a 200 OK response code and the entire
resource within the response body.

Example of changing the userName from `john_lennon` to `j.lennon` and setting `active` as true:

```
GET http://localhost:8080/scim/Users/e380b4e3-7b63-47c2-b156-3699be9ebcfe
```

```
{
    "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:User",
        "urn:indigo-dc:scim:schemas:IndigoUser"
    ],
    "userName": "john_lennon",
    "name": {
        "givenName": "John",
        "familyName": "Lennon",
        "formatted": "John Lennon"
    },
    "emails": [
        {
            "type": "work",
            "value": "lennon@email.test",
            "primary": true
        }
    ]
}
```

Retrieved the user's info, update userName as `"userName": "j.lennon"` and add `"active": true`:

```
PUT http://localhost:8080/scim/Users/e380b4e3-7b63-47c2-b156-3699be9ebcfe
```

```
{
    "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:User",
        "urn:indigo-dc:scim:schemas:IndigoUser"
    ],
    "userName": "j.lennon",
    "name": {
        "givenName": "John",
        "familyName": "Lennon",
        "formatted": "John Lennon"
    },
    "active": true,
    "emails": [
        {
            "type": "work",
            "value": "lennon@email.test",
            "primary": true
        }
    ]
}
```

The returned answer is:

```
HTTP/1.1 200 OK
Content-Type: application/scim+json;charset=UTF-8
{
    "id": "e380b4e3-7b63-47c2-b156-3699be9ebcfe",
    "meta": {
        "created": "2016-07-14T15:42:56.275+02:00",
        "lastModified": "2016-07-14T15:42:56.445+02:00",
        "location": "http://localhost:8080/scim/Users/e380b4e3-7b63-47c2-b156-3699be9ebcfe",
        "resourceType": "User"
    },
    "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:User",
        "urn:indigo-dc:scim:schemas:IndigoUser"
    ],
    "userName": "j.lennon",
    "name": {
        "givenName": "John",
        "familyName": "Lennon",
        "formatted": "John Lennon"
    },
    "displayName": "j.lennon",
    "active": true,
    "emails": [
        {
            "type": "work",
            "value": "lennon@email.test",
            "primary": true
        }
    ]
}
```

#### PATCH `/scim/Users/{id}`

Requires `ROLE_ADMIN` or scope `scim:write`.

PATCH enables consumers to send only the attributes requiring modification, reducing network and processing overhead.
Attributes may be deleted, replaced, merged, or added in a single request.
The body of a PATCH request MUST contain a partial resource with the desired modifications.
The server MUST return either a 200 OK response code and the entire Resource within the response body,
or a 204 No Content response code and the appropriate response headers for a successful PATCH request.

The following example shows how to replace the userName:

```
PATCH http://localhost:8080/scim/Users/b6769dd1-3d7d-416d-be6d-020be23ba904
Body:
{
    "schemas": [
        "urn:ietf:params:scim:api:messages:2.0:PatchOp"
    ],
    "operations": [
        {
            "op": "replace",
            "value": {
                "userName": "john_lennon_jr",
            }
        }
    ]
}
```

The following example shows how to add an OpenID Connect account and a ssh key:

```
PATCH http://localhost:8080/scim/Users/b6769dd1-3d7d-416d-be6d-020be23ba904
Body:
{
    "schemas": [
        "urn:ietf:params:scim:api:messages:2.0:PatchOp"
    ],
    "operations": [
        {
            "op": "add",
            "value": {
                "urn:indigo-dc:scim:schemas:IndigoUser": {
                    "oidcIds": [
                        {
                            "issuer": "test_issuer",
                            "subject": "test_subject"
                        }
                    ],
                    "sshKeys": [
                        {
                            "display": "Personal",
                            "primary": true,
                            "value": "AAAAB3NzaC1yc2EAAAADAQABAAABAQC4tjz4mfMLvJsM8RXIgdRYPBhH//VXLXbeLbUsJpm5ARIQPY6Gu1befPA3jqKacvdcBrMsYGiMp/DOhpkAwWclSnzMdvYLbYWkrOPwBVrRh7lvFtXFLaQZ6do4uMZHb5zU2ViTFacrJ6zJ/GLltjk4nBea7Z4qHaQdWou3Fk/108oMQGx7jqW44m+TA+HYo6rEbVWbimWVXyyiKchO2LTLKUbK6GBSWJiItezwAWR3KKs3FXKRmbJDiKESh3mDccJidfkjzNLPyDf3JHI2b/C/mcvtJsoAtkIWuVll2BhBBiqkYt3tX2llZCYGtF7rZOYTsqhw+LPnsJtsX+W7e4iN"
                        }
                    ]
                }
            }
        }
    ]
}
```

#### DELETE `/scim/Users/{id}`

Requires `ROLE_ADMIN` or scope `scim:write`.

Clients request user removal via DELETE.

```
DELETE /scim/Users/4380e98c-02f2-4d10-85ba-9fbbdb819ed8
```

```
HTTP/1.1 200 OK
```

Example: Client attempt to retrieve the previously deleted User:

```
GET /scim/Users/4380e98c-02f2-4d10-85ba-9fbbdb819ed8
{
    "status": "404",
    "detail": "No user mapped to id '4380e98c-02f2-4d10-85ba-9fbbdb819ed8'",
    "schemas": [
        "urn:ietf:params:scim:api:messages:2.0:Error"
    ]
}
```

#### GET `/scim/Groups/{id}`

Retrieves all the information about the group identified by `id` and returns results in application/json.

Requires `ROLE_ADMIN` or scope `scim:read`.

```
GET /scim/Groups/c617d586-54e6-411d-8e38-64967798fa8a
```

```
{
    "id": "c617d586-54e6-411d-8e38-64967798fa8a",
    "meta": {
        "created": "2016-07-14T16:22:05.170+02:00",
        "lastModified": "2016-07-14T16:22:05.170+02:00",
        "location": "http://localhost:8080/scim/Groups/c617d586-54e6-411d-8e38-64967798fa8a",
        "resourceType": "Group"
    },
    "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:Group"
    ],
    "displayName": "Production",
    "members": [
        {
            "display": "test",
            "value": "80e5fb8d-b7c8-451a-89ba-346ae278a66f",
            "$ref": "http://localhost:8080/scim/Users/80e5fb8d-b7c8-451a-89ba-346ae278a66f"
        },
        {
            "display": "admin",
            "value": "73f16d93-2441-4a50-88ff-85360d78c6b5",
            "$ref": "http://localhost:8080/scim/Users/73f16d93-2441-4a50-88ff-85360d78c6b5"
        }
    ]
}
```

#### POST `/scim/Groups`

Creates a new group, using the info specified within the request body, sent as application/json.

Requires `ROLE_ADMIN` or scope `scim:write`.

```
POST http://localhost:8080/scim/Groups/
```

```
{
    "id": "7b427ebe-9058-479e-95b6-f3cebec91731",
    "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:Group"
    ],
    "displayName": "engineers"
}
```

Successful Resource creation is indicated with a 201 ("Created") response code. Upon successful creation, the response body contains the newly created User.

```
{
    "id": "7b427ebe-9058-479e-95b6-f3cebec91731",
    "meta": {
        "created": "2016-07-14T16:24:50.941+02:00",
        "lastModified": "2016-07-14T16:24:50.941+02:00",
        "location": "http://localhost:8080/scim/Groups/7b427ebe-9058-479e-95b6-f3cebec91731",
        "resourceType": "Group"
    },
    "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:Group"
    ],
    "displayName": "engineers"
}
```

#### GET `/scim/Groups`

Requires `ROLE_ADMIN` or scope `scim:read`.

The pagination seen for users can be applied also to groups:

Example: retrieve the 22nd group

```
GET http://localhost:8080/scim/Groups?startIndex=22&count=1
```

```
{
    "totalResults": 22,
    "itemsPerPage": 1,
    "startIndex": 22,
    "schemas": [
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    ],
    "Resources": [
        {
            "id": "c617d586-54e6-411d-8e38-649677980020",
            "meta": {
                "created": "2016-07-14T16:33:20.135+02:00",
                "lastModified": "2016-07-14T16:33:20.135+02:00",
                "location": "http://localhost:8080/scim/Groups/c617d586-54e6-411d-8e38-649677980020",
                "resourceType": "Group"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:Group"
            ],
            "displayName": "Test-020"
        }
    ]
}
```

#### PUT `/scim/Groups/{id}`

Requires `ROLE_ADMIN` or scope `scim:write`.

PUT performs a full update. Clients should retrieve the entire resource and then PUT the desired modifications
as the operation overwrites all previously stored data.
A successful PUT operation returns a 200 OK response code and the entire resource within the response body.

Example of replacing group with a different displayName:

```
PUT http://localhost:8080/scim/Groups/891d042d-fc6e-4408-8a3a-ad9dfdf5db89
{
    "id": "891d042d-fc6e-4408-8a3a-ad9dfdf5db89",
    "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:Group"
    ],
    "displayName": "engineers_updated"
}
```

```
{
    "id": "891d042d-fc6e-4408-8a3a-ad9dfdf5db89",
    "meta": {
        "created": "2016-07-14T16:37:18.302+02:00",
        "lastModified": "2016-07-14T16:37:18.411+02:00",
        "location": "http://localhost:8080/scim/Groups/891d042d-fc6e-4408-8a3a-ad9dfdf5db89",
        "resourceType": "Group"
    },
    "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:Group"
    ],
    "displayName": "engineers_updated"
}
```

#### PATCH `/scim/Groups/{id}`

Requires `ROLE_ADMIN` or scope `scim:write`.

The following example shows how to add member to a group:

```
PATCH http://localhost:8080/scim/Groups/4ca7fa98-0875-4eb3-a71f-0f88ce5632cf
{
    "schemas": [
        "urn:ietf:params:scim:api:messages:2.0:PatchOp"
    ],
    "operations": [
        {
            "op": "add",
            "path": "members",
            "value": [
                {
                    "display": "john_lennon",
                    "value": "e9c8cfca-7158-4a0d-9684-4abdede617cd",
                    "$ref": "http://localhost:8080/scim/Users/e9c8cfca-7158-4a0d-9684-4abdede617cd"
                }
            ]
        }
    ]
}
```

#### DELETE `/scim/Groups/{id}`

Requires `ROLE_ADMIN` or scope `scim:write`.

Clients request group removal via DELETE.

```
DELETE /scim/Groups/5bae2407-08e3-4171-b180-4b4a0196e7b6
```

```
HTTP/1.1 200 OK
```

Example: Client attempt to retrieve the previously deleted User:

```
GET /scim/Groups/5bae2407-08e3-4171-b180-4b4a0196e7b6
{
    "status": "404",
    "detail": "No group mapped to id '5bae2407-08e3-4171-b180-4b4a0196e7b6'",
    "schemas": [
        "urn:ietf:params:scim:api:messages:2.0:Error"
    ]
}
```


[mitre]: https://github.com/mitreid-connect/OpenID-Connect-Java-Spring-Server
[mitre-doc]: https://github.com/mitreid-connect/OpenID-Connect-Java-Spring-Server/wiki
[mitre-doc-api]: https://github.com/mitreid-connect/OpenID-Connect-Java-Spring-Server/wiki/API
