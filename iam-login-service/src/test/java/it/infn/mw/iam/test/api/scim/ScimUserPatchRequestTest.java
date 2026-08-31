/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.test.api.scim;

import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_USER_SCHEMA;
import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.replace;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.scim.model.ScimPatchOperation;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.test.util.RestAssuredJacksonUtils;

class ScimUserPatchRequestTest {

  private final ObjectMapper mapper = RestAssuredJacksonUtils.createJacksonObjectMapper();

  @Test
  void preservesLegacyPathlessPartialUserValue() throws JsonProcessingException {

    String json = """
        {
          "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          "Operations": [{
            "op": "replace",
            "value": {"userName": "legacy-user", "active": true}
          }]
        }
        """;

    ScimPatchOperation<ScimUser> operation = readSingleOperation(json);

    assertEquals(replace, operation.getOp());
    assertNull(operation.getPath());
    assertEquals("legacy-user", operation.getValue().getUserName());
    assertTrue(operation.getValue().getActive());
  }

  @Test
  void rejectsPartialUserObjectWhenPathTargetsScalarAttribute() {

    String json = """
        {
          "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          "Operations": [{
            "op": "replace", "path": "userName",
            "value": {"userName": "legacy-user"}
          }]
        }
        """;

    assertThrows(JsonProcessingException.class,
        () -> mapper.readValue(json, ScimUserPatchRequest.class));
  }

  @Test
  void deserializesEntraStyleScalarAndComplexPathValues() throws JsonProcessingException {

    String json = """
        {
          "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          "Operations": [
            {"op": "Replace", "path": "userName", "value": "entra-user"},
            {"op": "replace", "path": "active", "value": false},
            {"op": "replace", "path":
              "urn:ietf:params:scim:schemas:core:2.0:User:name.givenName",
              "value": "Entra"},
            {"op": "replace", "path": "name", "value": {"familyName": "Person"}},
            {"op": "replace", "path": "emails[type eq \\"work\\"].value",
              "value": "entra-user@example.org"},
            {"op": "replace", "path": "%s:affiliation", "value": "member"}
          ]
        }
        """.formatted(INDIGO_USER_SCHEMA);

    ScimUserPatchRequest request = mapper.readValue(json, ScimUserPatchRequest.class);

    assertEquals("entra-user", request.getOperations().get(0).getValue().getUserName());
    assertFalse(request.getOperations().get(1).getValue().getActive());
    assertEquals("Entra",
        request.getOperations().get(2).getValue().getName().getGivenName());
    assertEquals("Person",
        request.getOperations().get(3).getValue().getName().getFamilyName());
    assertEquals("entra-user@example.org",
        request.getOperations().get(4).getValue().getEmails().get(0).getValue());
    assertEquals("member",
        request.getOperations().get(5).getValue().getIndigoUser().getAffiliation());
  }

  @Test
  void keepsUnsupportedPathForUpdaterErrorHandling() throws JsonProcessingException {

    String json = """
        {
          "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          "Operations": [{
            "op": "replace", "path": "externalId", "value": "external-user"
          }]
        }
        """;

    ScimPatchOperation<ScimUser> operation = readSingleOperation(json);

    assertEquals("externalId", operation.getPath());
    assertNull(operation.getValue().getUserName());
  }

  @Test
  void rejectsWrongNativeValueType() {

    String json = """
        {
          "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          "Operations": [{
            "op": "replace", "path": "active", "value": "true"
          }]
        }
        """;

    assertThrows(JsonProcessingException.class,
        () -> mapper.readValue(json, ScimUserPatchRequest.class));
  }

  @Test
  void deserializesEverySupportedCollectionAndExtensionPath() throws JsonProcessingException {

    String json = patchRequest("""
        {"op": "replace", "path": "password", "value": "new-password"},
        {"op": "replace", "path": "emails",
          "value": {"value": "path-email@example.org"}},
        {"op": "replace", "path": "photos",
          "value": {"type": "photo", "value": "https://example.org/photo.jpg"}},
        {"op": "replace", "path": "%1$s:serviceAccount", "value": true},
        {"op": "add", "path": "%1$s:sshKeys",
          "value": [{"display": "test key", "value": "ssh-rsa test"}]},
        {"op": "add", "path": "%1$s:oidcIds",
          "value": {"issuer": "https://issuer.example", "subject": "subject"}},
        {"op": "add", "path": "%1$s:samlIds",
          "value": [{"idpId": "idp", "userId": "user", "attributeId": "attribute"}]},
        {"op": "add", "path": "%1$s:certificates",
          "value": {"subjectDn": "CN=user", "issuerDn": "CN=issuer"}},
        {"op": "replace", "path": "photos[type eq \\"photo\\"].value",
          "value": "https://example.org/new-photo.jpg"}
        """.formatted(INDIGO_USER_SCHEMA));

    List<ScimPatchOperation<ScimUser>> operations =
        mapper.readValue(json, ScimUserPatchRequest.class).getOperations();

    assertEquals("new-password", operations.get(0).getValue().getPassword());
    assertEquals("path-email@example.org",
        operations.get(1).getValue().getEmails().get(0).getValue());
    assertEquals("https://example.org/photo.jpg",
        operations.get(2).getValue().getPhotos().get(0).getValue());
    assertTrue(operations.get(3).getValue().getIndigoUser().getServiceAccount());
    assertEquals("ssh-rsa test",
        operations.get(4).getValue().getIndigoUser().getSshKeys().get(0).getValue());
    assertEquals("https://issuer.example",
        operations.get(5).getValue().getIndigoUser().getOidcIds().get(0).getIssuer());
    assertEquals("idp",
        operations.get(6).getValue().getIndigoUser().getSamlIds().get(0).getIdpId());
    assertEquals("CN=user",
        operations.get(7).getValue().getIndigoUser().getCertificates().get(0).getSubjectDn());
    assertEquals("https://example.org/new-photo.jpg",
        operations.get(8).getValue().getPhotos().get(0).getValue());
  }

  @Test
  void rejectsMalformedNativePathValues() {

    List<String> invalidOperations = List.of(
        "{\"op\":\"replace\",\"value\":\"not-an-object\"}",
        "{\"op\":\"replace\",\"path\":\"name\",\"value\":\"not-an-object\"}",
        "{\"op\":\"replace\",\"path\":\"name\",\"value\":{}}",
        "{\"op\":\"replace\",\"path\":\"name\",\"value\":{\"middleName\":\"x\"}}",
        "{\"op\":\"replace\",\"path\":\"emails\",\"value\":\"not-an-object\"}",
        "{\"op\":\"replace\",\"path\":\"photos\",\"value\":[42]}",
        "{\"op\":\"replace\",\"path\":\"password\",\"value\":null}",
        "{\"op\":\"replace\",\"path\":\"password\"}");

    invalidOperations.forEach(operation -> assertThrows(JsonProcessingException.class,
        () -> mapper.readValue(patchRequest(operation), ScimUserPatchRequest.class), operation));
  }

  private ScimPatchOperation<ScimUser> readSingleOperation(String json)
      throws JsonProcessingException {

    return mapper.readValue(json, ScimUserPatchRequest.class).getOperations().get(0);
  }

  private String patchRequest(String operations) {

    return """
        {
          "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          "Operations": [%s]
        }
        """.formatted(operations);
  }
}
