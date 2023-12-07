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
package it.infn.mw.iam.test.api.mitre;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.openid.connect.web.ProtectedResourceRegistrationEndpoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;

import com.nimbusds.jwt.JWTParser;

import io.restassured.RestAssured;
import io.restassured.response.ValidatableResponse;
import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.ClientJsonStringBuilder;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
public class ProtectedResourceIntegrationTests {

  @Value("${local.server.port}")
  private Integer iamPort;

  @Autowired
  private ClientManagementService managementService;

  private ValidatableResponse doCreateProtectedResource(String clientJson) {

    return RestAssured.given()
      .port(iamPort)
      .contentType(APPLICATION_JSON_VALUE)
      .body(clientJson)
      .log()
      .all(true)
      .when()
      .post("/" + ProtectedResourceRegistrationEndpoint.URL)
      .then()
      .log()
      .all(true);
  }

  private ValidatableResponse doGetProtectedResource(String clientId, String rat) {

    return RestAssured.given()
      .port(iamPort)
      .accept(APPLICATION_JSON_VALUE)
      .header("Authorization", "Bearer " + rat)
      .log()
      .all(true)
      .when()
      .get("/" + ProtectedResourceRegistrationEndpoint.URL + "/" + clientId)
      .then()
      .log()
      .all(true);
  }

  private ValidatableResponse doUpdateProtectedResource(String clientId, String clientJson,
      String rat) {

    return RestAssured.given()
      .port(iamPort)
      .contentType(APPLICATION_JSON_VALUE)
      .accept(APPLICATION_JSON_VALUE)
      .header("Authorization", "Bearer " + rat)
      .body(clientJson)
      .log()
      .all(true)
      .when()
      .put("/" + ProtectedResourceRegistrationEndpoint.URL + "/" + clientId)
      .then()
      .log()
      .all(true);
  }

  private ValidatableResponse doDeleteProtectedResource(String clientId, String rat) {

    return RestAssured.given()
      .port(iamPort)
      .accept(APPLICATION_JSON_VALUE)
      .header("Authorization", "Bearer " + rat)
      .log()
      .all(true)
      .when()
      .delete("/" + ProtectedResourceRegistrationEndpoint.URL + "/" + clientId)
      .then()
      .log()
      .all(true);
  }

  @Test
  public void protectedResourceLifeCycle() throws Exception {

    final String NAME = "protected-resource";
    String clientJson = ClientJsonStringBuilder.builder().name(NAME).scopes("openid").build();

    // create protected resource
    RegisteredClientDTO testedResource =
        doCreateProtectedResource(clientJson).statusCode(HttpStatus.CREATED.value())
          .extract()
          .as(RegisteredClientDTO.class);

    // verify registration access token exists and expiration is null
    assertNull(JWTParser.parse(testedResource.getRegistrationAccessToken())
      .getJWTClaimsSet()
      .getExpirationTime());

    // retrieve protected resource directly from db
    RegisteredClientDTO fromDb =
        managementService.retrieveClientByClientId(testedResource.getClientId()).get();
    assertEquals(testedResource.getClientId(), fromDb.getClientId());
    assertTrue(fromDb.getGrantTypes().isEmpty());
    assertTrue(fromDb.getResponseTypes().isEmpty());
    assertTrue(fromDb.getRedirectUris().isEmpty());
    assertEquals(NAME, fromDb.getClientName());
    assertEquals(0, fromDb.getAccessTokenValiditySeconds());
    assertEquals(0, fromDb.getIdTokenValiditySeconds());
    assertEquals(0, fromDb.getRefreshTokenValiditySeconds());
    assertTrue(fromDb.isDynamicallyRegistered());
    assertTrue(fromDb.isAllowIntrospection());
    assertFalse(fromDb.getScope().isEmpty());
    assertEquals(1, fromDb.getScope().size());
    assertTrue(fromDb.getScope().contains("openid"));


    // retrieve protected resource from API
    RegisteredClientDTO fromAPI = doGetProtectedResource(testedResource.getClientId(),
        testedResource.getRegistrationAccessToken()).statusCode(HttpStatus.OK.value())
          .extract()
          .as(RegisteredClientDTO.class);

    assertEquals(testedResource.getClientId(), fromAPI.getClientId());
    assertEquals(NAME, fromAPI.getClientName());
    assertNull(fromAPI.getGrantTypes());
    assertNull(fromAPI.getResponseTypes());
    assertNull(fromAPI.getRedirectUris());
    assertNull(fromAPI.getAccessTokenValiditySeconds());
    assertNull(fromAPI.getIdTokenValiditySeconds());
    assertNull(fromAPI.getRefreshTokenValiditySeconds());
    assertEquals(0, fromAPI.getClientSecretExpiresAt().toInstant().getEpochSecond());
    assertFalse(fromAPI.getScope().isEmpty());
    assertEquals(1, fromAPI.getScope().size());
    assertTrue(fromAPI.getScope().contains("openid"));

    // update protected resource from API
    clientJson = ClientJsonStringBuilder.builder()
      .clientId(testedResource.getClientId())
      .name(NAME)
      .scopes("openid email")
      .build();
    RegisteredClientDTO updated = doUpdateProtectedResource(testedResource.getClientId(),
        clientJson, testedResource.getRegistrationAccessToken()).statusCode(HttpStatus.OK.value())
          .extract()
          .as(RegisteredClientDTO.class);

    assertEquals(testedResource.getClientId(), updated.getClientId());
    assertEquals(NAME, updated.getClientName());
    assertNull(updated.getGrantTypes());
    assertNull(updated.getResponseTypes());
    assertNull(updated.getRedirectUris());
    assertNull(updated.getAccessTokenValiditySeconds());
    assertNull(updated.getIdTokenValiditySeconds());
    assertNull(updated.getRefreshTokenValiditySeconds());
    assertEquals(0, updated.getClientSecretExpiresAt().toInstant().getEpochSecond());
    assertFalse(updated.getScope().isEmpty());
    assertEquals(2, updated.getScope().size());
    assertTrue(updated.getScope().contains("openid"));
    assertTrue(updated.getScope().contains("email"));

    doDeleteProtectedResource(testedResource.getClientId(),
        testedResource.getRegistrationAccessToken()).statusCode(HttpStatus.NO_CONTENT.value());

    assertTrue(managementService.retrieveClientByClientId(testedResource.getClientId()).isEmpty());
  }
}
