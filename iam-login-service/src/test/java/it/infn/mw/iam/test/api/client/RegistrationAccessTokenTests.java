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
package it.infn.mw.iam.test.api.client;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.text.ParseException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import io.restassured.RestAssured;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.core.TokenUtils;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.ClientJsonStringBuilder;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.RANDOM_PORT)
class RegistrationAccessTokenTests implements StructuredScopeTestSupportConstants {

  static final String LOCALHOST_URL_TEMPLATE = "http://localhost:%d";

  @Value("${local.server.port}")
  Integer iamPort;

  @Autowired
  ClientManagementService managementService;

  @Autowired
  IamOAuthAccessTokenRepository accessTokenRepo;

  @Autowired
  TokenUtils tokenUtils;

  String registerUrl;
  String ownedClientsUrl;

  @BeforeAll
  static void init() {
    TestUtils.initRestAssured();
  }

  @BeforeEach
  void setup() {
    RestAssured.port = iamPort;
    registerUrl = String.format(LOCALHOST_URL_TEMPLATE + "/iam/api/client-registration", iamPort);
    ownedClientsUrl = String.format(LOCALHOST_URL_TEMPLATE + "/iam/account/me/clients", iamPort);
  }

  @Test
  void testRatWorkAsExpected() throws ParseException {

    String clientJson =
        ClientJsonStringBuilder.builder().scopes("openid").grantTypes("authorization_code").build();

    RegisteredClientDTO registerResponse = RestAssured.given()
      .body(clientJson)
      .contentType(APPLICATION_JSON_VALUE)
      .when()
      .post(registerUrl)
      .then()
      .log()
      .all()
      .statusCode(HttpStatus.CREATED.value())
      .extract()
      .body()
      .as(RegisteredClientDTO.class);

    assertThat(registerResponse.getRegistrationAccessToken(), notNullValue());
    assertTrue(accessTokenRepo
      .findByTokenValue(tokenUtils.sha256(registerResponse.getRegistrationAccessToken()))
      .isPresent());
    JWT jwt = JWTParser.parse(registerResponse.getRegistrationAccessToken());
    assertThat(jwt.getJWTClaimsSet().getExpirationTime(), nullValue());
    assertThat(registerResponse.getScope(), not(empty()));

    RegisteredClientDTO getResponse = RestAssured.given()
      .auth()
      .oauth2(registerResponse.getRegistrationAccessToken())
      .when()
      .get(registerUrl + "/" + registerResponse.getClientId())
      .then()
      .statusCode(HttpStatus.OK.value())
      .log()
      .all()
      .extract()
      .body()
      .as(RegisteredClientDTO.class);

    assertThat(getResponse.getClientSecret(), nullValue());
    assertThat(getResponse.getRegistrationAccessToken(), nullValue());

    RegisteredClientDTO rotatedRatClient =
        managementService.rotateRegistrationAccessToken(getResponse.getClientId());

    assertThat(rotatedRatClient.getRegistrationAccessToken(), notNullValue());

    assertFalse(accessTokenRepo
      .findByTokenValue(tokenUtils.sha256(registerResponse.getRegistrationAccessToken()))
      .isPresent());

    assertTrue(accessTokenRepo
      .findByTokenValue(tokenUtils.sha256(rotatedRatClient.getRegistrationAccessToken()))
      .isPresent());

    RestAssured.given()
      .auth()
      .oauth2(registerResponse.getRegistrationAccessToken())
      .when()
      .get(registerUrl + "/" + registerResponse.getClientId())
      .then()
      .statusCode(HttpStatus.UNAUTHORIZED.value())
      .log()
      .ifError();

    RestAssured.given()
      .auth()
      .oauth2(rotatedRatClient.getRegistrationAccessToken())
      .when()
      .get(registerUrl + "/" + registerResponse.getClientId())
      .then()
      .statusCode(HttpStatus.OK.value());

    clientJson =
        ClientJsonStringBuilder.builder().scopes("openid").grantTypes("client_credentials").build();

    RestAssured.given()
      .body(clientJson)
      .contentType(APPLICATION_JSON_VALUE)
      .when()
      .post(registerUrl)
      .then()
      .log()
      .all()
      .statusCode(HttpStatus.BAD_REQUEST.value());

    managementService.deleteClientByClientId(registerResponse.getClientId());

    assertFalse(accessTokenRepo
      .findByTokenValue(tokenUtils.sha256(rotatedRatClient.getRegistrationAccessToken()))
      .isPresent());
  }

  @Test
  void testRedeemClientFlow() {

    // 1. Register a client
    String clientJson =
        ClientJsonStringBuilder.builder().scopes("openid").grantTypes("authorization_code").build();

    RegisteredClientDTO registerResponse = RestAssured.given()
      .body(clientJson)
      .contentType(APPLICATION_JSON_VALUE)
      .when()
      .post(registerUrl)
      .then()
      .log()
      .all()
      .statusCode(HttpStatus.CREATED.value())
      .extract()
      .body()
      .as(RegisteredClientDTO.class);

    assertThat(registerResponse.getRegistrationAccessToken(), notNullValue());
    assertThat(registerResponse.getScope(), not(empty()));

    // 2. Get an access token for the 'test' account
    String testAt = TestUtils.passwordTokenGetter()
      .username("test")
      .password("password")
      .port(iamPort)
      .getAccessToken();

    // 3. Check that test account doesn't own any client
    RestAssured.given()
      .auth()
      .oauth2(testAt)
      .log()
      .all()
      .when()
      .get(ownedClientsUrl)
      .then()
      .log()
      .all()
      .statusCode(HttpStatus.OK.value())
      .body("totalResults", equalTo(0));

    // 4. Redeem just-registered client
    RestAssured.given()
      .contentType(MediaType.APPLICATION_JSON_VALUE)
      .body(registerResponse.getRegistrationAccessToken())
      .auth()
      .oauth2(testAt)
      .log()
      .all()
      .when()
      .post(registerUrl + "/" + registerResponse.getClientId() + "/redeem")
      .then()
      .log()
      .all()
      .statusCode(HttpStatus.OK.value());

    // 5. Test account own registered client
    RestAssured.given()
      .auth()
      .oauth2(testAt)
      .log()
      .all()
      .when()
      .get(ownedClientsUrl)
      .then()
      .log()
      .all()
      .statusCode(HttpStatus.OK.value())
      .body("totalResults", equalTo(1))
      .body("Resources[0].client_id", equalTo(registerResponse.getClientId()));

    clientJson =
        ClientJsonStringBuilder.builder().scopes("openid").grantTypes("client_credentials").build();

    RestAssured.given()
      .body(clientJson)
      .contentType(APPLICATION_JSON_VALUE)
      .when()
      .post(registerUrl)
      .then()
      .log()
      .all()
      .statusCode(HttpStatus.BAD_REQUEST.value());

    managementService.deleteClientByClientId(registerResponse.getClientId());
  }

}
