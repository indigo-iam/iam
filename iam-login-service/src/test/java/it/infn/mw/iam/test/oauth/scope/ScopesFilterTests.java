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
package it.infn.mw.iam.test.oauth.scope;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.empty;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.util.List;

import javax.persistence.EntityManager;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.internal.util.collections.Sets;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.fasterxml.jackson.core.JsonProcessingException;

import freemarker.core.ParseException;
import io.restassured.RestAssured;
import io.restassured.response.ValidatableResponse;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopePolicyPDP;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@RunWith(SpringJUnit4ClassRunner.class)
@IamRandomPortIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.RANDOM_PORT)
public class ScopesFilterTests extends ScopePolicyTestUtils {

  public static final String SESSION = "JSESSIONID";
  public static final String TEST_CLIENT_ID = "client";
  public static final String RESPONSE_TYPE_CODE = "code";
  public static final String EMAIL = "email";
  public static final String SCOPE = "openid email";
  public static final String LOCALHOST_URL_TEMPLATE = "http://localhost:%d";
  public static final String TEST_CLIENT_REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  @Value("${local.server.port}")
  private Integer iamPort;

  @Autowired
  IamScopePolicyRepository policyScopeRepo;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  EntityManager em;

  @Autowired
  ScopePolicyPDP pdp;

  IamAccount findTestAccount() {
    return accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found!"));
  }

  private String loginUrl;
  private String authorizeUrl;

  @BeforeClass
  public static void init() {
    TestUtils.initRestAssured();
  }

  @Before
  public void setup() {
    RestAssured.port = iamPort;
    loginUrl = String.format(LOCALHOST_URL_TEMPLATE + "/login", iamPort);
    authorizeUrl = String.format(LOCALHOST_URL_TEMPLATE + "/authorize", iamPort);
  }

  @Test
  public void testConsentPageReturnsFilteredScopes()
      throws JsonProcessingException, IOException, ParseException {

    IamAccount testAccount = findTestAccount();

    IamScopePolicy up = initDenyScopePolicy();

    up.linkAccount(testAccount);
    up.setScopes(Sets.newSet(EMAIL));

    up = policyScopeRepo.save(up);
    accountRepo.save(testAccount);

    try {
      List<IamScopePolicy> accountPolicies = policyScopeRepo.findByAccount(testAccount);
      assertThat(accountPolicies, not(empty()));

      testAccount = findTestAccount();
      assertThat(testAccount.getScopePolicies(), hasItem(up));

    // @formatter:off
    ValidatableResponse authzResponse = RestAssured.given()
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .redirects().follow(false)
    .when()
      .get(authorizeUrl)
    .then()
      .log().all()
      .statusCode(HttpStatus.FOUND.value());
    // @formatter:on

    // @formatter:off
    ValidatableResponse loginResponse = RestAssured.given()
      .cookie(authzResponse.extract().detailedCookie(SESSION))
      .formParam("username", "test")
      .formParam("password", "password")
      .formParam("submit", "Login")
      .redirects().follow(false)
    .when()
      .post(loginUrl)
    .then()
      .log().all()
      .statusCode(HttpStatus.FOUND.value());
    // @formatter:on

    // @formatter:off
    String responseBody = RestAssured.given()
      .cookie(loginResponse.extract().detailedCookie(SESSION))
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .redirects().follow(false)
    .when()
      .get(authorizeUrl)
    .then()
      .log().all()
      .statusCode(HttpStatus.OK.value())
      .extract().body().asString();
    // @formatter:on

      assertThat(responseBody, not(containsString("scope_email")));
    } finally {
      policyScopeRepo.delete(up);
    }

  }

}
