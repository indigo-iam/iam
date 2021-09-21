/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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
package it.infn.mw.iam.test.oauth;

import static org.hamcrest.CoreMatchers.containsString;

import java.io.IOException;
import java.text.ParseException;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.restassured.RestAssured;
import com.jayway.restassured.response.ValidatableResponse;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.TestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class})
@WebIntegrationTest(randomPort = true)
@Transactional
public class IamClientApprovalTests {

  @Value("${local.server.port}")
  private Integer iamPort;

  @Autowired
  ObjectMapper mapper;

  public static final String TEST_CLIENT_ID = "client";
  public static final String TEST_CLIENT_REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  public static final String LOCALHOST_URL_TEMPLATE = "http://localhost:%d";

  public static final String RESPONSE_TYPE_CODE = "code";

  public static final String SCOPE = "openid profile email address phone offline_access";

  public static final String TEST_USER_ID = "test";
  public static final String TEST_USER_PASSWORD = "password";

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
  public void testApprove() throws JsonProcessingException, IOException, ParseException {

 // @formatter:off
    ValidatableResponse resp1 = RestAssured.given()
      .formParam("username", "test")
      .formParam("password", "password")
      .formParam("submit", "Login")
      .redirects().follow(false)
    .when()
      .post(loginUrl)
    .then()
      .statusCode(HttpStatus.FOUND.value());
    // @formatter:on

    // @formatter:off
    RestAssured.given()
      .cookie(resp1.extract().detailedCookie("JSESSIONID"))
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
      .body(containsString("IAM client consent page"));
    // @formatter:on

  }
}
