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
package it.infn.mw.iam.test.ext_authn.saml;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;

import io.restassured.RestAssured;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@IamRandomPortIntegrationTest
@TestPropertySource(properties = {"IAM_SAML_WAYF_LOGIN_BUTTON_VISIBLE=false",
  "saml.login-shortcuts[0].name=test",
  "saml.login-shortcuts[0].entityId=https://idptestbed/idp/shibboleth",
  "saml.login-shortcuts[0].loginButton.text=Sign in with Test IDP"})
class LoginShortcutsWithoutWayfTests {

  @Value("${local.server.port}")
  private Integer serverPort;

  @BeforeAll
  static void init() {
    TestUtils.initRestAssured();
  }

  @Test
  void loginPageShowsDirectShortcutWithoutWayfButton() {

    RestAssured.given()
      .port(serverPort)
      .when()
      .get("/login")
      .then()
      .statusCode(200)
      .body(containsString("id=\"saml-login-test\""))
      .body(containsString(
          "href=\"/saml/login?idp=https://idptestbed/idp/shibboleth\""))
      .body(not(containsString("id=\"saml-login\"")));
  }
}
