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
package it.infn.mw.iam.test.registration;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.transaction.annotation.Transactional;

import io.restassured.RestAssured;
import it.infn.mw.iam.test.TestUtils;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@Transactional
class RegistrationApiControllerTests {

  @Value("${local.server.port}")
  private Integer iamPort;

  @BeforeAll
  static void init() {
    TestUtils.initRestAssured();
  }

  @Test
  void testTokenIsNotReflectedInErrorPage() {

    String response = RestAssured.given()
      .port(iamPort)
      .contentType("application/x-www-form-urlencoded")
      .formParam("token", "<img src=x onerror=alert(1)>")
      .when()
      .post("/registration/verify")
      .then()
      .statusCode(200)
      .extract()
      .asString();

    assertThat(response).doesNotContain("<img src=x onerror=alert(1)>")
      .contains("No registration request found");
  }

  @Test
  void testTokenIsEscapedInConfirmPage() {

    String payload = "\"><img src=x onerror=alert(1)>";

    String response = RestAssured.given()
      .port(iamPort)
      .pathParam("token", payload)
      .when()
      .get("/registration/verify/{token}")
      .then()
      .statusCode(200)
      .extract()
      .asString();

    assertThat(response).doesNotContain("<img src=x onerror=alert(1)>");
  }
}
