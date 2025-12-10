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
package it.infn.mw.iam.test.login;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.TestPropertySource;

import io.restassured.RestAssured;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@IamRandomPortIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"iam.registration.registration-button-text=Another value"})
class RegistrationButtonTextTests {

  @Value("${local.server.port}")
  private Integer serverPort;

  private final String REGISTRATIONBUTTONTEXT = "Another value";

  @BeforeAll
  static void init() {
    TestUtils.initRestAssured();
  }

  @Test
  void registrationButtonSuccess() {
    RestAssured.given().port(serverPort).when().get("/login").then().statusCode(200);
  }

  @Test
  void registrationButtonIsShown() {
    String responseBody = RestAssured.given()
      .port(serverPort)
      .when()
      .get("/login")
      .then()
      .statusCode(200)
      .extract()
      .body()
      .asString();

    int amountOccurences = 0;
    int index = 0;

    while (responseBody.indexOf(REGISTRATIONBUTTONTEXT, index) != -1) {
      amountOccurences++;
      index = responseBody.indexOf(REGISTRATIONBUTTONTEXT, index) + 1;

    }

    assertEquals(2, amountOccurences);
  }

  @Test
  void registrationButtonText() {

    String responseBody = RestAssured.given()
      .port(serverPort)
      .when()
      .get("/login")
      .then()
      .statusCode(200)
      .extract()
      .body()
      .asString();

    assertTrue(responseBody.contains(REGISTRATIONBUTTONTEXT));

  }

}


