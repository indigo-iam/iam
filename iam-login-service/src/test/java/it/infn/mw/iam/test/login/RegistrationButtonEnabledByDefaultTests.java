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

import static org.hamcrest.CoreMatchers.containsString;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;

import io.restassured.RestAssured;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;


@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.RANDOM_PORT)
public class RegistrationButtonEnabledByDefaultTests {
  @Value("${local.server.port}")
  private Integer serverPort;

  @BeforeClass
  public static void init() {
    TestUtils.initRestAssured();
  }

  @Test
  public void registrationButtonIsShown() {
    RestAssured.given()
      .port(serverPort)
      .log()
      .all(true)
      .when()
      .get("/login")
      .then()
      .log()
      .all()
      .statusCode(200)
      .body(containsString("Apply for an account"));
  }
}
