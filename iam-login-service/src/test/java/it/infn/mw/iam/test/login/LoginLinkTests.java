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

import static org.junit.Assert.assertTrue;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;

import io.restassured.RestAssured;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.LoginLink;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
@SpringBootTest(classes = { IamLoginService.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
public class LoginLinkTests {

  @Value("${local.server.port}")
  private Integer serverPort;

  @Autowired
  private IamProperties iamProperties;

  @BeforeClass
  public static void init() {
    TestUtils.initRestAssured();
  }

  @Test
  public void testPrivacyPolicyLink() {
    String oldResponseBody = RestAssured.given().port(serverPort).when().get("/login").then().statusCode(200)
        .extract()
        .body()
        .asString();
    assertTrue(!oldResponseBody.contains("Privacy policy"));

    LoginLink privacyPolicy = new LoginLink();
    privacyPolicy.setUrl("https://ëxample.com/");
    iamProperties.setPrivacyPolicy(privacyPolicy);
    String responseBody = RestAssured.given().port(serverPort).when().get("/login").then().statusCode(200)
        .extract()
        .body()
        .asString();
    assertTrue(responseBody.contains("Privacy policy"));

  }

  @Test
  public void testSupportLink() {
    String oldResponseBody = RestAssured.given().port(serverPort).when().get("/login").then().statusCode(200)
        .extract()
        .body()
        .asString();
    assertTrue(!oldResponseBody.contains("Support"));

    LoginLink support = new LoginLink();
    support.setUrl("https://ëxample.com/");
    iamProperties.setSupport(support);
    String responseBody = RestAssured.given().port(serverPort).when().get("/login").then().statusCode(200)
        .extract()
        .body()
        .asString();
    assertTrue(responseBody.contains("Support"));

  }

}
