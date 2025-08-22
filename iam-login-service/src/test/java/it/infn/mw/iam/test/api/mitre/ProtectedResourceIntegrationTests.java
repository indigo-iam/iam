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

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.openid.connect.web.ProtectedResourceRegistrationEndpoint;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;

import io.restassured.RestAssured;
import io.restassured.response.ValidatableResponse;
import it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.ClientJsonStringBuilder;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
public class ProtectedResourceIntegrationTests {

  @Value("${local.server.port}")
  private Integer iamPort;

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

  @Test
  public void protectedResourceLifeCycle() throws Exception {

    final String NAME = "protected-resource";
    String clientJson = ClientJsonStringBuilder.builder().name(NAME).scopes("openid").build();

    // create protected resource
    doCreateProtectedResource(clientJson).statusCode(HttpStatus.METHOD_NOT_ALLOWED.value());

  }
}