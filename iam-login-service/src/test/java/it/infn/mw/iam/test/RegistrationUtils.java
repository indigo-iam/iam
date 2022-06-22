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
package it.infn.mw.iam.test;

import static io.restassured.RestAssured.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import org.hamcrest.Matchers;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.restassured.RestAssured;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.registration.RegistrationRequestDto;

public class RegistrationUtils {

  final MockMvc mvc;
  final ObjectMapper mapper;

  public RegistrationUtils(MockMvc mvc, ObjectMapper mapper) {
    this.mvc = mvc;
    this.mapper = mapper;
  }

  public RegistrationRequestDto createRegistrationRequest(String username) throws Exception {

    String email = username + "@example.org";
    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setNotes("Some short notes...");

    String responseJson =
    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(MockMvcResultMatchers.status().isOk())
      .andReturn().getResponse().getContentAsString();

    request = mapper.readValue(responseJson, RegistrationRequestDto.class);
    
    return request;
  }
  
  public void confirmRegistrationRequest(String confirmationKey, int port) {

    // @formatter:off
    given()
      .port(port)
      .pathParam("token", confirmationKey)
    .when()
      .get("/registration/confirm/{token}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("status", Matchers.equalTo(IamRegistrationRequestStatus.CONFIRMED.name()))
    ;
    // @formatter:on
  }

  public static RegistrationRequestDto approveRequest(String uuid, int port) {
    return requestDecision(uuid, IamRegistrationRequestStatus.APPROVED, port);
  }

  public static RegistrationRequestDto rejectRequest(String uuid, int port) {
    return requestDecision(uuid, IamRegistrationRequestStatus.REJECTED, port);
  }

  public static void changePassword(String resetKey, String newPassword, int port) {
    // @formatter:off
    RestAssured.given()
      .port(port)
      .param("token", resetKey)
      .param("password", newPassword)
    .when()
      .post("/iam/password-reset")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
    ;
    // @formatter:on
  }

  private static RegistrationRequestDto requestDecision(String uuid,
      IamRegistrationRequestStatus decision, int port) {
    String accessToken =
        TestUtils.getAccessToken("registration-client", "secret", "registration:write");

    // @formatter:off
    RegistrationRequestDto req =
    given()
      .port(port)
      .auth()
        .preemptive()
        .oauth2(accessToken)
      .pathParam("uuid", uuid)
      .pathParam("decision", decision)
    .when()
      .post("/registration/{uuid}/{decision}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .extract().as(RegistrationRequestDto.class);
    // @formatter:on

    return req;
  }

}
