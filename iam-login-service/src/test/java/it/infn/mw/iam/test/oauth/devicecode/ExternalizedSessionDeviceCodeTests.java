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
package it.infn.mw.iam.test.oauth.devicecode;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.restassured.RestAssured;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.redis.RedisContainer;



@Testcontainers
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = "spring.session.store-type=redis")
@Disabled
public class ExternalizedSessionDeviceCodeTests implements DeviceCodeTestsConstants {


  @LocalServerPort
  private Integer iamPort;

  @Autowired
  ObjectMapper mapper;

  @Container
  private static final RedisContainer REDIS = new RedisContainer();

  @DynamicPropertySource
  static void redisProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.redis.port", REDIS::getFirstMappedPort);

  }

  @BeforeEach
  public void setup() {
    TestUtils.initRestAssured();
    RestAssured.port = iamPort;

  }

  @Test
  public void ensureRedisRunning() {
    assertTrue(REDIS.isRunning());
  }

  @Test
  public void testDeviceCodeWithExternalizedSession()
      throws JsonMappingException, JsonProcessingException {
    // @formatter:off
    final String response = 
        RestAssured
        .given()
          .auth()
            .basic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET)
          .contentType(APPLICATION_FORM_URLENCODED_VALUE)
          .param("client_id", DEVICE_CODE_CLIENT_ID)
          .queryParam("scope", "openid profile")
          .redirects()
            .follow(false)
         .when()
           .post(DEVICE_CODE_ENDPOINT)
         .then()
           .statusCode(HttpStatus.OK.value())
           .extract()
             .response().asString();
    // @formatter:on
    JsonNode responseJson = mapper.readTree(response);

    // String userCode = responseJson.get("user_code").asText();
    String deviceCode = responseJson.get("device_code").asText();

    // @formatter:off
    RestAssured
    .given()
      .auth()
        .basic(DEVICE_CODE_CLIENT_ID, DEVICE_CODE_CLIENT_SECRET)
      .contentType(APPLICATION_FORM_URLENCODED_VALUE)
      .param("grant_type", DEVICE_CODE_GRANT_TYPE)
      .param("device_code", deviceCode)
     .when()
       .post(TOKEN_ENDPOINT)
     .then()
       .statusCode(HttpStatus.BAD_REQUEST.value())
       .body("error", is("authorization_pending"));
    // @formatter:on


  }
}
