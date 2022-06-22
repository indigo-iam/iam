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

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpStatus;

import io.restassured.response.ValidatableResponse;
import it.infn.mw.iam.api.scim.model.ScimUser;

public class ScimRestUtils {

  public static final String SCIM_CONTENT_TYPE = "application/scim+json";

  private final String accessToken;

  private ScimRestUtils(String accessToken) {

    this.accessToken = accessToken;
  }

  public static ScimRestUtils getInstance(String accessToken) {

    return new ScimRestUtils(accessToken);
  }

  public <B> ValidatableResponse doPost(String location, B content) {

    return doPost(location, content, HttpStatus.CREATED);
  }

  public <B> ValidatableResponse doPost(String location, B content, HttpStatus expectedError) {

    return given().port(8080)
      .auth()
      .preemptive()
      .oauth2(accessToken)
      .contentType(SCIM_CONTENT_TYPE)
      .body(content)
      .log()
      .all(true)
      .when()
      .post(location)
      .then()
      .log()
      .all(true)
      .statusCode(expectedError.value())
      .contentType(SCIM_CONTENT_TYPE);
  }

  public <B> ValidatableResponse doPut(String location, B content) {

    return doPut(location, content, HttpStatus.OK);
  }

  public <B> ValidatableResponse doPut(String location, B content,
      HttpStatus expectedResponseCode) {

    /** @formatter:off */
    return given().port(8080)
      .auth()
      .preemptive()
      .oauth2(accessToken)
      .contentType(SCIM_CONTENT_TYPE)
      .body(content)
      .log()
      .all(true)
      .when()
      .put(location)
      .then()
      .log()
      .all(true)
      .statusCode(expectedResponseCode.value());
    /** @formatter:on */
  }

  public void doDelete(String location, HttpStatus statusExpected) {

    /** @formatter:off */
    given().port(8080)
      .auth()
      .preemptive()
      .oauth2(accessToken)
      .when()
      .delete(location)
      .then()
      .log().all(true)
      .statusCode(statusExpected.value());
    /** @formatter:on */
  }

  public void doDelete(String location) {

    doDelete(location, HttpStatus.NO_CONTENT);
  }

  public ValidatableResponse doGet(String location) {

    return doGet(location, HttpStatus.OK);
  }

  public ValidatableResponse doGet(String location, HttpStatus expectedStatus) {

    /** @formatter:off */
    return given().port(8080)
      .auth()
      .preemptive()
      .oauth2(accessToken)
      .contentType(SCIM_CONTENT_TYPE)
      .when()
      .get(location)
      .then()
      .log()
      .all(true)
      .statusCode(expectedStatus.value());
    /** @formatter:on */
  }

  public <T> ValidatableResponse doPatch(String location, T content, HttpStatus expectedStatus) {

    /** @formatter:off */
    return given().port(8080)
      .auth()
      .preemptive()
      .oauth2(accessToken)
      .contentType(SCIM_CONTENT_TYPE)
      .body(content)
      .log()
      .all(true)
      .when()
      .patch(location)
      .then()
      .log()
      .all(true)
      .statusCode(expectedStatus.value());
    /** @formatter:on */
  }

  public <T> ValidatableResponse doPatch(String location, T content) {

    return doPatch(location, content, HttpStatus.NO_CONTENT);
  }

  public void deleteUsers(ScimUser... scimUsers) {
    for (ScimUser u : scimUsers) {
      doDelete(u.getMeta().getLocation());
    }
  }

  public List<ScimUser> createUsers(String location, ScimUser... scimUsers) {

    List<ScimUser> createdUsers = new ArrayList<ScimUser>();
    for (ScimUser u : scimUsers) {
      createdUsers.add(doPost(location, u).extract().as(ScimUser.class));
    }
    return createdUsers;
  }
}
