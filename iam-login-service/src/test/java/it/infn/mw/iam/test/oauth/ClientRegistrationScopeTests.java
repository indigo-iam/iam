package it.infn.mw.iam.test.oauth;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.Set;

import javax.transaction.Transactional;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.RegisteredClientFields;
import org.mitre.openid.connect.ClientDetailsEntityJsonProcessor;
import org.mitre.util.JsonUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Joiner;
import com.google.common.collect.Sets;
import com.google.gson.JsonObject;
import com.jayway.restassured.RestAssured;
import com.jayway.restassured.http.ContentType;
import com.jayway.restassured.response.Response;

import it.infn.mw.iam.IamLoginService;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
@Transactional
public class ClientRegistrationScopeTests {

  @Value("${server.port}")
  private Integer iamPort;

  @Test
  public void testCreateClientWithRegistrationReservedScopes()
      throws JsonProcessingException, IOException {

    String clientName = "test_client";
    Set<String> scopes =
        Sets.newHashSet("registration:read", "registration:write", "scim:read", "scim:write");

    String jsonInString = buildClientJsonString(clientName, scopes);

    // @formatter:off
    Response response = RestAssured.given()
      .port(iamPort)
      .contentType(ContentType.JSON)
      .body(jsonInString)
      .log()
        .all(true)
    .when()
      .post("/register")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.CREATED.value())
      .contentType(ContentType.JSON)
      .extract()
        .response()
    ;
    // @formatter:on

    String str = response.asString();
    ClientDetailsEntity saved = ClientDetailsEntityJsonProcessor.parse(str);

    assertNotNull(saved);
    for (String reservedScope : scopes) {
      Assert.assertFalse(saved.getScope().contains(reservedScope));
    }


  }

  @Test
  public void testGetTokenWithScimReservedScopesFailure()
      throws JsonProcessingException, IOException {

    String clientName = "test_client";
    Set<String> scopes =
        Sets.newHashSet("scim:read", "scim:write", "registration:read", "registration:write");

    String jsonInString = buildClientJsonString(clientName, scopes);

    // @formatter:off
    Response response = RestAssured.given()
      .port(iamPort)
      .contentType(ContentType.JSON)
      .body(jsonInString)
      .log()
        .all(true)
    .when()
      .post("/register")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.CREATED.value())
      .contentType(ContentType.JSON)
      .extract()
        .response()
    ;
    // @formatter:on

    String str = response.asString();
    ClientDetailsEntity saved = ClientDetailsEntityJsonProcessor.parse(str);

    Assert.assertNotNull(saved);

    // @formatter:off
    RestAssured.given()
      .port(iamPort)
      .param("grant_type", "client_credentials")
      .param("client_id", saved.getClientId())
      .param("client_secret", saved.getClientSecret())
      .param("scope", setToString(scopes))
    .when()
      .post("/token")
    .then()
      .log()
        .all(true)
      .statusCode(HttpStatus.BAD_REQUEST.value())
    ;
    // @formatter:on
  }


  private String buildClientJsonString(String clientName, Set<String> scopes) {

    JsonObject json = new JsonObject();
    json.addProperty(RegisteredClientFields.CLIENT_NAME, clientName);
    json.addProperty(RegisteredClientFields.SCOPE, setToString(scopes));
    json.add(RegisteredClientFields.REDIRECT_URIS,
        JsonUtils.getAsArray(Sets.newHashSet("http://localhost:9090")));
    json.add(RegisteredClientFields.GRANT_TYPES,
        JsonUtils.getAsArray(Sets.newHashSet("client_credentials")));
    json.add(RegisteredClientFields.RESPONSE_TYPES, JsonUtils.getAsArray(Sets.newHashSet(), true));
    json.add(RegisteredClientFields.CONTACTS,
        JsonUtils.getAsArray(Sets.newHashSet("test@iam.test")));
    json.add(RegisteredClientFields.CLAIMS_REDIRECT_URIS,
        JsonUtils.getAsArray(Sets.newHashSet(), true));
    json.add(RegisteredClientFields.REQUEST_URIS, JsonUtils.getAsArray(Sets.newHashSet(), true));

    return json.toString();
  }


  private String setToString(Set<String> scopes) {

    Joiner joiner = Joiner.on(RegisteredClientFields.SCOPE_SEPARATOR);
    return joiner.join(scopes);
  }

}
