package it.infn.mw.iam.test.oauth;

import java.util.Arrays;
import java.util.Set;

import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.discovery.web.DiscoveryEndpoint;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.google.common.collect.Sets;
import com.jayway.restassured.RestAssured;
import com.jayway.restassured.response.Response;

import it.infn.mw.iam.IamLoginService;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class DiscoveryEndpointTests {

  @Value("${server.port}")
  private Integer iamPort;

  private String endpoint = DiscoveryEndpoint.OPENID_CONFIGURATION_URL;

  private Set<String> iamSupportedGrants = Sets.newLinkedHashSet(Arrays.asList("authorization_code",
      "implicit", "refresh_token", "client_credentials", "password",
      "urn:ietf:params:oauth:grant-type:jwt-bearer", "urn:ietf:params:oauth:grant_type:redelegate",
      "urn:ietf:params:oauth:grant-type:token-exchange"));

  private static final String IAM_ORGANISATION_NAME_CLAIM = "organisation_name";
  private static final String IAM_GROUPS_CLAIM = "groups";
  private static final String IAM_EXTERNAL_AUTHN_CLAIM = "external_authn";

  @Test
  public void testGrantTypesSupported() {

    // @formatter:off
    Response response =RestAssured.given()
      .port(iamPort)
    .when()
      .post(endpoint)
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("grant_types_supported", Matchers.notNullValue())
      .extract()
        .response()
      ;
    // @formatter:on

    Set<String> grantsSet = Sets.newLinkedHashSet(response.getBody().path("grant_types_supported"));
    Assert.assertThat(Sets.difference(iamSupportedGrants, grantsSet), Matchers.empty());
  }

  @Test
  public void testSupportedClaims() {
    // @formatter:off
    Response response =RestAssured.given()
      .port(iamPort)
    .when()
      .post(endpoint)
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("claims_supported", Matchers.notNullValue())
      .extract()
        .response()
     ;
    // @formatter:on
    Set<String> claimsSet = Sets.newLinkedHashSet(response.getBody().path("claims_supported"));
    Assert.assertThat(claimsSet, Matchers.hasItem(IAM_ORGANISATION_NAME_CLAIM));
    Assert.assertThat(claimsSet, Matchers.hasItem(IAM_GROUPS_CLAIM));
    Assert.assertThat(claimsSet, Matchers.hasItem(IAM_EXTERNAL_AUTHN_CLAIM));
  }
}
