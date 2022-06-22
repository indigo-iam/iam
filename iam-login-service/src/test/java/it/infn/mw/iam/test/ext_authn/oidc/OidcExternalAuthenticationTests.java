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
package it.infn.mw.iam.test.ext_authn.oidc;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.UnsupportedEncodingException;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;
import it.infn.mw.iam.test.util.oidc.CodeRequestHolder;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;

@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, OidcTestConfig.class},
    webEnvironment = WebEnvironment.RANDOM_PORT)
public class OidcExternalAuthenticationTests extends OidcExternalAuthenticationTestsSupport {

  @Before
  public void setup() {
    MockRestTemplateFactory tf = (MockRestTemplateFactory) restTemplateFactory;
    tf.resetTemplate();
  }
  
  @Test
  public void testOidcUnregisteredUserRedirectedToRegisterPage() throws JOSEException,
      JsonProcessingException, RestClientException, UnsupportedEncodingException {

    RestTemplate rt = noRedirectRestTemplate();
    ResponseEntity<String> response = rt.getForEntity(openidConnectLoginURL(), String.class);

    checkAuthorizationEndpointRedirect(response);
    HttpHeaders requestHeaders = new HttpHeaders();

    String sessionCookie = extractSessionCookie(response);
    requestHeaders.add("Cookie", sessionCookie);

    CodeRequestHolder ru = buildCodeRequest(sessionCookie, response);

    String tokenResponse = mockOidcProvider.prepareTokenResponse(OidcTestConfig.TEST_OIDC_CLIENT_ID,
        "unregistered", ru.nonce);

    prepareSuccessResponse(tokenResponse);

    response = rt.postForEntity(openidConnectLoginURL(), ru.requestEntity, String.class);
    verifyMockServerCalls();

    assertThat(response.getStatusCode(), equalTo(HttpStatus.FOUND));
    assertNotNull(response.getHeaders().getLocation());

    UriComponents locationUri =
        UriComponentsBuilder.fromUri(response.getHeaders().getLocation()).build();

    assertThat(locationUri.getPath(), equalTo("/"));

    HttpEntity<ExternalAuthenticationRegistrationInfo> requestEntity =
        new HttpEntity<ExternalAuthenticationRegistrationInfo>(null, requestHeaders);

    ResponseEntity<ExternalAuthenticationRegistrationInfo> res = rt.exchange(authnInfoURL(),
        HttpMethod.GET, requestEntity, ExternalAuthenticationRegistrationInfo.class);

    assertThat(res.getStatusCode(), equalTo(HttpStatus.OK));
    ExternalAuthenticationRegistrationInfo info = res.getBody();
    assertNotNull(info);

    assertThat(info.getType(), equalTo(ExternalAuthenticationType.OIDC));
    assertThat(info.getSubject(), equalTo("unregistered"));
    assertThat(info.getIssuer(), equalTo(OidcTestConfig.TEST_OIDC_ISSUER));
    assertNull(info.getGivenName());
    assertNull(info.getFamilyName());
    assertNull(info.getEmail());

  }

  @Test
  public void testOidcRegisteredUserRedirectToHome() throws JOSEException, JsonProcessingException,
      RestClientException, UnsupportedEncodingException {

    RestTemplate rt = noRedirectRestTemplate();
    ResponseEntity<String> response = rt.getForEntity(openidConnectLoginURL(), String.class);

    checkAuthorizationEndpointRedirect(response);
    HttpHeaders requestHeaders = new HttpHeaders();

    String sessionCookie = extractSessionCookie(response);
    requestHeaders.add("Cookie", sessionCookie);

    CodeRequestHolder ru = buildCodeRequest(sessionCookie, response);

    String tokenResponse = mockOidcProvider.prepareTokenResponse(OidcTestConfig.TEST_OIDC_CLIENT_ID,
        "test-user", ru.nonce);

    prepareSuccessResponse(tokenResponse);

    response = rt.postForEntity(openidConnectLoginURL(), ru.requestEntity, String.class);
    verifyMockServerCalls();

    assertThat(response.getStatusCode(), equalTo(HttpStatus.FOUND));
    assertNotNull(response.getHeaders().getLocation());

    assertThat(response.getHeaders().getLocation().toString(), equalTo(landingPageURL()));

  }

  @Test
  public void testExternalAuthenticationErrorHandling() throws JsonProcessingException {

    RestTemplate rt = noRedirectRestTemplate();
    ResponseEntity<String> response = rt.getForEntity(openidConnectLoginURL(), String.class);

    checkAuthorizationEndpointRedirect(response);
    HttpHeaders requestHeaders = new HttpHeaders();

    String sessionCookie = extractSessionCookie(response);
    requestHeaders.add("Cookie", sessionCookie);

    CodeRequestHolder ru = buildCodeRequest(sessionCookie, response);

    String errorResponse =
        mockOidcProvider.prepareErrorResponse("invalid_request", "malformed request");

    prepareErrorResponse(errorResponse);
    response = rt.postForEntity(openidConnectLoginURL(), ru.requestEntity, String.class);
    verifyMockServerCalls();

    assertThat(response.getStatusCode(), equalTo(HttpStatus.FOUND));
    assertNotNull(response.getHeaders().getLocation());
    assertThat(response.getHeaders().getLocation().toString(), Matchers.startsWith(loginPageURL()));
  }

}
