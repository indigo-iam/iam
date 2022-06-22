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

import static it.infn.mw.iam.test.ext_authn.oidc.OidcTestConfig.TEST_OIDC_AUTHORIZATION_ENDPOINT_URI;
import static it.infn.mw.iam.test.ext_authn.oidc.OidcTestConfig.TEST_OIDC_TOKEN_ENDPOINT_URI;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertNotNull;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;

import org.junit.Assert;
import org.mitre.openid.connect.client.UserInfoFetcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.test.web.client.response.MockRestResponseCreators;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.test.rcauth.RCAuthTestSupport;
import it.infn.mw.iam.test.util.oidc.CodeRequestHolder;
import it.infn.mw.iam.test.util.oidc.MockOIDCProvider;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;

public class OidcExternalAuthenticationTestsSupport {

  @Value("${local.server.port}")
  protected Integer iamPort;

  @Autowired
  protected RestTemplateFactory restTemplateFactory;

  @Autowired
  protected MockOIDCProvider mockOidcProvider;

  @Autowired
  protected UserInfoFetcher mockUserInfoFetcher;


  protected String baseIamURL() {
    return "http://localhost:" + iamPort;
  }

  protected String openidConnectLoginURL() {
    return baseIamURL() + "/openid_connect_login";
  }

  protected String authnInfoURL() {
    return baseIamURL() + "/iam/authn-info";
  }

  protected String landingPageURL() {
    return baseIamURL() + "/dashboard";
  }

  protected String loginPageURL() {
    return baseIamURL() + "/login";
  }

  protected ClientHttpRequestFactory noRedirectHttpRequestFactory() {

    SimpleClientHttpRequestFactory rf = new SimpleClientHttpRequestFactory() {
      protected void prepareConnection(java.net.HttpURLConnection connection, String httpMethod)
          throws java.io.IOException {
        super.prepareConnection(connection, httpMethod);
        connection.setInstanceFollowRedirects(false);
      }
    };

    return rf;
  }

  protected RestTemplate noRedirectRestTemplate() {
    return new RestTemplate(noRedirectHttpRequestFactory());
  }

  protected void checkAuthorizationEndpointRedirect(ResponseEntity<String> response) {
    assertThat(response.getStatusCode(), equalTo(HttpStatus.FOUND));
    assertNotNull(response.getHeaders().getLocation());

    assertThat(response.getHeaders().getLocation().toString(),
        startsWith(TEST_OIDC_AUTHORIZATION_ENDPOINT_URI));

    UriComponents locationUri =
        UriComponentsBuilder.fromUri(response.getHeaders().getLocation()).build();

    Assert.assertFalse(locationUri.getQueryParams().get("state").isEmpty());
    Assert.assertFalse(locationUri.getQueryParams().get("nonce").isEmpty());
    Assert.assertFalse(response.getHeaders().get("Set-Cookie").isEmpty());

  }

  protected String extractSessionCookie(ResponseEntity<String> response) {

    return response.getHeaders().get("Set-Cookie").get(0);

  }

  protected CodeRequestHolder buildCodeRequest(String sessionCookie, ResponseEntity<String> response) {

    CodeRequestHolder result = new CodeRequestHolder();

    HttpHeaders requestHeaders = new HttpHeaders();
    UriComponents locationUri =
        UriComponentsBuilder.fromUri(response.getHeaders().getLocation()).build();

    String state = locationUri.getQueryParams().get("state").get(0);
    String nonce = locationUri.getQueryParams().get("nonce").get(0);

    requestHeaders.add("Cookie", sessionCookie);
    requestHeaders.setContentType(RCAuthTestSupport.APPLICATION_FORM_URLENCODED_UTF8);


    MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
    params.add("state", state);
    params.add("code", "1234");

    HttpEntity<MultiValueMap<String, String>> requestEntity =
        new HttpEntity<MultiValueMap<String, String>>(params, requestHeaders);

    result.nonce = nonce;
    result.requestEntity = requestEntity;
    return result;
  }

  protected void prepareSuccessResponse(String tokenResponse) {
    MockRestTemplateFactory tf = (MockRestTemplateFactory) restTemplateFactory;
    tf.getMockServer()
      .expect(requestTo(TEST_OIDC_TOKEN_ENDPOINT_URI))
      .andExpect(method(HttpMethod.POST))
      .andExpect(content().contentType(RCAuthTestSupport.APPLICATION_FORM_URLENCODED_UTF8))
      .andRespond(MockRestResponseCreators.withSuccess(tokenResponse, MediaType.APPLICATION_JSON));
  }

  protected void prepareErrorResponse(String errorResponse) {
    MockRestTemplateFactory tf = (MockRestTemplateFactory) restTemplateFactory;
    tf.getMockServer()
      .expect(requestTo(TEST_OIDC_TOKEN_ENDPOINT_URI))
      .andExpect(method(HttpMethod.POST))
      .andExpect(content().contentType(RCAuthTestSupport.APPLICATION_FORM_URLENCODED_UTF8))
      .andRespond(MockRestResponseCreators.withBadRequest()
        .contentType(MediaType.APPLICATION_JSON)
        .body(errorResponse));
  }

  protected void verifyMockServerCalls() {
    MockRestTemplateFactory tf = (MockRestTemplateFactory) restTemplateFactory;
    tf.getMockServer().verify();
    tf.resetTemplate();
  }

}
