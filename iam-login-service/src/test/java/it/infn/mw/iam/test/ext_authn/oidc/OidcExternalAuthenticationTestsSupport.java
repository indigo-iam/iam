package it.infn.mw.iam.test.ext_authn.oidc;

import static it.infn.mw.iam.test.ext_authn.oidc.OidcTestConfig.TEST_OIDC_AUTHORIZATION_ENDPOINT_URI;
import static it.infn.mw.iam.test.ext_authn.oidc.OidcTestConfig.TEST_OIDC_TOKEN_ENDPOINT_URI;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
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
import it.infn.mw.iam.test.util.oidc.CodeRequestUtil;
import it.infn.mw.iam.test.util.oidc.MockOIDCProvider;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;

public class OidcExternalAuthenticationTestsSupport {

  @Value("${local.server.port}")
  Integer iamPort;

  @Autowired
  RestTemplateFactory restTemplateFactory;

  @Autowired
  MockOIDCProvider mockOidcProvider;

  @Autowired
  UserInfoFetcher mockUserInfoFetcher;


  String baseIamURL() {
    return "http://localhost:" + iamPort;
  }

  String openidConnectLoginURL() {
    return baseIamURL() + "/openid_connect_login";
  }

  String authnInfoURL() {
    return baseIamURL() + "/iam/authn-info";
  }

  String landingPageURL() {
    return baseIamURL() + "/";
  }

  String loginPageURL() {
    return baseIamURL() + "/login";
  }

  ClientHttpRequestFactory noRedirectHttpRequestFactory() {

    SimpleClientHttpRequestFactory rf = new SimpleClientHttpRequestFactory() {
      protected void prepareConnection(java.net.HttpURLConnection connection, String httpMethod)
	  throws java.io.IOException {
	super.prepareConnection(connection, httpMethod);
	connection.setInstanceFollowRedirects(false);
      }
    };

    return rf;
  }

  RestTemplate noRedirectRestTemplate() {
    return new RestTemplate(noRedirectHttpRequestFactory());
  }

  void checkAuthorizationEndpointRedirect(ResponseEntity<String> response) {
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

  String extractSessionCookie(ResponseEntity<String> response) {

    HttpHeaders requestHeaders = new HttpHeaders();
    UriComponents locationUri =
	UriComponentsBuilder.fromUri(response.getHeaders().getLocation()).build();

    return response.getHeaders().get("Set-Cookie").get(0);

  }

  CodeRequestUtil buildCodeRequest(String sessionCookie, ResponseEntity<String> response) {

    CodeRequestUtil result = new CodeRequestUtil();

    HttpHeaders requestHeaders = new HttpHeaders();
    UriComponents locationUri =
	UriComponentsBuilder.fromUri(response.getHeaders().getLocation()).build();

    String state = locationUri.getQueryParams().get("state").get(0);
    String nonce = locationUri.getQueryParams().get("nonce").get(0);

    requestHeaders.add("Cookie", sessionCookie);
    requestHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);


    MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
    params.add("state", state);
    params.add("code", "1234");

    HttpEntity<MultiValueMap<String, String>> requestEntity =
	new HttpEntity<MultiValueMap<String, String>>(params, requestHeaders);

    result.nonce = nonce;
    result.requestEntity = requestEntity;
    return result;
  }

  void prepareSuccessResponse(String tokenResponse) {
    MockRestTemplateFactory tf = (MockRestTemplateFactory) restTemplateFactory;
    tf.getMockServer()
      .expect(requestTo(TEST_OIDC_TOKEN_ENDPOINT_URI))
      .andExpect(method(HttpMethod.POST))
      .andExpect(content().contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
      .andRespond(MockRestResponseCreators.withSuccess(tokenResponse, MediaType.APPLICATION_JSON));
  }

  void prepareErrorResponse(String errorResponse) {
    MockRestTemplateFactory tf = (MockRestTemplateFactory) restTemplateFactory;
    tf.getMockServer()
      .expect(requestTo(TEST_OIDC_TOKEN_ENDPOINT_URI))
      .andExpect(method(HttpMethod.POST))
      .andExpect(content().contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
      .andRespond(MockRestResponseCreators.withBadRequest()
	.contentType(MediaType.APPLICATION_JSON)
	.body(errorResponse));
  }

  void verifyMockServerCalls() {
    MockRestTemplateFactory tf = (MockRestTemplateFactory) restTemplateFactory;
    tf.getMockServer().verify();
    tf.resetTemplate();
  }

}
