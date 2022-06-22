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
package it.infn.mw.iam.test.ext_authn.oidc.validator;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.UnsupportedEncodingException;
import java.util.Optional;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.common.Fail;
import it.infn.mw.iam.authn.common.ValidatorResolver;
import it.infn.mw.iam.test.ext_authn.oidc.OidcExternalAuthenticationTestsSupport;
import it.infn.mw.iam.test.ext_authn.oidc.OidcTestConfig;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;
import it.infn.mw.iam.test.util.oidc.CodeRequestHolder;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;

@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, OidcTestConfig.class,
    OidcValidatorIntegrationTests.Config.class}, webEnvironment = WebEnvironment.RANDOM_PORT)
public class OidcValidatorIntegrationTests extends OidcExternalAuthenticationTestsSupport {
  
  @Configuration
  public static class Config {
    @Bean
    @Primary
    ValidatorResolver<JWT> validatorResolver(){
      return r -> Optional.of(new Fail<>());
    }
  }

  @Before
  public void setup() {
    MockRestTemplateFactory tf = (MockRestTemplateFactory) restTemplateFactory;
    tf.resetTemplate();
  }
  
  @Test
  public void testValidatorError() throws JOSEException,
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

    assertThat(locationUri.getPath(), equalTo("/login"));
    assertThat(locationUri.getQueryParams().keySet(), hasItem("externalAuthenticationError"));
    assertThat(locationUri.getQueryParams().getFirst("externalAuthenticationError"), is("always%20fails"));
  }
  
  

}
