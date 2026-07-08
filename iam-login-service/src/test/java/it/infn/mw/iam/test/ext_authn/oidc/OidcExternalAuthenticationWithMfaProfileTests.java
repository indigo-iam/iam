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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import it.infn.mw.iam.IamLoginService;

@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@Transactional
//@formatter:off
@SpringBootTest(classes = {IamLoginService.class, OidcTestConfig.class},
  webEnvironment = WebEnvironment.DEFINED_PORT,
  properties = {
      "mfa.password-to-encrypt-and-decrypt=secret",
      "server.port=8989",
      "oidc.providers[0].name=provider",
      "oidc.providers[0].issuer=urn:test-oidc-issuer",
      "oidc.providers[0].client.clientId=iam",
      "oidc.providers[0].client.clientSecret=secret",
      "oidc.providers[0].client.scope=openid profile email",
      "oidc.providers[0].client.redirectUris=http://localhost:8989/openid_connect_login",
      "oidc.providers[0].client.tokenEndpointAuthMethod=SECRET_BASIC"
      })
//@formatter:on
@ActiveProfiles({"h2-test", "mfa"})
class OidcExternalAuthenticationWithMfaProfileTests
  extends OidcExternalAuthenticationTestsSupport {

  @Test
  void testAcrValuesClaimIsAddedWhenMfaProfileIsActive()
    throws RestClientException, UnsupportedEncodingException {

    RestTemplate rt = noRedirectRestTemplate();
    ResponseEntity<String> response = rt.getForEntity(openidConnectLoginURL(), String.class);

    UriComponents locationUri =
        UriComponentsBuilder.fromUri(response.getHeaders().getLocation()).build();

    String acrValue = locationUri.getQueryParams().getFirst("acr_values");
    String decodedAcrValue = URLDecoder.decode(acrValue, StandardCharsets.UTF_8.name());

    assertThat(decodedAcrValue, equalTo(MFA_REFEDS_VALUE));
  }
}
