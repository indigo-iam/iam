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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@IamRandomPortIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, OidcTestConfig.class},
  webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"h2", "mfa"})
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
