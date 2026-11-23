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
package it.infn.mw.iam.test.login;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class LoginPageRenderingTests {

  @Autowired
  private TestRestTemplate restTemplate;

  @Test
  void shouldRenderLoginHint() {
    String loginHint = "zz\"><svg onload=alert(1)>";

    ResponseEntity<String> authorizeResponse = restTemplate.getForEntity(
        "/authorize?client_id=client"
            + "&redirect_uri=http://localhost:9090/iam-test-client/login/oauth2/code/dynamic"
            + "&response_type=code" + "&scope=openid" + "&login_hint={loginHint}",
        String.class, loginHint);

    assertThat(authorizeResponse.getStatusCode()).isEqualTo(HttpStatus.FOUND);

    URI loginUri = authorizeResponse.getHeaders().getLocation();
    assertThat(loginUri).isNotNull();

    String sessionCookie = authorizeResponse.getHeaders().getFirst(HttpHeaders.SET_COOKIE);

    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.COOKIE, sessionCookie.split(";")[0]);

    ResponseEntity<String> loginResponse =
        restTemplate.exchange(loginUri, HttpMethod.GET, new HttpEntity<>(headers), String.class);

    assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(loginResponse.getBody()).isNotNull();

    assertThat(loginResponse.getBody())
      .contains("value=\"zz&#034;&gt;&lt;svg onload=alert(1)&gt;\"");

    assertThat(loginResponse.getBody()).doesNotContain("<svg onload=alert(1)>");
  }
}
