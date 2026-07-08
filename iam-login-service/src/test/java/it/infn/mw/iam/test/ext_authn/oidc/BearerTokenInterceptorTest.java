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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpResponse;

import it.infn.mw.iam.authn.oidc.service.BearerTokenInterceptor;

@ExtendWith(MockitoExtension.class)
class BearerTokenInterceptorTest {

  @Mock
  private HttpRequest request;

  @Mock
  private ClientHttpRequestExecution execution;

  @Mock
  private ClientHttpResponse response;

  private HttpHeaders headers;

  @BeforeEach
  void setup() throws Exception {

    headers = new HttpHeaders();

    when(request.getHeaders()).thenReturn(headers);
    when(execution.execute(any(), any())).thenReturn(response);
  }

  @Test
  void bearerTokenIsAddedToAuthorizationHeader() throws Exception {

    BearerTokenInterceptor interceptor = new BearerTokenInterceptor("my-token");

    byte[] body = new byte[0];

    ClientHttpResponse result = interceptor.intercept(request, body, execution);

    assertEquals("Bearer my-token", headers.getFirst(HttpHeaders.AUTHORIZATION));
    assertSame(response, result);
    verify(execution).execute(request, body);
  }
}
