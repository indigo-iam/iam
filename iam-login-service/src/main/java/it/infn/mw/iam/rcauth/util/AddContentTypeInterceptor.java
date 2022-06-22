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
package it.infn.mw.iam.rcauth.util;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

public class AddContentTypeInterceptor implements ClientHttpRequestInterceptor {

  public static final String CONTENT_TYPE_HEADER = "Content-Type";

  private final String defaultContentType;

  public AddContentTypeInterceptor(String contentType) {
    defaultContentType = contentType;
  }


  @Override
  public ClientHttpResponse intercept(HttpRequest request, byte[] body,
      ClientHttpRequestExecution execution) throws IOException {

    ClientHttpResponse response = execution.execute(request, body);
    HttpHeaders headers = response.getHeaders();

    if (!headers.containsKey(CONTENT_TYPE_HEADER)) {
      headers.add(CONTENT_TYPE_HEADER, defaultContentType);
    }

    return response;
  }

}
