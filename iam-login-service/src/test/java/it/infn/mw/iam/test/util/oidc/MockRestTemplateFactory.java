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
package it.infn.mw.iam.test.util.oidc;

import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import it.infn.mw.iam.authn.oidc.DefaultRestTemplateFactory;

public class MockRestTemplateFactory extends DefaultRestTemplateFactory {

  RestTemplate template;
  MockRestServiceServer mockServer;

  public MockRestTemplateFactory() {
    super(new HttpComponentsClientHttpRequestFactory());
    resetTemplate();
  }

  public MockRestServiceServer resetTemplate() {
    template = new RestTemplate();
    mockServer = MockRestServiceServer.createServer(template);
    return mockServer;
  }

  public MockRestServiceServer getMockServer() {
    return mockServer;
  }

  @Override
  public RestTemplate newRestTemplate() {
    return template;
  }


}
