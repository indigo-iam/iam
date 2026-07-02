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
package it.infn.mw.iam.config;

import java.util.function.Function;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.web.client.RestTemplate;

import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.config.oidc.OidcClient;

@Configuration
public class ProxiedIntrospectionConfig {
  @Bean
  Function<OidcClient, RestTemplate> introspectionRestTemplateFactory(
      RestTemplateFactory defaultRestTemplateFactory) {

    return client -> createRestTemplate(client, defaultRestTemplateFactory);
  }

  private RestTemplate createRestTemplate(OidcClient client, RestTemplateFactory factory) {

    RestTemplate restTemplate = factory.newRestTemplate();

    restTemplate.getInterceptors()
      .add(new BasicAuthenticationInterceptor(client.clientId(), client.clientSecret()));

    return restTemplate;
  }
}
