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
package it.infn.mw.iam.authn.oidc.service;

import java.util.Optional;

import org.mitre.openid.connect.model.DefaultUserInfo;
import org.mitre.openid.connect.model.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import com.google.common.base.Strings;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadata;
import it.infn.mw.iam.authn.oidc.PendingOIDCAuthenticationToken;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;

@Component
public class UserInfoFetcher {

  private static final Logger LOG = LoggerFactory.getLogger(UserInfoFetcher.class);

  private RestTemplateFactory factory;

  public UserInfoFetcher(RestTemplateFactory factory) {
    this.factory = factory;
  }

  public Optional<UserInfo> loadUserInfo(final PendingOIDCAuthenticationToken token) {

    OIDCProviderMetadata metadata = token.getWellKnownEndpoint();

    if (metadata == null || Strings.isNullOrEmpty(metadata.userInfoEndpoint())) {
      LOG.warn("No userinfo endpoint available.");
      return Optional.empty();
    }

    RestTemplate restTemplate = factory.newRestTemplate();

    restTemplate.getInterceptors().add(new BearerTokenInterceptor((String) token.getCredentials()));

    String response = restTemplate.getForObject(metadata.userInfoEndpoint(), String.class);

    if (Strings.isNullOrEmpty(response)) {
      LOG.warn("Received empty userinfo response from {}", metadata.userInfoEndpoint());
      return Optional.empty();
    }

    JsonObject userInfoJson = JsonParser.parseString(response).getAsJsonObject();
    return Optional.of(DefaultUserInfo.fromJson(userInfoJson));

  }
}

