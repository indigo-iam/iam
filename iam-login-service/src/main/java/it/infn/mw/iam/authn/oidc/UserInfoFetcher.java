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
package it.infn.mw.iam.authn.oidc;

import java.io.IOException;
import java.net.URI;

import org.mitre.openid.connect.model.DefaultUserInfo;
import org.mitre.openid.connect.model.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import com.google.common.base.Strings;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadataService.OIDCProviderMetadata;

public class UserInfoFetcher {

  private static final Logger LOG = LoggerFactory.getLogger(UserInfoFetcher.class);

  public static final String USERINFO_CACHE_NAME = "userInfo";
  
  private HttpComponentsClientHttpRequestFactory factory;

  public UserInfoFetcher(HttpComponentsClientHttpRequestFactory factory) {
    this.factory = factory;
  }

  @Cacheable(cacheNames = USERINFO_CACHE_NAME, key = "#token?.sub")
  public UserInfo loadUserInfo(final PendingOIDCAuthenticationToken token) {

    LOG.debug("No cache of the userinfo endpoint is used for token subject {}", token.getSub());

    OIDCProviderMetadata serverConfiguration = token.getServerConfiguration();

    if (serverConfiguration == null) {
      LOG.warn("No server configuration found.");
      return null;
    }

    if (Strings.isNullOrEmpty(serverConfiguration.userInfoEndpoint())) {
      LOG.warn("No userinfo endpoint, not fetching.");
      return null;
    }

    RestTemplate restTemplate = new RestTemplate(factory) {

      @Override
      protected ClientHttpRequest createRequest(URI url, HttpMethod method) throws IOException {
        ClientHttpRequest httpRequest = super.createRequest(url, method);
        httpRequest.getHeaders()
          .add("Authorization", String.format("Bearer %s", token.getAccessTokenValue()));
        return httpRequest;
      }
    };

    String userInfoString =
        restTemplate.getForObject(serverConfiguration.userInfoEndpoint(), String.class);

    if (!Strings.isNullOrEmpty(userInfoString)) {

      JsonObject userInfoJson = JsonParser.parseString(userInfoString).getAsJsonObject();

      return fromJson(userInfoJson);
    } else {
      throw new IllegalArgumentException("Unable to load user info");
    }

  }

  protected UserInfo fromJson(JsonObject userInfoJson) {
    return DefaultUserInfo.fromJson(userInfoJson);
  }
}

