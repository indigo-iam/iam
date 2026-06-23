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
import java.net.URISyntaxException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.mitre.openid.connect.model.DefaultUserInfo;
import org.mitre.openid.connect.model.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import com.google.common.base.Strings;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadataService.OIDCProviderMetadata;

public class UserInfoFetcher {

  private static final Logger LOG = LoggerFactory.getLogger(UserInfoFetcher.class);

  private LoadingCache<PendingOIDCAuthenticationToken, UserInfo> cache;

  public UserInfoFetcher() {
    this(HttpClientBuilder.create().useSystemProperties().build());
  }

  public UserInfoFetcher(HttpClient httpClient) {
    cache = CacheBuilder.newBuilder()
      .expireAfterWrite(1, TimeUnit.HOURS)
      .maximumSize(100)
      .build(new UserInfoLoader(httpClient));
  }

  public UserInfo loadUserInfo(final PendingOIDCAuthenticationToken token) {
    try {
      return cache.get(token);
    } catch (UncheckedExecutionException | ExecutionException e) {
      LOG.warn("Couldn't load User Info from token: {}", e.getMessage());
      return null;
    }

  }


  private class UserInfoLoader extends CacheLoader<PendingOIDCAuthenticationToken, UserInfo> {
    private HttpComponentsClientHttpRequestFactory factory;

    UserInfoLoader(HttpClient httpClient) {
      this.factory = new HttpComponentsClientHttpRequestFactory(httpClient);
    }

    @Override
    public UserInfo load(final PendingOIDCAuthenticationToken token) throws URISyntaxException {

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

        JsonObject userInfoJson = new JsonParser().parse(userInfoString).getAsJsonObject();

        UserInfo userInfo = fromJson(userInfoJson);

        return userInfo;
      } else {
        throw new IllegalArgumentException("Unable to load user info");
      }

    }
  }

  protected UserInfo fromJson(JsonObject userInfoJson) {
    return DefaultUserInfo.fromJson(userInfoJson);
  }
}

