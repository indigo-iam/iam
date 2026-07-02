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

import java.net.URISyntaxException;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.http.client.utils.URIBuilder;
import org.springframework.security.authentication.AuthenticationServiceException;

import com.google.common.base.Strings;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadataService.OIDCProviderMetadata;
import it.infn.mw.iam.config.oidc.OidcProvider;

public class PlainAuthRequestUrlBuilder {

  public String buildAuthRequestUrl(OIDCProviderMetadata serverConfig, OidcProvider clientConfig,
      String redirectUri, String nonce, String state, Map<String, String> options,
      String loginHint) {
    try {

      URIBuilder uriBuilder = new URIBuilder(serverConfig.authorizationEndpoint());
      uriBuilder.addParameter("response_type", "code");
      uriBuilder.addParameter("client_id", clientConfig.getClient().clientId());
      uriBuilder.addParameter("scope",
          String.join(" ", clientConfig.getClient().scope().split(",")));
      uriBuilder.addParameter("redirect_uri", redirectUri);
      uriBuilder.addParameter("nonce", nonce);
      uriBuilder.addParameter("state", state);

      for (Entry<String, String> option : options.entrySet()) {
        uriBuilder.addParameter(option.getKey(), option.getValue());
      }

      if (!Strings.isNullOrEmpty(loginHint)) {
        uriBuilder.addParameter("login_hint", loginHint);
      }

      return uriBuilder.build().toString();

    } catch (URISyntaxException e) {
      throw new AuthenticationServiceException("Malformed Authorization Endpoint Uri", e);
    }
  }

}
