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
package it.infn.mw.iam.core.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver;
import org.springframework.stereotype.Component;

import com.google.common.base.Strings;

import it.infn.mw.iam.config.MitreConfigurationPropertiesBean;
import it.infn.mw.iam.core.oauth.BlacklistedSiteService;

@SuppressWarnings("deprecation")
@Component
public class BlacklistAwareRedirectResolver extends DefaultRedirectResolver {

  @Autowired
  private BlacklistedSiteService blacklistService;

  @Autowired
  private MitreConfigurationPropertiesBean config;

  private boolean strictMatch = true;

  @Override
  public String resolveRedirect(String requestedRedirect, ClientDetails client)
      throws OAuth2Exception {
    String redirect = super.resolveRedirect(requestedRedirect, client);
    if (blacklistService.isBlacklisted(redirect)) {
      throw new InvalidRequestException("The supplied redirect_uri is not allowed on this server.");
    }
    return redirect;
  }

  @Override
  protected boolean redirectMatches(String requestedRedirect, String redirectUri) {

    if (isStrictMatch()) {
      // we're doing a strict string match for all clients
      return Strings.nullToEmpty(requestedRedirect).equals(redirectUri);
    }
    return super.redirectMatches(requestedRedirect, redirectUri);
  }

  public boolean isStrictMatch() {
    if (config.isHeartMode()) {
      return true;
    }
    return strictMatch;
  }

  public void setStrictMatch(boolean strictMatch) {
    this.strictMatch = strictMatch;
  }
}

