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
package it.infn.mw.iam.core.oauth.granters;

import java.util.Date;

import org.mitre.oauth2.exception.AuthorizationPendingException;
import org.mitre.oauth2.exception.DeviceCodeExpiredException;
import org.mitre.oauth2.model.DeviceCode;
import org.mitre.oauth2.service.DeviceCodeService;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

@SuppressWarnings("deprecation")
public class IamDeviceCodeTokenGranter extends AbstractTokenGranter {

  public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

  private final DeviceCodeService deviceCodeService;

  public IamDeviceCodeTokenGranter(AuthorizationServerTokenServices tokenServices,
      ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory,
      DeviceCodeService deviceCodeService) {
    super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
    this.deviceCodeService = deviceCodeService;
  }


  // Revert back to mitre implementation as soon as they have fixed how
  // they manage the granter creation (use proper constructor injection)
  @Override
  protected OAuth2Authentication getOAuth2Authentication(ClientDetails client,
      TokenRequest tokenRequest) {

    String deviceCode = tokenRequest.getRequestParameters().get("device_code");

    // look up the device code and consume it
    DeviceCode dc = deviceCodeService.findDeviceCode(deviceCode, client);

    if (dc == null) {
      throw new InvalidGrantException("Invalid device code: " + deviceCode);
    }

    final Date now = new Date();

    // dc expiration checks
    if (dc.getExpiration() != null && dc.getExpiration().before(now)) {
      deviceCodeService.clearDeviceCode(deviceCode, client);
      throw new DeviceCodeExpiredException("Device code has expired: " + deviceCode);
    }

    if (!dc.isApproved()) {
      throw new AuthorizationPendingException("Authorization pending for code: " + deviceCode);
    }

    // inherit the (approved) scopes from the original request
    tokenRequest.setScope(dc.getScope());

    OAuth2Authentication auth =
        new OAuth2Authentication(getRequestFactory().createOAuth2Request(client, tokenRequest),
            dc.getAuthenticationHolder().getUserAuth());

    deviceCodeService.clearDeviceCode(deviceCode, client);

    return auth;
  }
}
