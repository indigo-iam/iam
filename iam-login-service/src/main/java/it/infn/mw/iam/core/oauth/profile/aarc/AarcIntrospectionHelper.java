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
package it.infn.mw.iam.core.oauth.profile.aarc;

import java.util.Map;
import java.util.Optional;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;

import com.nimbusds.jwt.JWTClaimsSet;

import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.common.BaseIntrospectionHelper;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AarcIntrospectionHelper extends BaseIntrospectionHelper {

  private final ClaimValueHelper claimValueHelper;

  public AarcIntrospectionHelper(ClaimValueHelper claimValueHelper, IamAccountService accountService) {
    super(accountService);
    this.claimValueHelper = claimValueHelper;
  }

  @Override
  public Map<String, Object> assembleIntrospectionResult(OAuth2AccessTokenEntity accessToken,
      ClientDetailsEntity authenticatedClient) {

    Map<String, Object> result =
        super.assembleIntrospectionResult(accessToken, authenticatedClient);

    JWTClaimsSet claims = getClaimsSet(accessToken.getJwt());
    final Optional<IamAccount> account;
    if (accessToken.getAuthenticationHolder().getUserAuth() != null) {
      String subject = claims.getSubject();
      account = getAccountService().findByUuid(subject);
    } else {
      account = Optional.empty();
    }

    AarcExtraClaimNames.INTROSPECTION_REQUIRED_CLAIMS.forEach(claimName -> {
      Object claimValue = claimValueHelper.resolveClaim(claimName,
          accessToken.getAuthenticationHolder().getAuthentication(), account);
      if (claimValueHelper.isValidClaimValue(claimValue)) {
        result.putIfAbsent(claimName, claimValue);
      }
    });

    // add all the others avoiding duplicates/override
    claims.getClaims().forEach(result::putIfAbsent);
    return result;
  }

  @Override
  public Map<String, Object> assembleIntrospectionResult(OAuth2RefreshTokenEntity refreshToken,
      ClientDetailsEntity authenticatedClient) {

    Map<String, Object> result =
        super.assembleIntrospectionResult(refreshToken, authenticatedClient);
    // add all the others avoiding duplicates/override
    getClaimsSet(refreshToken.getJwt()).getClaims().forEach(result::putIfAbsent);
    return result;
  }
}
