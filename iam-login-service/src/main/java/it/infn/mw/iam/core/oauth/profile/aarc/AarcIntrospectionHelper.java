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

import java.text.ParseException;
import java.util.Map;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;

import it.infn.mw.iam.core.oauth.profile.common.BaseIntrospectionHelper;
import it.infn.mw.iam.core.user.IamAccountService;

public class AarcIntrospectionHelper extends BaseIntrospectionHelper {


  public AarcIntrospectionHelper(IamAccountService accountService) {
    super(accountService);
  }

  @Override
  public Map<String, Object> assembleIntrospectionResult(OAuth2AccessTokenEntity accessToken,
      ClientDetailsEntity authenticatedClient) throws ParseException {

    Map<String, Object> claims =
        super.assembleIntrospectionResult(accessToken, authenticatedClient);
    // add all the others avoiding duplicates/override
    accessToken.getJwt().getJWTClaimsSet().getClaims().forEach(claims::putIfAbsent);
    return claims;
  }

  @Override
  public Map<String, Object> assembleIntrospectionResult(OAuth2RefreshTokenEntity refreshToken,
      ClientDetailsEntity authenticatedClient) throws ParseException {

    Map<String, Object> claims =
        super.assembleIntrospectionResult(refreshToken, authenticatedClient);
    // add all the others avoiding duplicates/override
    refreshToken.getJwt().getJWTClaimsSet().getClaims().forEach(claims::putIfAbsent);
    return claims;
  }
}
