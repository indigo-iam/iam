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

import static it.infn.mw.iam.core.userinfo.AarcDecoratedUserInfo.VOPERSON_EXTERNAL_AFFILIATION;

import java.util.Map;
import java.util.Set;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.SavedUserAuthentication;
import org.mitre.oauth2.service.IntrospectionResultAssembler;
import org.mitre.openid.connect.model.UserInfo;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.authn.ExternalAuthenticationInfoProcessor;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.common.BaseIntrospectionHelper;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.UserInfoAdapter;

@SuppressWarnings("deprecation")
public class AarcJWTProfileTokenIntrospectionHelper extends BaseIntrospectionHelper {

  protected final AarcClaimValueHelper claimValueHelper;

  protected final ExternalAuthenticationInfoProcessor extAuthnProcessor;

  public AarcJWTProfileTokenIntrospectionHelper(IamProperties props,
      IntrospectionResultAssembler assembler, ScopeMatcherRegistry scopeMatchersRegistry,
      AarcClaimValueHelper claimValueHelper, ExternalAuthenticationInfoProcessor proc) {
    super(props, assembler, scopeMatchersRegistry);
    this.claimValueHelper = claimValueHelper;
    this.extAuthnProcessor = proc;
  }

  @Override
  public Map<String, Object> assembleIntrospectionResult(OAuth2AccessTokenEntity accessToken,
      UserInfo userInfo, Set<String> authScopes) {

    Map<String, Object> result = getAssembler().assembleFrom(accessToken, userInfo, authScopes);

    Set<String> scopes = filterScopes(accessToken, authScopes);

    if (userInfo != null) {

      IamUserInfo iamUserInfo = ((UserInfoAdapter) userInfo).getUserinfo();

      if (scopes.contains(PROFILE)) {

        result.put(NAME, iamUserInfo.getName());
        result.put(GIVEN_NAME, iamUserInfo.getGivenName());
        result.put(FAMILY_NAME, iamUserInfo.getFamilyName());

      }

      if (scopes.contains(EMAIL)) {
        result.put(EMAIL, userInfo.getEmail());
      }

      if (scopes.contains(EDUPERSON_SCOPED_AFFILIATION)) {
        result.put(EDUPERSON_SCOPED_AFFILIATION,
            claimValueHelper.getClaimValueFromUserInfo(EDUPERSON_SCOPED_AFFILIATION, iamUserInfo));
      }

      if (scopes.contains(ENTITLEMENTS)) {
        result.put(ENTITLEMENTS,
            claimValueHelper.getClaimValueFromUserInfo(ENTITLEMENTS, iamUserInfo));
      }

      if (scopes.contains(EDUPERSON_ENTITLEMENT)) {
        result.put(ENTITLEMENTS,
            claimValueHelper.getClaimValueFromUserInfo(ENTITLEMENTS, iamUserInfo));
        result.put(EDUPERSON_ENTITLEMENT,
            claimValueHelper.getClaimValueFromUserInfo(EDUPERSON_ENTITLEMENT, iamUserInfo));
      }

      if (scopes.contains(EDUPERSON_ASSURANCE)) {
        result.put(EDUPERSON_ASSURANCE,
            claimValueHelper.getClaimValueFromUserInfo(EDUPERSON_ASSURANCE, iamUserInfo));
      }

      OAuth2Authentication auth = accessToken.getAuthenticationHolder().getAuthentication();
      SavedUserAuthentication userAuth = (SavedUserAuthentication) auth.getUserAuthentication();
      if (userAuth != null && !userAuth.getAdditionalInfo().isEmpty()){
        result.put(VOPERSON_EXTERNAL_AFFILIATION, addVoPersonExternalAffiliation(auth));
      }
      result.put("voperson_id", userInfo.getSub());
    }
    addAcrClaimIfNeeded(accessToken, result);

    return result;
  }

  private String addVoPersonExternalAffiliation (OAuth2Authentication auth){
    Map<String, String> claims = extAuthnProcessor.process(auth);
      if (claims.containsKey("EPSA")) {
        return claims.get("EPSA");
      } 
      if (claims.containsKey("eduperson_scoped_affiliation")) {
        return claims.get("eduperson_scoped_affiliation");
      }
    return "";
  }

}
