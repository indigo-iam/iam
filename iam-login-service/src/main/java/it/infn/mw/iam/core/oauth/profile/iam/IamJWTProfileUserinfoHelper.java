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
package it.infn.mw.iam.core.oauth.profile.iam;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.authn.ExternalAuthenticationInfoProcessor;
import it.infn.mw.iam.authn.util.AuthenticationUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.common.BaseUserinfoHelper;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamSshKey;

@SuppressWarnings("deprecation")
public class IamJWTProfileUserinfoHelper extends BaseUserinfoHelper {

  public static final Logger LOG = LoggerFactory.getLogger(IamJWTProfileUserinfoHelper.class);

  private final SshKeyConverter sshConverter;
  private final ExternalAuthenticationInfoProcessor extAuthnProcessor;

  public IamJWTProfileUserinfoHelper(IamProperties props,
      ExternalAuthenticationInfoProcessor proc) {
    super(props);
    this.extAuthnProcessor = proc;
    this.sshConverter = new SshKeyConverter();
  }

  @Override
  public Map<String, Object> resolveScopeClaims(OAuth2Authentication auth, Set<String> scopes,
      IamAccount account) {

    Map<String, Object> claims = super.resolveScopeClaims(auth, scopes, account);
    if (scopes.contains(OidcScopes.PROFILE)) {
      claims.put("scopes", scopes);
      claims.put("organisation_name", getProperties().getOrganisation().getName());
      includeIfNotNull(claims, "last_login_at", account.getLastLoginTime());
      includeIfNotNull(claims, "affiliation", account.getAffiliation());
      includeIfNotEmpty(claims, "groups", getGroupsAsStringSet(account.getUserInfo().getGroups()));
    }
    if (scopes.contains("ssh-keys")) {
      if (!account.getSshKeys().isEmpty()) {
        claims.put("ssh_keys", getSshKeysFilteredSet(account.getSshKeys()));
      }
    }
    // external Authentication info?
    if (AuthenticationUtils.isSupportedExternalAuthenticationToken(auth.getUserAuthentication())) {
      Map<String, String> processedAuthInfo = extAuthnProcessor.process(auth);
      if (!processedAuthInfo.isEmpty()) {
        claims.put("external_authn", processedAuthInfo);
      }
    }
    return claims;
  }

  private Set<ScimSshKey> getSshKeysFilteredSet(Set<IamSshKey> sshKeys) {
    return sshKeys.stream().map(sshConverter::dtoFromEntity).collect(Collectors.toSet());
  }
}
