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

import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.AFFILIATION;
import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.ATTR;
import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.EXTERNAL_AUTHN;
import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.GROUPS;
import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.LAST_LOGIN_AT;
import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.ORGANISATION_NAME;
import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.SSH_KEYS;

import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.mitre.oauth2.model.SavedUserAuthentication;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.authn.util.AuthenticationUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.attributes.AttributeMapHelper;
import it.infn.mw.iam.core.oauth.profile.common.BaseClaimValueHelper;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamSshKey;

@SuppressWarnings("deprecation")
public class IamClaimValueHelper extends BaseClaimValueHelper {

  private final IamProperties properties;
  private final SshKeyConverter sshConverter;
  private final AttributeMapHelper attrHelper;
  private final ScopeClaimTranslationService scopeClaimTranslationService;

  public IamClaimValueHelper(IamProperties properties, SshKeyConverter sshConverter,
      AttributeMapHelper attrHelper, ScopeClaimTranslationService scopeClaimTranslationService) {
    this.properties = properties;
    this.sshConverter = sshConverter;
    this.attrHelper = attrHelper;
    this.scopeClaimTranslationService = scopeClaimTranslationService;
  }

  protected IamProperties getProperties() {
    return properties;
  }

  protected SshKeyConverter getSshConverter() {
    return sshConverter;
  }

  protected AttributeMapHelper getAttrHelper() {
    return attrHelper;
  }

  public ScopeClaimTranslationService getScopeClaimTranslationService() {
    return scopeClaimTranslationService;
  }

  @Override
  public Object resolveClaim(String claimName, OAuth2Authentication auth,
      Optional<IamAccount> account) {

    switch (claimName) {
      case ORGANISATION_NAME:
        return properties.getOrganisation().getName();
      case LAST_LOGIN_AT:
        return account.isPresent() ? account.get().getLastLoginTime() : null;
      case AFFILIATION:
        return account.isPresent() ? account.get().getUserInfo().getAffiliation() : null;
      case GROUPS:
        return account.isPresent() ? getGroupNames(account.get().getUserInfo().getGroups()) : null;
      case SSH_KEYS:
        return account.isPresent() ? getSshKeysFilteredSet(account.get().getSshKeys()) : null;
      case ATTR:
        return account.isPresent() ? attrHelper.getAttributeMapFromUserInfo(account.get().getUserInfo())
            : null;
      case EXTERNAL_AUTHN:
        Optional<SavedUserAuthentication> userAuth =
            AuthenticationUtils.getExternalAuthenticationInfo(auth.getUserAuthentication());
        if (userAuth.isPresent()) {
          return userAuth.get().getAdditionalInfo();
        }
        return null;
      default:
        return super.resolveClaim(claimName, auth, account);
    }
  }

  protected Collection<String> getGroupNames(Set<IamGroup> groups) {
    return groups.stream().map(IamGroup::getName).collect(Collectors.toSet());
  }

  private Set<ScimSshKey> getSshKeysFilteredSet(Set<IamSshKey> sshKeys) {
    return sshKeys.stream().map(sshConverter::dtoFromEntity).collect(Collectors.toSet());
  }

}
