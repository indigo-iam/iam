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

import static java.lang.String.format;

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.mitre.oauth2.model.SavedUserAuthentication;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.authn.util.AuthenticationUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.attributes.AttributeMapHelper;
import it.infn.mw.iam.core.oauth.profile.iam.IamClaimValueHelper;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@SuppressWarnings("deprecation")
public class AarcClaimValueHelper extends IamClaimValueHelper {

  public static final String AARC_VERSION_URI =
      "https://aarc-community.org/attribute/profile/version/1.0";
  public static final String REFEDS_ASSURANCE_URI = "https://refeds.org/assurance";
  public static final String REFEDS_ASSURANCE_IAP_LOW_URI = "https://refeds.org/assurance/IAP/low";

  public static final Set<String> DEFAULT_LOA =
      Set.of(REFEDS_ASSURANCE_URI, REFEDS_ASSURANCE_IAP_LOW_URI);

  static final String DEFAULT_AFFILIATION_TYPE = "member";

  public AarcClaimValueHelper(IamProperties properties, SshKeyConverter sshConverter,
      AttributeMapHelper attrHelper, ScopeClaimTranslationService scopeClaimTranslationService) {
    super(properties, sshConverter, attrHelper, scopeClaimTranslationService);
  }

  public Set<String> resolveGroups(IamUserInfo userInfo) {

    Set<String> encodedGroups = new HashSet<>();
    userInfo.getGroups().forEach(g -> encodedGroups.add(encodeGroup(g)));
    return encodedGroups;
  }

  private String encodeGroup(IamGroup group) {

    var aarcConfig = properties.getAarcProfile();

    String urnNid = aarcConfig.getUrnNid();
    String urnDelegatedNamespace = aarcConfig.getUrnDelegatedNamespace();
    String encodedGroupName = group.getName().replace("/", ":");

    String encodedSubnamespace = "";
    String urnSubnamespaces = aarcConfig.getUrnSubnamespaces();
    if (urnSubnamespaces != null && !urnSubnamespaces.isBlank()) {
      encodedSubnamespace = ":" + String.join(":", urnSubnamespaces.trim().split("\\s+"));
    }

    return String.format("urn:%s:%s%s:group:%s", urnNid, urnDelegatedNamespace, encodedSubnamespace,
        encodedGroupName);
  }

  private String resolveScopeDomain() {
    if (properties.getAarcProfile() != null) {
      String configuredScopeDomain = properties.getAarcProfile().getAffiliationScope();
      if (configuredScopeDomain != null && !configuredScopeDomain.isBlank()) {
        return configuredScopeDomain;
      }
    }
  
    return properties.getIssuer();
  }

  @Override
  public Object resolveClaim(String claimName, OAuth2Authentication auth,
      Optional<IamAccount> account) {

    final String SCOPED_FORMAT = "%s@%s";
    String scopeDomain = resolveScopeDomain();

    Optional<SavedUserAuthentication> userAuth =
        (auth != null && auth.getUserAuthentication() != null)
            ? AuthenticationUtils.getExternalAuthenticationInfo(auth.getUserAuthentication())
            : Optional.empty();

    if (account.isPresent()) {
      switch (claimName) {
        case AarcExtraClaimNames.AARC_VER:
          return AARC_VERSION_URI;
        case AarcExtraClaimNames.EDUPERSON_ASSURANCE:
          if (userAuth.isPresent()) {
            Set<String> loa = new HashSet<>(DEFAULT_LOA);
            String remoteLoa = firstOf(userAuth.get().getAdditionalInfo(),
                Set.of("eduPersonAssurance", "urn:oid:1.3.6.1.4.1.5923.1.1.1.11"));
            if (remoteLoa != null) {
              loa.add(remoteLoa);
            }
            return loa;
          }
          return DEFAULT_LOA;
        case AarcExtraClaimNames.EDUPERSON_ENTITLEMENT, AarcExtraClaimNames.ENTITLEMENTS:
          return resolveGroups(account.get().getUserInfo());
        case AarcExtraClaimNames.VOPERSON_ID:
          return format(SCOPED_FORMAT, account.get().getUserInfo().getSub(), scopeDomain);
        case AarcExtraClaimNames.EDUPERSON_SCOPED_AFFILIATION:
          return format(SCOPED_FORMAT, DEFAULT_AFFILIATION_TYPE, scopeDomain);
        case AarcExtraClaimNames.VOPERSON_EXTERNAL_AFFILIATION:
          if (userAuth.isPresent()) {
            Set<String> scopedAffiliations = new HashSet<>();
            if (account.get().getAffiliation() != null) {
              scopedAffiliations.add(format(SCOPED_FORMAT, account.get().getAffiliation(),
                  scopeDomain));
            }
            String externalScopedAffiliation = firstOf(userAuth.get().getAdditionalInfo(),
                Set.of("EPSA", "eduPersonScopedAffiliation", "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"));
            if (externalScopedAffiliation != null) {
              scopedAffiliations.add(externalScopedAffiliation);
            }
            return scopedAffiliations;
          }
          return null;
        case AarcExtraClaimNames.SCHAC_HOME_ORGANIZATION:
          if (userAuth.isPresent()) {
            return userAuth.get().getAdditionalInfo().get("urn:oid:1.3.6.1.4.1.25178.1.2.9");
          }
          return null;
        default:
          return super.resolveClaim(claimName, auth, account);
      }
    } else {
      return super.resolveClaim(claimName, auth, account);
    }
  }

  private String firstOf(Map<String, String> additionalInfo, Set<String> keys) {
    for (String key : keys) {
      if (additionalInfo.containsKey(key)) {
        return additionalInfo.get(key);
      }
    }
    return null;
  }
}
