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
package it.infn.mw.iam.authn.saml;

import static com.google.common.base.Preconditions.checkNotNull;
import static it.infn.mw.iam.config.saml.IamSamlJITAccountProvisioningProperties.UsernameMappingPolicy.attributeValuePolicy;
import static it.infn.mw.iam.config.saml.IamSamlJITAccountProvisioningProperties.UsernameMappingPolicy.samlIdPolicy;
import static java.util.Objects.isNull;

import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.saml.util.Saml2Attribute;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolver;
import it.infn.mw.iam.config.saml.IamSamlJITAccountProvisioningProperties.AttributeMappingProperties;
import it.infn.mw.iam.config.saml.IamSamlJITAccountProvisioningProperties.UsernameMappingPolicy;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class JustInTimeProvisioningSAMLUserDetailsService extends SAMLUserDetailsServiceSupport
    implements SAMLUserDetailsService {


  private final IamAccountRepository repo;
  private final IamAccountService accountService;
  private final Optional<Set<String>> trustedIdpEntityIds;

  private final MappingPropertiesResolver mappingResolver;


  public JustInTimeProvisioningSAMLUserDetailsService(SamlUserIdentifierResolver resolver,
      IamAccountService accountService, InactiveAccountAuthenticationHander inactiveAccountHandler,
      IamAccountRepository repo, Optional<Set<String>> trustedIdpEntityIds,
      MappingPropertiesResolver mappingResolver) {

    super(inactiveAccountHandler, resolver);
    this.accountService = accountService;
    this.repo = repo;
    this.trustedIdpEntityIds = trustedIdpEntityIds;
    this.mappingResolver = mappingResolver;
  }

  protected void samlCredentialEntityIdChecks(SAMLCredential credential) {
    trustedIdpEntityIds.ifPresent(l -> {
      if (!l.contains(credential.getRemoteEntityID())) {
        throw new UsernameNotFoundException(
            String.format("Error provisioning user! SAML credential issuer '%s' is not trusted"
                + " for just-in-time account provisioning.", credential.getRemoteEntityID()));
      }
    });
  }

  protected void samlCredentialAttributesChecks(SAMLCredential credential,
      EnumSet<Saml2Attribute> requiredAttributes) {
    for (Saml2Attribute a : requiredAttributes) {
      if (credential.getAttributeAsString(a.getAttributeName()) == null) {
        throw new UsernameNotFoundException(String.format(
            "Error provisioning user! SAML credential is missing required attribute: %s (%s)",
            a.getAlias(), a.getAttributeName()));
      }
    }
  }


  private void safeSetUsername(IamAccount account, String username, String defaultUsername) {
    if (username.length() < 128) {
      account.setUsername(username);
    } else {
      account.setUsername(defaultUsername);
    }
  }

  private EnumSet<Saml2Attribute> buildRequiredAttributes(
      AttributeMappingProperties mappingProperties) {
    EnumSet<Saml2Attribute> requiredAttrs = EnumSet.noneOf(Saml2Attribute.class);

    requiredAttrs.add(Saml2Attribute.byAlias(mappingProperties.getFirstNameAttribute()));
    requiredAttrs.add(Saml2Attribute.byAlias(mappingProperties.getFamilyNameAttribute()));
    requiredAttrs.add(Saml2Attribute.byAlias(mappingProperties.getEmailAttribute()));

    if (attributeValuePolicy.equals(mappingProperties.getUsernameMappingPolicy())) {
      requiredAttrs.add(Saml2Attribute.byAlias(mappingProperties.getUsernameAttribute()));
    }

    return requiredAttrs;
  }

  private void mapAttributes(SAMLCredential credential, IamSamlId samlId, IamAccount newAccount,
      AttributeMappingProperties mappingProperties) {

    Saml2Attribute givenName = Saml2Attribute.byAlias(mappingProperties.getFirstNameAttribute());
    Saml2Attribute familyName = Saml2Attribute.byAlias(mappingProperties.getFamilyNameAttribute());
    Saml2Attribute email = Saml2Attribute.byAlias(mappingProperties.getEmailAttribute());

    newAccount.getUserInfo().setGivenName(getAttributeAsString(credential, givenName));

    newAccount.getUserInfo().setFamilyName(getAttributeAsString(credential, familyName));

    newAccount.getUserInfo().setEmail(getAttributeAsString(credential, email));

    final UsernameMappingPolicy mp = mappingProperties.getUsernameMappingPolicy();

    if (attributeValuePolicy.equals(mp)) {
      if (!isNull(mappingProperties.getUsernameAttribute())) {
        Saml2Attribute username = Saml2Attribute.byAlias(mappingProperties.getUsernameAttribute());
        safeSetUsername(newAccount, getAttributeAsString(credential, username),
            newAccount.getUsername());
      }
    } else if (samlIdPolicy.equals(mp)) {
      safeSetUsername(newAccount, samlId.getUserId(), newAccount.getUsername());
    }
  }


  private String getAttributeAsString(SAMLCredential credential, Saml2Attribute attribute) {
    return credential.getAttributeAsString(attribute.getAttributeName());
  }


  private IamAccount provisionAccount(SAMLCredential credential, IamSamlId samlId) {

    samlCredentialEntityIdChecks(credential);

    AttributeMappingProperties mappingProperties =
        mappingResolver.resolveMappingProperties(credential.getRemoteEntityID());

    samlCredentialAttributesChecks(credential, buildRequiredAttributes(mappingProperties));

    IamAccount newAccount = IamAccount.newAccount();

    newAccount.setUsername(UUID.randomUUID().toString());
    newAccount.setProvisioned(true);
    newAccount.getSamlIds().add(samlId);
    samlId.setAccount(newAccount);

    newAccount.setActive(true);
    mapAttributes(credential, samlId, newAccount, mappingProperties);

    accountService.createAccount(newAccount);
    return newAccount;
  }

  @Override
  public Object loadUserBySAML(SAMLCredential credential) {
    checkNotNull(credential, "null saml credential");

    IamSamlId samlId = resolveSamlId(credential);

    Optional<IamAccount> account = repo.findBySamlId(samlId);

    if (account.isPresent()) {
      return buildUserFromIamAccount(account.get());
    } else {
      return buildUserFromIamAccount(provisionAccount(credential, samlId));
    }
  }

}
