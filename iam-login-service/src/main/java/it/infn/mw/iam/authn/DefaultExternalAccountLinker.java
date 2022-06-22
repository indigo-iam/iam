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
package it.infn.mw.iam.authn;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.authn.error.AccountAlreadyLinkedError;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolver;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Component
public class DefaultExternalAccountLinker implements ExternalAccountLinker {

  final IamAccountRepository repo;
  final SamlUserIdentifierResolver samlUserIdResolver;

  @Autowired
  public DefaultExternalAccountLinker(IamAccountRepository repo,
      SamlUserIdentifierResolver resolver) {
    this.repo = repo;
    this.samlUserIdResolver = resolver;
  }

  @Override
  public void linkToIamAccount(IamAccount targetAccount, OidcExternalAuthenticationToken token) {

    final String oidcSubject = token.getExternalAuthentication().getSub();
    final String oidcIssuer = token.getExternalAuthentication().getIssuer();

    repo.findByOidcId(oidcIssuer, oidcSubject).ifPresent(found -> {

      if (found.equals(targetAccount)) {

        String errorMsg =
            String.format("OpenID connect account '[%s] %s' is already linked to user '%s'",
                oidcIssuer, oidcSubject, found.getUsername());

        throw new AccountAlreadyLinkedError(errorMsg);

      } else {

        String errorMsg =
            String.format("OpenID connect account '[%s] %s' is already linked to another user",
                oidcIssuer, oidcSubject);

        throw new AccountAlreadyLinkedError(errorMsg);
      }
    });

    IamOidcId oidcId = new IamOidcId();
    oidcId.setIssuer(oidcIssuer);
    oidcId.setSubject(oidcSubject);
    oidcId.setAccount(targetAccount);
    targetAccount.getOidcIds().add(oidcId);
    repo.save(targetAccount);
  }

  @Override
  public void linkToIamAccount(IamAccount targetAccount, SamlExternalAuthenticationToken token) {

    final SAMLCredential credential =
        (SAMLCredential) token.getExternalAuthentication().getCredentials();

    final IamSamlId iamSamlId = samlUserIdResolver.resolveSamlUserIdentifier(credential)
      .getResolvedId()
      .orElseThrow(() -> new UsernameNotFoundException(
          "Could not extract a user identifier from the SAML assertion"));

    repo.findBySamlId(iamSamlId).ifPresent(found -> {

      if (found.equals(targetAccount)) {

        String errorMsg = String.format(
            "SAML account '[%s] (%s = %s)' is already linked to user '%s'", iamSamlId.getIdpId(),
            iamSamlId.getAttributeId(), iamSamlId.getUserId(), found.getUsername());

        throw new AccountAlreadyLinkedError(errorMsg);
      } else {

        String errorMsg =
            String.format("SAML account '[%s] (%s = %s)' is already linked to another user",
                iamSamlId.getIdpId(), iamSamlId.getAttributeId(), iamSamlId.getUserId());

        throw new AccountAlreadyLinkedError(errorMsg);
      }

    });

    iamSamlId.setAccount(targetAccount);
    targetAccount.getSamlIds().add(iamSamlId);
    repo.save(targetAccount);

  }

}
