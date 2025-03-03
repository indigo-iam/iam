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
package it.infn.mw.iam.authn.oidc.service;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class JustInTimeProvisioningOIDCUserDetailsService extends DefaultOidcUserDetailsService {

  private final IamAccountService accountService;
  private final Optional<Set<String>> trustedIdpEntityIds;

  public JustInTimeProvisioningOIDCUserDetailsService(IamAccountRepository repo,
      InactiveAccountAuthenticationHander handler, IamAccountService accountService,
      Optional<Set<String>> trustedIdpEntityIds) {
    super(repo, handler);
    this.accountService = accountService;
    this.trustedIdpEntityIds = trustedIdpEntityIds;
  }

  private void checkTrustedIdp(String issuer) {
    trustedIdpEntityIds.ifPresent(trustedIds -> {
      if (!trustedIds.contains(issuer)) {
        throw new UsernameNotFoundException(
            String.format("OIDC issuer '%s' is not trusted for JIT provisioning.", issuer));
      }
    });
  }

  private void checkRequiredClaims(OIDCAuthenticationToken token) {
    if (token.getUserInfo().getGivenName() == null || token.getUserInfo().getFamilyName() == null
        || token.getUserInfo().getEmail() == null) {
      throw new UsernameNotFoundException("OIDC token is missing required claims.");
    }
  }

  private IamAccount provisionAccount(OIDCAuthenticationToken token) {
    checkTrustedIdp(token.getIssuer());
    checkRequiredClaims(token);

    IamAccount newAccount = IamAccount.newAccount();
    newAccount.setUsername(UUID.randomUUID().toString());
    newAccount.setProvisioned(true);

    IamOidcId oidcId = new IamOidcId();
    oidcId.setIssuer(token.getIssuer());
    oidcId.setSubject(token.getSub());
    oidcId.setAccount(newAccount);

    newAccount.getOidcIds().add(oidcId);

    newAccount.setActive(true);

    newAccount.getUserInfo().setGivenName(token.getUserInfo().getGivenName());
    newAccount.getUserInfo().setFamilyName(token.getUserInfo().getFamilyName());
    newAccount.getUserInfo().setEmail(token.getUserInfo().getEmail());

    accountService.createAccount(newAccount);
    return newAccount;
  }

  @Override
  public Object loadUserByOIDC(OIDCAuthenticationToken token) {
    Optional<IamAccount> account = repo.findByOidcId(token.getIssuer(), token.getSub());

    if (account.isPresent()) {
      return buildUserFromIamAccount(account.get());
    } else {
      return buildUserFromIamAccount(provisionAccount(token));
    }
  }
}
