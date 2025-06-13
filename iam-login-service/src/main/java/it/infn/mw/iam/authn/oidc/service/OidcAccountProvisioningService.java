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
import org.springframework.stereotype.Service;

import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Service
public class OidcAccountProvisioningService {

  private final IamAccountService accountService;
  private final Optional<Set<String>> trustedIdpEntityIds;
  private final IamAccountRepository repo;

  public OidcAccountProvisioningService(IamAccountRepository repo, IamAccountService accountService,
      Optional<Set<String>> trustedIdpEntityIds) {
    this.repo = repo;
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

  public IamAccount provisionAccount(OIDCAuthenticationToken token) {
    checkTrustedIdp(token.getIssuer());
    checkRequiredClaims(token);

    IamAccount newAccount = IamAccount.newAccount();
    String username = generateUniqueUsername(token.getUserInfo().getPreferredUsername(), repo);
    newAccount.setUsername(username);
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

  private String generateUniqueUsername(String preferredUsername,
      IamAccountRepository iamAccountRepository) {
    if (preferredUsername != null && !preferredUsername.isEmpty()
        && iamAccountRepository.findByUsername(preferredUsername).isEmpty()) {
      return preferredUsername;
    }
    return UUID.randomUUID().toString();
  }
}
