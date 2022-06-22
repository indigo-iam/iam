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

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolver;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class DefaultSAMLUserDetailsService extends SAMLUserDetailsServiceSupport
    implements SAMLUserDetailsService {

  final IamAccountRepository repo;

  @Autowired
  public DefaultSAMLUserDetailsService(SamlUserIdentifierResolver resolver,
      IamAccountRepository repo, InactiveAccountAuthenticationHander handler) {
    super(handler, resolver);
    this.repo = repo;
  }

  @Override
  public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {

    IamSamlId samlId = resolveSamlId(credential);

    Optional<IamAccount> account = repo.findBySamlId(samlId);

    if (account.isPresent()) {
      return buildUserFromIamAccount(account.get());
    }

    return buildUserFromSamlCredential(samlId, credential);
  }

}
