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
package it.infn.mw.iam.core;

import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAuthenticationInfoBuilder;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.SavedUserAuthentication;
import it.infn.mw.iam.persistence.repository.IamAuthenticationHolderRepository;

@SuppressWarnings("deprecation")
@Service
public class IamAuthenticationHolderService {

  final IamAuthenticationHolderRepository repo;
  final ExternalAuthenticationInfoBuilder mapBuilder;

  public IamAuthenticationHolderService(IamAuthenticationHolderRepository repo,
      ExternalAuthenticationInfoBuilder mapBuilder) {
    this.repo = repo;
    this.mapBuilder = mapBuilder;
  }

  public AuthenticationHolderEntity create(OAuth2Authentication authn, ClientDetailsEntity client) {

    AuthenticationHolderEntity holder = new AuthenticationHolderEntity();
    holder.setAuthentication(authn);
    holder.setClient(client);
    Authentication userAuthentication = authn.getUserAuthentication();
    if (userAuthentication != null) {
      SavedUserAuthentication userAuth = new SavedUserAuthentication(userAuthentication);
      if (userAuthentication instanceof AbstractExternalAuthenticationToken<?> token) {
        Map<String, String> info = token.buildAuthnInfoMap(mapBuilder);
        userAuth.getAdditionalInfo().putAll(info);
      }
      holder.setUserAuth(userAuth);
    }
    return holder;
  }

  public AuthenticationHolderEntity save(AuthenticationHolderEntity authHolder) {
    return repo.save(authHolder);
  }

  public AuthenticationHolderEntity createAndSave(OAuth2Authentication authn, ClientDetailsEntity client) {
    return save(create(authn, client));
  }
}
