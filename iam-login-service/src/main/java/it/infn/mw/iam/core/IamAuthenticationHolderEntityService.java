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

import java.util.List;
import java.util.Map;

import org.mitre.data.PageCriteria;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.repository.AuthenticationHolderRepository;
import org.mitre.oauth2.service.AuthenticationHolderEntityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAuthenticationInfoBuilder;

@SuppressWarnings("deprecation")
@Service("authenticationHolderEntityService")
@Primary
public class IamAuthenticationHolderEntityService implements AuthenticationHolderEntityService {


  final AuthenticationHolderRepository repo;
  final ExternalAuthenticationInfoBuilder mapBuilder;

  @Autowired
  public IamAuthenticationHolderEntityService(AuthenticationHolderRepository repo,
      ExternalAuthenticationInfoBuilder mapBuilder) {
    this.repo = repo;
    this.mapBuilder = mapBuilder;
  }

  @Override
  public AuthenticationHolderEntity create(OAuth2Authentication authn) {

    AuthenticationHolderEntity holder = new AuthenticationHolderEntity();
    holder.setAuthentication(authn);

    if (authn.getUserAuthentication() != null
        && authn.getUserAuthentication() instanceof AbstractExternalAuthenticationToken<?>) {

      AbstractExternalAuthenticationToken<?> token =
          (AbstractExternalAuthenticationToken<?>) authn.getUserAuthentication();

      Map<String, String> info = token.buildAuthnInfoMap(mapBuilder);
      holder.getUserAuth().getAdditionalInfo().putAll(info);

    }

    return repo.save(holder);

  }

  @Override
  public void remove(AuthenticationHolderEntity holder) {

    repo.remove(holder);
  }

  @Override
  public List<AuthenticationHolderEntity> getOrphanedAuthenticationHolders() {

    return repo.getOrphanedAuthenticationHolders();
  }

  @Override
  public List<AuthenticationHolderEntity> getOrphanedAuthenticationHolders(PageCriteria page) {
    return repo.getOrphanedAuthenticationHolders(page);
  }
}
