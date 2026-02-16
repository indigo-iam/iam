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
package it.infn.mw.iam.core.oauth;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.persistence.model.WhitelistedSite;
import it.infn.mw.iam.persistence.repository.IamWhitelistedSiteRepository;

@Service
@Transactional
public class IamWhitelistedSiteService implements WhitelistedSiteService {

  @Autowired
  private IamWhitelistedSiteRepository repository;

  @Override
  public WhitelistedSite getById(Long id) {
    return repository.getById(id);
  }

  @Override
  public void remove(WhitelistedSite whitelistedSite) {
    repository.delete(whitelistedSite);
  }

  @Override
  public WhitelistedSite saveNew(WhitelistedSite whitelistedSite) {
    if (whitelistedSite.getId() != null) {
      throw new IllegalArgumentException(
          "A new whitelisted site cannot be created with an id value already set: "
              + whitelistedSite.getId());
    }
    return repository.save(whitelistedSite);
  }

  @Override
  public Collection<WhitelistedSite> getAll() {
    return repository.findAll();
  }

  @Override
  public WhitelistedSite getByClientId(String clientId) {
    return repository.findByClientId(clientId).orElse(null);
  }

}

