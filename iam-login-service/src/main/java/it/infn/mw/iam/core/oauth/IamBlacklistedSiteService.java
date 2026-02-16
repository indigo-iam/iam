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

import com.google.common.base.Strings;

import it.infn.mw.iam.persistence.model.BlacklistedSite;
import it.infn.mw.iam.persistence.repository.IamBlacklistedSiteRepository;

@Service
public class IamBlacklistedSiteService implements BlacklistedSiteService {

  @Autowired
  private IamBlacklistedSiteRepository repository;

  @Override
  public Collection<BlacklistedSite> getAll() {
    return repository.findAll();
  }

  @Override
  public BlacklistedSite getById(Long id) {
    return repository.findById(id).orElse(null);
  }

  @Override
  public void remove(BlacklistedSite blacklistedSite) {
    repository.delete(blacklistedSite);
  }

  @Override
  public BlacklistedSite save(BlacklistedSite blacklistedSite) {
    return repository.save(blacklistedSite);
  }

  @Override
  public boolean isBlacklisted(String uri) {

    if (Strings.isNullOrEmpty(uri)) {
      return false;
    }
    Collection<BlacklistedSite> sites = repository.findByUri(uri);
    return sites.stream().filter(bs -> bs.getUri() != null).anyMatch(bs -> uri.equals(bs.getUri()));
  }

}
