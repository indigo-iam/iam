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
package it.infn.mw.iam.core.oauth.consent;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.persistence.model.BlockedUri;
import it.infn.mw.iam.persistence.repository.IamBlockedUriRepository;

@Service
public class DefaultBlockedUriService implements BlockedUriService {

  private IamBlockedUriRepository repository;

  public DefaultBlockedUriService(IamBlockedUriRepository repository) {
    this.repository = repository;
  }

  @Override
  public List<BlockedUri> findAll() {
    return repository.findAll();
  }

  @Override
  public Optional<BlockedUri> findById(Long id) {
    return repository.findById(id);
  }

  @Override
  public void remove(BlockedUri blockedUri) {
    repository.delete(blockedUri);
  }

  @Override
  public BlockedUri save(BlockedUri blockedUri) {
    return repository.save(blockedUri);
  }

  @Override
  public boolean isBlockedUri(String uri) {

    if (uri == null || uri.isBlank()) {
      return false;
    }
    return repository.findByUri(uri).isPresent();
  }

}
