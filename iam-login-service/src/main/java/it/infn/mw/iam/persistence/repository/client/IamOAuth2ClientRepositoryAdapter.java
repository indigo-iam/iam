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
package it.infn.mw.iam.persistence.repository.client;

import java.util.Collection;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.repository.OAuth2ClientRepository;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.ImmutableList;

@Transactional
public class IamOAuth2ClientRepositoryAdapter implements OAuth2ClientRepository {

  private final IamClientRepository iamClientRepo;
  private final IamAccountClientRepository iamAccountClientRepo;

  public IamOAuth2ClientRepositoryAdapter(IamClientRepository iamClientRepo,
      IamAccountClientRepository iamAccountClientRepo) {
    this.iamClientRepo = iamClientRepo;
    this.iamAccountClientRepo = iamAccountClientRepo;
  }

  @Override
  public ClientDetailsEntity getById(Long id) {
    return iamClientRepo.findById(id).orElse(null);
  }

  @Override
  public ClientDetailsEntity getClientByClientId(String clientId) {
    return iamClientRepo.findByClientId(clientId).orElse(null);
  }

  @Override
  public ClientDetailsEntity saveClient(ClientDetailsEntity client) {
    return iamClientRepo.save(client);
  }

  @Override
  public void deleteClient(ClientDetailsEntity client) {

    iamAccountClientRepo.deleteByClientId(client.getId());
    iamClientRepo.delete(client);
  }

  @Override
  public ClientDetailsEntity updateClient(Long id, ClientDetailsEntity client) {
    client.setId(id);
    return iamClientRepo.save(client);
  }

  @Override
  public Collection<ClientDetailsEntity> getAllClients() {
    return ImmutableList.copyOf(iamClientRepo.findAll());
  }

}
