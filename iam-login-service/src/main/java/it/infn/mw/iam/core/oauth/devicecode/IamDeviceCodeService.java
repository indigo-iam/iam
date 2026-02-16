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
package it.infn.mw.iam.core.oauth.devicecode;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.core.AuthenticationHolderService;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.DeviceCode;
import it.infn.mw.iam.persistence.repository.IamDeviceCodeRepository;
import it.infn.mw.iam.util.SimpleRandomValueStringGenerator;

@SuppressWarnings("deprecation")
@Service
public class IamDeviceCodeService implements DeviceCodeService {

  private final static SimpleRandomValueStringGenerator randomGenerator = new SimpleRandomValueStringGenerator(6);

  private IamDeviceCodeRepository dcRepository;
  private AuthenticationHolderService authHolderService;

  public IamDeviceCodeService(IamDeviceCodeRepository dcRepository, AuthenticationHolderService authHolderService) {

    this.dcRepository = dcRepository;
    this.authHolderService = authHolderService;
  }

  @Override
  public DeviceCode createNew(Set<String> requestedScopes, ClientDetailsEntity client,
      Map<String, String> parameters) {

    // create a device code, should be big and random
    String deviceCode = UUID.randomUUID().toString();

    // create a user code, should be random but small, type-able, and always upper-case
    String userCode = randomGenerator.generate().toUpperCase();

    DeviceCode dc = new DeviceCode(deviceCode, userCode, requestedScopes, client, parameters);

    return dcRepository.save(dc);
  }

  @Override
  public DeviceCode findByUserCode(String userCode) {

    return dcRepository.findByUserCode(userCode.toUpperCase()).orElse(null);
  }

  @Override
  public DeviceCode approve(DeviceCode dc, OAuth2Authentication auth) {

    DeviceCode approvedDc = dcRepository.getById(dc.getId());
    approvedDc.approve();
    AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity(approvedDc.getClient(), auth);
    authHolder.addDeviceCode(approvedDc);
    approvedDc.setAuthenticationHolder(authHolder);
    return authHolderService.save(authHolder).getDeviceCodes().stream().findFirst().get();
  }

  @Override
  public DeviceCode findByDeviceCode(String deviceCode, ClientDetails client) {

    Optional<DeviceCode> dc = dcRepository.findByDeviceCode(deviceCode);
    if (dc.isPresent() && dc.get().getClient().getClientId().equals(client.getClientId())) {
      return dc.get();
    }
    return null;
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public int clearExpired() {

    Page<DeviceCode> expired = dcRepository.findExpiredDeviceCode(new OffsetPageable(0, 100));
    int found = expired.getContent().size();
    expired.getContent().forEach(dcRepository::delete);
    return found;
  }

  @Override
  public void clearDeviceCode(String deviceCode, ClientDetails client) {

    DeviceCode found = findByDeviceCode(deviceCode, client);
    if (found != null) {
      dcRepository.delete(found);
    }
  }

  @Override
  public DeviceCode update(DeviceCode deviceCode) {

    return dcRepository.save(deviceCode);
  }

}

