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
package it.infn.mw.iam.core.oauth.device;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.core.IamAuthenticationHolderService;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.DeviceCode;
import it.infn.mw.iam.persistence.repository.IamDeviceCodeRepository;

@SuppressWarnings("deprecation")
@Service
public class IamDeviceCodeService implements DeviceCodeService {

  private final Clock clock;
  private final IamDeviceCodeRepository codeRepository;
  private final SecureRandom random;
  private final IamAuthenticationHolderService authHolderService;

  public IamDeviceCodeService(Clock clock, IamDeviceCodeRepository codeRepository,
      SecureRandom random, IamAuthenticationHolderService authHolderService) {
    this.clock = clock;
    this.codeRepository = codeRepository;
    this.random = random;
    this.authHolderService = authHolderService;
  }

  @Override
  public Optional<DeviceCode> findByUserCode(String userCode) {

    return codeRepository.findByUserCode(userCode);
  }

  @Override
  public DeviceCode approveDeviceCode(DeviceCode dc, OAuth2Authentication o2Auth) {

    dc.setApproved(true);
    AuthenticationHolderEntity authHolder = authHolderService.createAndSave(o2Auth, dc.getClient());
    dc.setAuthenticationHolder(authHolder);
    return codeRepository.save(dc);
  }

  @Override
  public Optional<DeviceCode> findByDeviceCodeAndClientId(String deviceCode, String clientId) {

    return codeRepository.findByDeviceCodeAndClient_ClientId(deviceCode, clientId);
  }

  @Override
  public void clearDeviceCode(DeviceCode dc) {

    codeRepository.findById(dc.getId()).ifPresent(codeRepository::delete);
  }

  private String generateToken() {

    byte[] bytes = new byte[6];
    random.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  @Override
  public DeviceCode createNewDeviceCode(Set<String> requestedScopes, ClientDetailsEntity client,
      Map<String, String> parameters) {

    String deviceCode = UUID.randomUUID().toString();
    String userCode = generateToken().toUpperCase();
    DeviceCode dc = new DeviceCode(deviceCode, userCode, requestedScopes, client, parameters);

    if (client.getDeviceCodeValiditySeconds() != null) {
      Date expiration =
          Date.from(clock.instant().plusSeconds(client.getDeviceCodeValiditySeconds()));
      dc.setExpiration(expiration);
    }
    dc.setApproved(false);

    return codeRepository.save(dc);

  }
}
