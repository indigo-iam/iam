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

import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.DeviceCode;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.persistence.repository.IamDeviceCodeRepository;

@SuppressWarnings("deprecation")
@Service
public class IamDeviceCodeService implements DeviceCodeService {

  private final Clock clock;
  private final IamDeviceCodeRepository codeRepository;
  private final SecureRandom random;

  public IamDeviceCodeService(Clock clock, IamDeviceCodeRepository codeRepository,
      SecureRandom random) {
    this.clock = clock;
    this.codeRepository = codeRepository;
    this.random = random;
  }

  @Override
  public Optional<DeviceCode> findByUserCode(String userCode) {

    return codeRepository.findByUserCode(userCode);
  }

  @Override
  public DeviceCode approveDeviceCode(DeviceCode dc, OAuth2Authentication o2Auth) {

    dc.setApproved(true);
    AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity();
    authHolder.setAuthentication(o2Auth);
    dc.setAuthenticationHolder(authHolder);
    return codeRepository.save(dc);
  }

  @Override
  public Optional<DeviceCode> findByDeviceCodeAndClient(String deviceCode, ClientDetails client) {

    return codeRepository.findByDeviceCodeAndClientId(deviceCode, client.getClientId());
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
    DeviceCode dc =
        new DeviceCode(deviceCode, userCode, requestedScopes, client.getClientId(), parameters);

    if (client.getDeviceCodeValiditySeconds() != null) {
      Date expiration =
          Date.from(clock.instant().plusSeconds(client.getDeviceCodeValiditySeconds()));
      dc.setExpiration(expiration);
    }
    dc.setApproved(false);

    return codeRepository.save(dc);

  }
}
