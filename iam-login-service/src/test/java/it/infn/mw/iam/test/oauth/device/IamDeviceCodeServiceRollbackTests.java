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
package it.infn.mw.iam.test.oauth.device;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.oauth.device.IamDeviceCodeService;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.DeviceCode;
import it.infn.mw.iam.persistence.repository.IamAuthenticationHolderRepository;
import it.infn.mw.iam.persistence.repository.IamDeviceCodeRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;

@SuppressWarnings("deprecation")
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
class IamDeviceCodeServiceRollbackTests {

  private static final String CLIENT_ID = "password-grant";

  @Autowired
  IamDeviceCodeService deviceCodeService;

  @Autowired
  IamAuthenticationHolderRepository authenticationHolderRepo;

  @Autowired
  IamClientRepository clientRepository;

  @SpyBean
  IamDeviceCodeRepository deviceCodeRepository;

  @Test
  void failedDeviceCodeApprovalRollsBackAuthenticationHolder() {

    ClientDetailsEntity client = clientRepository.findByClientId(CLIENT_ID).orElseThrow();
    client.setDeviceCodeValiditySeconds(600);
    DeviceCode deviceCode =
        deviceCodeService.createNewDeviceCode(Set.of("openid"), client, Map.of());

    Long deviceCodeId = deviceCode.getId();
    long holderCountBefore = authenticationHolderRepo.count();

    OAuth2Request request = new OAuth2Request(Map.of(), CLIENT_ID, null, true, Set.of("openid"),
        null, null, null, null);
    OAuth2Authentication authentication = new OAuth2Authentication(request, null);

    try {
      doThrow(new IllegalStateException("Simulated device code save failure"))
        .when(deviceCodeRepository)
        .save(any(DeviceCode.class));

      assertThrows(IllegalStateException.class,
          () -> deviceCodeService.approveDeviceCode(deviceCode, authentication));

      assertEquals(holderCountBefore, authenticationHolderRepo.count(),
          "The authentication holder must be rolled back if device code approval fails");

      DeviceCode persisted = deviceCodeRepository.findById(deviceCodeId).orElseThrow();
      assertFalse(persisted.isApproved(), "The device code must remain unapproved");
      assertNull(persisted.getAuthenticationHolder(),
          "A failed approval must not associate an authentication holder");
    } finally {
      reset(deviceCodeRepository);
      deviceCodeRepository.findById(deviceCodeId).ifPresent(deviceCodeRepository::delete);
    }
  }
}
