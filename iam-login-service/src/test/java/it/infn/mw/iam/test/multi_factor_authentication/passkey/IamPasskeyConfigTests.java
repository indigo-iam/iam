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
package it.infn.mw.iam.test.multi_factor_authentication.passkey;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.DefaultIamPasskeyService;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.DisabledIamPasskeyService;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.IamPasskeyService;
import it.infn.mw.iam.config.IamPasskeyConfig;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.Organisation;
import it.infn.mw.iam.config.mfa.IamPasskeyProperties;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamPasskeyRepository;

@ExtendWith(MockitoExtension.class)
class IamPasskeyConfigTests {

  @Mock
  IamProperties iamProperties;

  @Mock
  Organisation organisation;

  @Mock
  IamPasskeyRepository passkeyRepository;

  @Mock
  IamAccountRepository accountRepository;

  @Mock
  IamAccountService accountService;

  @Mock
  NotificationFactory notificationFactory;

  @Mock
  ApplicationEventPublisher eventPublisher;

  @Mock
  IamTotpMfaService totpMfaService;

  IamPasskeyConfig config = new IamPasskeyConfig();
  IamPasskeyProperties properties;
  IamTotpMfaProperties totpMfaProperties = new IamTotpMfaProperties();
  Clock clock = Clock.systemUTC();

  @BeforeEach
  void setup() {
    properties = new IamPasskeyProperties();
    lenient().when(iamProperties.getBaseUrl()).thenReturn("https://iam.example.org");
    lenient().when(iamProperties.getOrganisation()).thenReturn(organisation);
    lenient().when(organisation.getName()).thenReturn("Example");
  }

  private IamPasskeyService service() {
    return config.passkeyService(clock, properties, totpMfaProperties, iamProperties,
        passkeyRepository, accountRepository, accountService, totpMfaService,
        notificationFactory, eventPublisher);
  }

  @Test
  void disabledByDefault() {
    assertThat(service(), instanceOf(DisabledIamPasskeyService.class));
  }

  @Test
  void disabledWithRegisteredPasskeysStillBoots() {
    when(passkeyRepository.count()).thenReturn(3L);
    assertThat(service(), instanceOf(DisabledIamPasskeyService.class));
  }

  @Test
  void enabledWithDefaultsDerivedFromBaseUrl() {
    properties.setEnabled(true);
    assertThat(service(), instanceOf(DefaultIamPasskeyService.class));
  }

  @Test
  void enabledWithExplicitRpIdAndOrigins() {
    properties.setEnabled(true);
    properties.setRpId("example.org");
    properties.setRpName("My org");
    properties.setAllowedOrigins(List.of("https://login.example.org", " https://other.example.org:8443 ", ""));
    assertThat(service(), instanceOf(DefaultIamPasskeyService.class));
  }

  @Test
  void enabledAndMandatory() {
    properties.setEnabled(true);
    properties.setMandatory(true);
    assertThat(service(), instanceOf(DefaultIamPasskeyService.class));
  }

  @Test
  void mandatoryWithoutEnabledIsRejected() {
    properties.setMandatory(true);
    IllegalStateException e = assertThrows(IllegalStateException.class, this::service);
    assertThat(e.getMessage(), containsString("mandatory"));
  }

  @Test
  void rpIdNotMatchingBaseUrlHostIsRejected() {
    properties.setEnabled(true);
    properties.setRpId("example.com");
    IllegalStateException e = assertThrows(IllegalStateException.class, this::service);
    assertThat(e.getMessage(), containsString("rp-id"));
  }

  @Test
  void rpIdThatIsOnlyASuffixSubstringIsRejected() {
    properties.setEnabled(true);
    properties.setRpId("ample.org");
    assertThrows(IllegalStateException.class, this::service);
  }

  @Test
  void originOutsideRelyingPartyIsRejected() {
    properties.setEnabled(true);
    properties.setAllowedOrigins(List.of("https://evil.example.com"));
    IllegalStateException e = assertThrows(IllegalStateException.class, this::service);
    assertThat(e.getMessage(), containsString("allowed-origins"));
  }

  @Test
  void originWithoutSchemeIsRejected() {
    properties.setEnabled(true);
    properties.setAllowedOrigins(List.of("//iam.example.org"));
    IllegalStateException e = assertThrows(IllegalStateException.class, this::service);
    assertThat(e.getMessage(), containsString("http(s) origin"));
  }

  @Test
  void invalidOriginIsRejected() {
    properties.setEnabled(true);
    properties.setAllowedOrigins(List.of("not a url"));
    assertThrows(IllegalStateException.class, this::service);
  }

  @Test
  void baseUrlWithoutHostIsRejected() {
    properties.setEnabled(true);
    when(iamProperties.getBaseUrl()).thenReturn("iam");
    IllegalStateException e = assertThrows(IllegalStateException.class, this::service);
    assertThat(e.getMessage(), containsString("iam.baseUrl"));
  }
}
