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
package it.infn.mw.iam.config;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.util.LinkedHashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.DefaultIamPasskeyService;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.DisabledIamPasskeyService;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.IamPasskeyService;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRelyingParty;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorPasskeyCheckProvider;
import it.infn.mw.iam.config.mfa.IamPasskeyProperties;
import it.infn.mw.iam.config.mfa.IamPasskeyProperties.UserVerification;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamPasskeyRepository;

/**
 * Beans for handling passkey (WebAuthn) MFA functionality
 */
@Configuration
public class IamPasskeyConfig {

  private static final Logger LOG = LoggerFactory.getLogger(IamPasskeyConfig.class);

  @Bean
  public IamPasskeyService passkeyService(Clock clock, IamPasskeyProperties passkeyProperties,
      IamTotpMfaProperties totpMfaProperties, IamProperties iamProperties,
      IamPasskeyRepository passkeyRepository, IamAccountRepository accountRepository,
      IamAccountService accountService, IamTotpMfaService totpMfaService,
      NotificationFactory notificationFactory, ApplicationEventPublisher eventPublisher) {

    if (!passkeyProperties.isEnabled()) {
      if (passkeyProperties.isMandatory()) {
        throw new IllegalStateException(
            "mfa.passkey.mandatory requires mfa.passkey.enabled to be true");
      }
      // Passkeys registered while the feature was on are not accepted at login until it is
      // switched on again; they stay visible and removable in the meantime
      long stored = passkeyRepository.count();
      if (stored > 0) {
        LOG.warn("[PASSKEY] Passkey MFA is disabled, but {} passkey(s) are registered: they are "
            + "not accepted as second factor until mfa.passkey.enabled is set to true", stored);
      } else {
        LOG.info("[PASSKEY] Passkey MFA is disabled");
      }
      return new DisabledIamPasskeyService(passkeyRepository, accountService,
          notificationFactory, eventPublisher);
    }

    URI baseUrl = parseBaseUrl(iamProperties.getBaseUrl());
    String rpId = resolveRpId(passkeyProperties, baseUrl);
    Set<String> origins = resolveOrigins(passkeyProperties, baseUrl, rpId);
    String rpName = isBlank(passkeyProperties.getRpName())
        ? iamProperties.getOrganisation().getName()
        : passkeyProperties.getRpName();

    PasskeyRelyingParty relyingParty = new PasskeyRelyingParty(origins, rpId, rpName,
        UserVerification.REQUIRED.equals(passkeyProperties.getUserVerification()));

    LOG.info("[PASSKEY] Passkey MFA enabled: rpId={}, origins={}, userVerification={}, "
        + "mandatory={}", rpId, origins, passkeyProperties.getUserVerification().getValue(),
        passkeyProperties.isMandatory());

    return new DefaultIamPasskeyService(clock, passkeyProperties, totpMfaProperties,
        relyingParty, passkeyRepository, accountRepository, accountService, totpMfaService,
        notificationFactory, eventPublisher);
  }

  @Bean
  MultiFactorPasskeyCheckProvider passkeyCheckProvider(IamAccountRepository accountRepo,
      IamPasskeyService passkeyService) {
    return new MultiFactorPasskeyCheckProvider(accountRepo, passkeyService);
  }

  private URI parseBaseUrl(String baseUrl) {
    try {
      URI uri = new URI(baseUrl);
      if (isBlank(uri.getHost())) {
        throw new IllegalStateException("iam.baseUrl does not contain a host: " + baseUrl);
      }
      return uri;
    } catch (URISyntaxException e) {
      throw new IllegalStateException("iam.baseUrl is not a valid URI: " + baseUrl, e);
    }
  }

  private String resolveRpId(IamPasskeyProperties properties, URI baseUrl) {
    String rpId = isBlank(properties.getRpId()) ? baseUrl.getHost().toLowerCase()
        : properties.getRpId().trim().toLowerCase();

    if (!isValidRpId(rpId, baseUrl.getHost())) {
      throw new IllegalStateException(String.format(
          "mfa.passkey.rp-id '%s' must be equal to, or a registrable domain suffix of, "
              + "the iam.baseUrl host '%s'",
          rpId, baseUrl.getHost()));
    }
    return rpId;
  }

  private Set<String> resolveOrigins(IamPasskeyProperties properties, URI baseUrl, String rpId) {
    Set<String> origins = new LinkedHashSet<>();
    origins.add(originOf(baseUrl));

    for (String configured : properties.getAllowedOrigins()) {
      if (isBlank(configured)) {
        continue;
      }
      URI uri;
      try {
        uri = new URI(configured.trim());
      } catch (URISyntaxException e) {
        throw new IllegalStateException(
            "mfa.passkey.allowed-origins contains an invalid URI: " + configured, e);
      }
      if (!isWebOrigin(uri)) {
        throw new IllegalStateException(String.format(
            "mfa.passkey.allowed-origins entry '%s' is not an http(s) origin", configured));
      }
      if (!isValidRpId(rpId, uri.getHost())) {
        throw new IllegalStateException(String.format(
            "mfa.passkey.allowed-origins entry '%s' is not within the Relying Party ID '%s'",
            configured, rpId));
      }
      origins.add(originOf(uri));
    }
    return origins;
  }

  private static boolean isWebOrigin(URI uri) {
    return uri.getScheme() != null && !isBlank(uri.getHost())
        && ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()));
  }

  private static String originOf(URI uri) {
    StringBuilder sb = new StringBuilder();
    sb.append(uri.getScheme().toLowerCase()).append("://").append(uri.getHost().toLowerCase());
    if (uri.getPort() != -1) {
      sb.append(':').append(uri.getPort());
    }
    return sb.toString();
  }

  private static boolean isBlank(String value) {
    return value == null || value.isBlank();
  }

  private static boolean isValidRpId(String rpId, String host) {
    String h = host.toLowerCase();
    return h.equals(rpId) || h.endsWith("." + rpId);
  }
}
