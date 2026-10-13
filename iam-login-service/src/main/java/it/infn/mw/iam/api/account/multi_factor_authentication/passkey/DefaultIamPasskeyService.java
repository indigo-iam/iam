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
package it.infn.mw.iam.api.account.multi_factor_authentication.passkey;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.SQLIntegrityConstraintViolationException;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.api.account.multi_factor_authentication.MandatoryFactorException;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyChallenge.Purpose;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRelyingParty.RegistrationResult;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyCeremonyException;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyLimitExceededException;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.PasskeyRegisteredEvent;
import it.infn.mw.iam.audit.events.account.multi_factor_authentication.PasskeyVerifiedEvent;
import it.infn.mw.iam.config.mfa.IamPasskeyProperties;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamPasskeyRepository;

/**
 * Passkey service of an instance where the feature is enabled: runs the WebAuthn ceremonies
 * through the relying party and keeps the credentials in the database
 */
public class DefaultIamPasskeyService extends AbstractIamPasskeyService {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultIamPasskeyService.class);

  public static final int CHALLENGE_SIZE = 32;
  public static final String ATTESTATION_NONE = "none";
  public static final String RESIDENT_KEY_DISCOURAGED = "discouraged";
  public static final String CHALLENGE_MISSING_MESSAGE =
      "No passkey challenge was issued for this session";
  public static final String CHALLENGE_EXPIRED_MESSAGE = "The passkey challenge has expired";
  public static final String CHALLENGE_MISMATCH_MESSAGE =
      "The passkey challenge does not match this ceremony";
  public static final String CREDENTIAL_ALREADY_REGISTERED_MESSAGE =
      "This passkey is already registered";
  public static final String UNKNOWN_CREDENTIAL_MESSAGE =
      "The passkey is not registered on this account";
  public static final String USER_HANDLE_MISMATCH_MESSAGE =
      "The passkey belongs to a different user";
  public static final String LIMIT_EXCEEDED_MESSAGE =
      "The maximum number of passkeys for this account has been reached";
  public static final String UNKNOWN_ACCOUNT_MESSAGE = "Account not found";
  public static final String LAST_PASSKEY_MANDATORY_MESSAGE =
      "Passkeys are mandatory: register another passkey before removing this one";
  public static final String LAST_FACTOR_MANDATORY_MESSAGE =
      "Multi-factor authentication is mandatory: enable another second factor before removing "
          + "this passkey";
  public static final String REMOVAL_PROOF_REQUIRED_MESSAGE =
      "Removing a passkey requires a passkey assertion or, when the authenticator app is active, "
          + "a code from the authenticator app";
  public static final String BAD_REMOVAL_TOTP_MESSAGE =
      "The authenticator app code is not valid";

  private static final long BROWSER_TIMEOUT_MARGIN_SECONDS = 30L;
  private static final long MIN_BROWSER_TIMEOUT_SECONDS = 30L;

  private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+=*");

  private final Clock clock;
  private final SecureRandom secureRandom = new SecureRandom();
  private final IamPasskeyProperties properties;
  private final IamTotpMfaProperties totpMfaProperties;
  private final PasskeyRelyingParty relyingParty;
  private final IamAccountRepository accountRepository;
  private final IamTotpMfaService totpMfaService;

  public DefaultIamPasskeyService(Clock clock, IamPasskeyProperties properties,
      IamTotpMfaProperties totpMfaProperties, PasskeyRelyingParty relyingParty,
      IamPasskeyRepository passkeyRepository, IamAccountRepository accountRepository,
      IamAccountService accountService, IamTotpMfaService totpMfaService,
      NotificationFactory notificationFactory, ApplicationEventPublisher eventPublisher) {
    super(passkeyRepository, accountService, notificationFactory, eventPublisher);
    this.clock = clock;
    this.properties = properties;
    this.totpMfaProperties = totpMfaProperties;
    this.relyingParty = relyingParty;
    this.accountRepository = accountRepository;
    this.totpMfaService = totpMfaService;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

  @Override
  @Transactional(readOnly = true)
  public boolean isPasskeyActive(IamAccount account) {
    return passkeyRepository.countByAccountId(account.getId()) > 0;
  }

  @Override
  public PasskeyChallenge createChallenge(IamAccount account, Purpose purpose) {
    byte[] value = new byte[CHALLENGE_SIZE];
    secureRandom.nextBytes(value);
    Instant expiresAt =
        clock.instant().plus(properties.getChallengeTimeoutSeconds(), ChronoUnit.SECONDS);
    return new PasskeyChallenge(value, purpose, account.getUsername(), expiresAt);
  }

  @Override
  @Transactional(readOnly = true)
  public PasskeyRegistrationOptionsDTO getRegistrationOptions(IamAccount account,
      PasskeyChallenge challenge) {

    checkChallenge(challenge, Purpose.REGISTRATION, account);

    PasskeyRegistrationOptionsDTO options = new PasskeyRegistrationOptionsDTO();
    options.setRp(new PasskeyRegistrationOptionsDTO.RelyingParty(relyingParty.getRpId(),
        relyingParty.getRpName()));
    options.setUser(new PasskeyRegistrationOptionsDTO.User(userHandle(account),
        account.getUsername(), account.getUserInfo().getName()));
    options.setChallenge(PasskeyRelyingParty.encode(challenge.getValue()));
    options.setPubKeyCredParams(relyingParty.getSupportedAlgorithmIdentifiers()
      .stream()
      .map(PasskeyRegistrationOptionsDTO.CredentialParameters::new)
      .collect(Collectors.toList()));
    options.setTimeout(timeoutMillis());
    options.setExcludeCredentials(descriptors(account));
    options.setAuthenticatorSelection(new PasskeyRegistrationOptionsDTO.AuthenticatorSelection(
        RESIDENT_KEY_DISCOURAGED, properties.getUserVerification().getValue()));
    options.setAttestation(ATTESTATION_NONE);
    return options;
  }

  @Override
  @Transactional
  public IamPasskey registerPasskey(IamAccount account, PasskeyChallenge challenge,
      PasskeyRegistrationDTO registration) {

    checkChallenge(challenge, Purpose.REGISTRATION, account);

    // The account row is locked so that concurrent registrations for the same account are
    // serialised and the per-account limit cannot be exceeded
    IamAccount lockedAccount = lockAccount(account);

    if (passkeyRepository.countByAccountId(lockedAccount.getId()) >= properties
      .getMaxCredentialsPerAccount()) {
      throw new PasskeyLimitExceededException(LIMIT_EXCEEDED_MESSAGE);
    }

    RegistrationResult result = relyingParty.verifyRegistration(challenge.getValue(), registration);

    if (passkeyRepository.findByCredentialId(result.getCredentialId()).isPresent()) {
      throw new PasskeyCeremonyException(CREDENTIAL_ALREADY_REGISTERED_MESSAGE);
    }

    IamPasskey passkey = new IamPasskey(clock.instant(), lockedAccount);
    passkey.setUuid(UUID.randomUUID().toString());
    passkey.setLabel(registration.getLabel().trim());
    passkey.setCredentialId(result.getCredentialId());
    passkey.setAttestedCredentialData(result.getAttestedCredentialData());
    passkey.setAaguid(result.getAaguid());
    passkey.setSignCount(result.getSignCount());
    passkey.setTransports(PasskeyTransports.toColumn(result.getTransports()));

    try {
      // The credential id is unique across accounts: a concurrent registration of the same
      // credential on another account is rejected by the database
      passkey = passkeyRepository.saveAndFlush(passkey);
    } catch (DataAccessException e) {
      if (isConstraintViolation(e)) {
        throw new PasskeyCeremonyException(CREDENTIAL_ALREADY_REGISTERED_MESSAGE, e);
      }
      throw e;
    }

    saveAccount(lockedAccount);
    eventPublisher.publishEvent(new PasskeyRegisteredEvent(this, lockedAccount, passkey));
    notificationFactory.createPasskeyRegisteredMessage(lockedAccount, passkey);

    LOG.info("Passkey '{}' registered for account '{}'", passkey.getLabel(),
        lockedAccount.getUsername());
    return passkey;
  }

  @Override
  @Transactional(readOnly = true)
  public PasskeyAssertionOptionsDTO getAssertionOptions(IamAccount account,
      PasskeyChallenge challenge) {

    checkChallenge(challenge, account);
    if (!challenge.getPurpose().isAssertion()) {
      throw new PasskeyCeremonyException(CHALLENGE_MISMATCH_MESSAGE);
    }

    PasskeyAssertionOptionsDTO options = new PasskeyAssertionOptionsDTO();
    options.setChallenge(PasskeyRelyingParty.encode(challenge.getValue()));
    options.setRpId(relyingParty.getRpId());
    options.setTimeout(timeoutMillis());
    options.setAllowCredentials(descriptors(account));
    options.setUserVerification(properties.getUserVerification().getValue());
    return options;
  }

  @Override
  @Transactional
  public IamPasskey verifyPasskey(IamAccount account, PasskeyChallenge challenge,
      PasskeyAssertionDTO assertion) {
    return verifyAssertion(account, challenge, Purpose.AUTHENTICATION, assertion);
  }

  @Override
  @Transactional
  public IamPasskey removePasskey(IamAccount account, String passkeyUuid,
      PasskeyChallenge challenge, PasskeyRemovalDTO proof) {

    // The account row is locked before anything is read: under a mandatory policy two concurrent
    // removals (or a removal and a disabling of the authenticator app) must not both see a
    // surviving factor, and in general every writer takes the account lock before a credential
    // row lock, so that two removals proving each other cannot deadlock
    lockAccount(account);

    IamPasskey passkey = findPasskey(account, passkeyUuid);
    checkNotLastMandatoryFactor(account);
    checkRemovalProof(account, challenge, proof);
    deletePasskey(account, passkey);
    return passkey;
  }

  /**
   * When passkeys are mandatory the user must keep one; when a second factor of any kind is
   * mandatory the user must keep one factor, and the authenticator app counts
   */
  private void checkNotLastMandatoryFactor(IamAccount account) {
    if (properties.isMandatory()) {
      if (passkeyRepository.countByAccountId(account.getId()) <= 1) {
        throw new MandatoryFactorException(LAST_PASSKEY_MANDATORY_MESSAGE);
      }
    } else if (totpMfaProperties.isMultiFactorMandatory()
        && passkeyRepository.countByAccountId(account.getId()) <= 1
        && !totpMfaService.isAuthenticatorAppActive(account)) {
      throw new MandatoryFactorException(LAST_FACTOR_MANDATORY_MESSAGE);
    }
  }

  /**
   * A passkey can only be removed by someone holding a second factor of the account: a stolen
   * session must not be enough to downgrade the account to the password alone. The assertion may
   * come from any registered passkey, including the one being removed. The authenticator app is
   * accepted as proof only where it is accepted at login, i.e. unless passkeys are mandatory
   */
  private void checkRemovalProof(IamAccount account, PasskeyChallenge challenge,
      PasskeyRemovalDTO proof) {
    if (proof != null && proof.hasAssertion()) {
      verifyAssertion(account, challenge, Purpose.REMOVAL, proof.getAssertion());
      return;
    }
    if (proof != null && proof.hasTotp() && !properties.isMandatory()
        && totpMfaService.isAuthenticatorAppActive(account)) {
      if (!verifyTotp(account, proof.getTotp().trim())) {
        throw new PasskeyCeremonyException(BAD_REMOVAL_TOTP_MESSAGE);
      }
      return;
    }
    throw new PasskeyCeremonyException(REMOVAL_PROOF_REQUIRED_MESSAGE);
  }

  private boolean verifyTotp(IamAccount account, String totp) {
    try {
      return totpMfaService.verifyTotp(account, totp);
    } catch (MfaSecretNotFoundException e) {
      // The authenticator app was reset between the check above and the verification
      throw new PasskeyCeremonyException(REMOVAL_PROOF_REQUIRED_MESSAGE, e);
    }
  }

  private IamPasskey verifyAssertion(IamAccount account, PasskeyChallenge challenge,
      Purpose purpose, PasskeyAssertionDTO assertion) {

    checkChallenge(challenge, purpose, account);

    // The credential row is locked for the whole verification so that concurrent assertions
    // for the same credential see each other's signature counter update
    IamPasskey passkey = passkeyRepository
      .findByCredentialIdForUpdate(normaliseCredentialId(assertion.getId()))
      .filter(p -> p.getAccount().getId().equals(account.getId()))
      .orElseThrow(() -> new PasskeyCeremonyException(UNKNOWN_CREDENTIAL_MESSAGE));

    String userHandle = assertion.getResponse().getUserHandle();
    if (userHandle != null && !userHandle.isEmpty() && !userHandle.equals(userHandle(account))) {
      throw new PasskeyCeremonyException(USER_HANDLE_MISMATCH_MESSAGE);
    }

    long signCount = relyingParty.verifyAssertion(challenge.getValue(), assertion,
        passkey.getCredentialId(), passkey.getAttestedCredentialData(), passkey.getSignCount(),
        PasskeyTransports.toList(passkey.getTransports()));

    passkey.setSignCount(signCount);
    passkey.touchLastUsed(clock.instant());
    passkey = passkeyRepository.save(passkey);

    eventPublisher.publishEvent(new PasskeyVerifiedEvent(this, account, passkey));
    return passkey;
  }

  private IamAccount lockAccount(IamAccount account) {
    return accountRepository.findByIdForUpdate(account.getId())
      .orElseThrow(() -> new PasskeyCeremonyException(UNKNOWN_ACCOUNT_MESSAGE));
  }

  private void checkChallenge(PasskeyChallenge challenge, Purpose purpose, IamAccount account) {
    checkChallenge(challenge, account);
    if (challenge.getPurpose() != purpose) {
      throw new PasskeyCeremonyException(CHALLENGE_MISMATCH_MESSAGE);
    }
  }

  private void checkChallenge(PasskeyChallenge challenge, IamAccount account) {
    if (challenge == null) {
      throw new PasskeyCeremonyException(CHALLENGE_MISSING_MESSAGE);
    }
    if (!challenge.getUsername().equals(account.getUsername())) {
      throw new PasskeyCeremonyException(CHALLENGE_MISMATCH_MESSAGE);
    }
    if (challenge.isExpired(clock.instant())) {
      throw new PasskeyCeremonyException(CHALLENGE_EXPIRED_MESSAGE);
    }
  }

  private List<PasskeyCredentialDescriptorDTO> descriptors(IamAccount account) {
    return passkeyRepository.findByAccountId(account.getId())
      .stream()
      .map(p -> new PasskeyCredentialDescriptorDTO(p.getCredentialId(),
          PasskeyTransports.toList(p.getTransports())))
      .collect(Collectors.toList());
  }

  private long timeoutMillis() {
    // The browser is given less than the challenge lifetime, so that an assertion produced at the
    // very end of the prompt still finds its challenge valid on the server; a lifetime too short
    // to leave the full margin is split instead
    long lifetime = properties.getChallengeTimeoutSeconds();
    long browserTimeout = Math.max(MIN_BROWSER_TIMEOUT_SECONDS,
        lifetime - BROWSER_TIMEOUT_MARGIN_SECONDS);
    return Math.min(lifetime, browserTimeout) * 1000L;
  }

  /**
   * EclipseLink reports a unique constraint violation as a generic JpaSystemException rather than
   * as a DataIntegrityViolationException, so the SQL cause chain is inspected as well
   */
  private static boolean isConstraintViolation(DataAccessException e) {
    if (e instanceof DataIntegrityViolationException) {
      return true;
    }
    for (Throwable cause = e.getCause(); cause != null
        && cause != cause.getCause(); cause = cause.getCause()) {
      if (cause instanceof SQLIntegrityConstraintViolationException) {
        return true;
      }
    }
    return false;
  }

  private static String userHandle(IamAccount account) {
    return PasskeyRelyingParty.encode(account.getUuid().getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Credential ids are stored unpadded; tolerate padded base64url from non-browser clients. The
   * column is ASCII, so anything else is refused before it reaches the database
   */
  private static String normaliseCredentialId(String credentialId) {
    if (credentialId == null || !BASE64URL.matcher(credentialId).matches()) {
      throw new PasskeyCeremonyException(UNKNOWN_CREDENTIAL_MESSAGE);
    }
    int end = credentialId.length();
    while (end > 0 && credentialId.charAt(end - 1) == '=') {
      end--;
    }
    return credentialId.substring(0, end);
  }
}
