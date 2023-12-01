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
package it.infn.mw.iam.core.user;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Strings.isNullOrEmpty;
import static it.infn.mw.iam.core.lifecycle.ExpiredAccountsHandler.LIFECYCLE_STATUS_LABEL;
import static java.util.Objects.isNull;

import java.time.Clock;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.audit.events.account.AccountCreatedEvent;
import it.infn.mw.iam.audit.events.account.AccountDisabledEvent;
import it.infn.mw.iam.audit.events.account.AccountEndTimeUpdatedEvent;
import it.infn.mw.iam.audit.events.account.AccountRemovedEvent;
import it.infn.mw.iam.audit.events.account.AccountRestoredEvent;
import it.infn.mw.iam.audit.events.account.attribute.AccountAttributeRemovedEvent;
import it.infn.mw.iam.audit.events.account.attribute.AccountAttributeSetEvent;
import it.infn.mw.iam.audit.events.account.group.GroupMembershipAddedEvent;
import it.infn.mw.iam.audit.events.account.group.GroupMembershipRemovedEvent;
import it.infn.mw.iam.audit.events.account.label.AccountLabelRemovedEvent;
import it.infn.mw.iam.audit.events.account.label.AccountLabelSetEvent;
import it.infn.mw.iam.core.user.exception.CredentialAlreadyBoundException;
import it.infn.mw.iam.core.user.exception.InvalidCredentialException;
import it.infn.mw.iam.core.user.exception.UserAlreadyExistsException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountGroupMembership;
import it.infn.mw.iam.persistence.model.IamAttribute;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;

@Service
@Transactional
public class DefaultIamAccountService implements IamAccountService, ApplicationEventPublisherAware {

  private final Clock clock;
  private final IamAccountRepository accountRepo;
  private final IamGroupRepository groupRepo;
  private final IamAuthoritiesRepository authoritiesRepo;
  private final PasswordEncoder passwordEncoder;
  private ApplicationEventPublisher eventPublisher;
  private final OAuth2TokenEntityService tokenService;
  private final IamAccountClientRepository accountClientRepo;

  @Autowired
  public DefaultIamAccountService(Clock clock, IamAccountRepository accountRepo,
      IamGroupRepository groupRepo, IamAuthoritiesRepository authoritiesRepo,
      PasswordEncoder passwordEncoder, ApplicationEventPublisher eventPublisher,
      OAuth2TokenEntityService tokenService, IamAccountClientRepository accountClientRepo) {

    this.clock = clock;
    this.accountRepo = accountRepo;
    this.groupRepo = groupRepo;
    this.authoritiesRepo = authoritiesRepo;
    this.passwordEncoder = passwordEncoder;
    this.eventPublisher = eventPublisher;
    this.tokenService = tokenService;
    this.accountClientRepo = accountClientRepo;
  }

  private void labelSetEvent(IamAccount account, IamLabel label) {
    eventPublisher.publishEvent(new AccountLabelSetEvent(this, account, label));
  }

  private void accountAddedToGroupEvent(IamAccount account, IamGroup group) {
    eventPublisher.publishEvent(new GroupMembershipAddedEvent(this, account, group));
  }

  private void accountRemovedFromGroupEvent(IamAccount account, IamGroup group) {
    eventPublisher.publishEvent(new GroupMembershipRemovedEvent(this, account, group));
  }

  private void labelRemovedEvent(IamAccount account, IamLabel label) {
    eventPublisher.publishEvent(new AccountLabelRemovedEvent(this, account, label));
  }

  private void attributeSetEvent(IamAccount account, IamAttribute attribute) {
    eventPublisher.publishEvent(new AccountAttributeSetEvent(this, account, attribute));
  }

  private void attributeRemovedEvent(IamAccount account, IamAttribute attribute) {
    eventPublisher.publishEvent(new AccountAttributeRemovedEvent(this, account, attribute));
  }

  @Override
  public IamAccount createAccount(IamAccount account) {
    checkNotNull(account, "Cannot create a null account");

    final Date now = Date.from(clock.instant());
    final String randomUuid = UUID.randomUUID().toString();

    newAccountSanityChecks(account);

    if (account.getCreationTime() == null) {
      account.setCreationTime(now);
    }

    if (account.getUuid() == null) {
      account.setUuid(randomUuid);
    }

    account.setLastUpdateTime(now);

    account.getUserInfo().setEmailVerified(true);

    if (account.getPassword() == null) {
      account.setPassword(UUID.randomUUID().toString());
    }

    account.setPassword(passwordEncoder.encode(account.getPassword()));

    IamAuthority roleUserAuthority = authoritiesRepo.findByAuthority("ROLE_USER")
      .orElseThrow(
          () -> new IllegalStateException("ROLE_USER not found in database. This is a bug"));

    account.getAuthorities().add(roleUserAuthority);

    // Credentials sanity checks
    newAccountX509CertificatesSanityChecks(account);
    newAccountSshKeysSanityChecks(account);
    newAccountSamlIdsSanityChecks(account);
    newAccountOidcIdsSanityChecks(account);

    // Set creation time for certificates
    account.getX509Certificates().forEach(c -> {
      c.setCreationTime(now);
      c.setLastUpdateTime(now);
    });

    account.getSshKeys().forEach(c -> {
      c.setCreationTime(now);
      c.setLastUpdateTime(now);
    });

    accountRepo.save(account);

    eventPublisher.publishEvent(new AccountCreatedEvent(this, account,
        "Account created for user " + account.getUsername()));

    return account;
  }

  protected void removeClientLinks(IamAccount account) {

    accountClientRepo.deleteByAccount(account);

  }


  protected void deleteTokensForAccount(IamAccount account) {

    Set<OAuth2AccessTokenEntity> accessTokens =
        tokenService.getAllAccessTokensForUser(account.getUsername());

    Set<OAuth2RefreshTokenEntity> refreshTokens =
        tokenService.getAllRefreshTokensForUser(account.getUsername());

    for (OAuth2AccessTokenEntity t : accessTokens) {
      tokenService.revokeAccessToken(t);
    }

    for (OAuth2RefreshTokenEntity t : refreshTokens) {
      tokenService.revokeRefreshToken(t);
    }
  }

  @Override
  public IamAccount deleteAccount(IamAccount account) {
    checkNotNull(account, "cannot delete a null account");
    deleteTokensForAccount(account);
    removeClientLinks(account);
    accountRepo.delete(account);

    eventPublisher.publishEvent(new AccountRemovedEvent(this, account,
        "Removed account for user " + account.getUsername()));

    return account;
  }

  private void newAccountOidcIdsSanityChecks(IamAccount account) {
    account.getOidcIds().forEach(this::oidcIdSanityChecks);
  }


  private void newAccountSamlIdsSanityChecks(IamAccount account) {
    account.getSamlIds().forEach(this::samlIdSanityChecks);
  }

  private void newAccountSanityChecks(IamAccount account) {
    checkArgument(!isNullOrEmpty(account.getUsername()), "Null or empty username");
    checkNotNull(account.getUserInfo(), "Null userinfo object");
    checkArgument(!isNullOrEmpty(account.getUserInfo().getEmail()), "Null or empty email");

    accountRepo.findByUsername(account.getUsername()).ifPresent(a -> {
      throw new UserAlreadyExistsException(
          String.format("A user with username '%s' already exists", a.getUsername()));
    });

    accountRepo.findByEmail(account.getUserInfo().getEmail()).ifPresent(a -> {
      throw new UserAlreadyExistsException(String
        .format("A user linked with email '%s' already exists", a.getUserInfo().getEmail()));
    });

  }

  private void newAccountSshKeysSanityChecks(IamAccount account) {

    if (account.hasSshKeys()) {

      account.getSshKeys().forEach(this::sshKeySanityChecks);

      final long count = account.getSshKeys().stream().filter(IamSshKey::isPrimary).count();

      if (count > 1) {
        throw new InvalidCredentialException("Only one SSH key can be marked as primary");
      }

      if (count == 0) {
        account.getSshKeys().stream().findFirst().ifPresent(k -> k.setPrimary(true));
      }
    }
  }

  private void newAccountX509CertificatesSanityChecks(IamAccount account) {

    if (account.hasX509Certificates()) {

      account.getX509Certificates().forEach(this::x509CertificateSanityCheck);

      final long count =
          account.getX509Certificates().stream().filter(IamX509Certificate::isPrimary).count();

      if (count > 1) {
        throw new InvalidCredentialException("Only one X.509 certificate can be marked as primary");
      }

      if (count == 0) {
        account.getX509Certificates().stream().findFirst().ifPresent(c -> c.setPrimary(true));
      }
    }

  }

  private void oidcIdSanityChecks(IamOidcId oidcId) {
    checkNotNull(oidcId, "null oidc id");
    checkArgument(!isNullOrEmpty(oidcId.getIssuer()), "null or empty oidc id issuer");
    checkArgument(!isNullOrEmpty(oidcId.getSubject()), "null or empty oidc id subject");

    accountRepo.findByOidcId(oidcId.getIssuer(), oidcId.getSubject()).ifPresent(account -> {

      throw new CredentialAlreadyBoundException(String.format(
          "OIDC id '%s,%s' is already bound to a user", oidcId.getIssuer(), oidcId.getSubject()));
    });
  }

  private void samlIdSanityChecks(IamSamlId samlId) {

    checkNotNull(samlId, "null saml id");

    checkArgument(!isNullOrEmpty(samlId.getIdpId()), "null or empty idpId");
    checkArgument(!isNullOrEmpty(samlId.getUserId()), "null or empty userId");
    checkArgument(!isNullOrEmpty(samlId.getAttributeId()), "null or empty attributeId");

    accountRepo.findBySamlId(samlId).ifPresent(account -> {
      throw new CredentialAlreadyBoundException(
          String.format("SAML id '%s,%s,%s' already bound to a user", samlId.getIdpId(),
              samlId.getAttributeId(), samlId.getUserId()));
    });
  }

  private void sshKeySanityChecks(IamSshKey sshKey) {

    checkNotNull(sshKey, "null ssh key");
    checkArgument(!isNullOrEmpty(sshKey.getValue()), "null or empty ssh key value");

    accountRepo.findBySshKeyValue(sshKey.getValue()).ifPresent(account -> {
      throw new CredentialAlreadyBoundException(
          String.format("SSH key '%s' already bound to a user", sshKey.getValue()));
    });
  }

  private void x509CertificateSanityCheck(IamX509Certificate cert) {
    checkNotNull(cert, "null X.509 certificate");
    checkArgument(!isNullOrEmpty(cert.getSubjectDn()),
        "null or empty X.509 certificate subject DN");
    checkArgument(!isNullOrEmpty(cert.getIssuerDn()), "null or empty X.509 certificate issuer DN");
    checkArgument(!isNullOrEmpty(cert.getLabel()), "null or empty X.509 certificate label");

    accountRepo.findByCertificateSubject(cert.getSubjectDn()).ifPresent(c -> {
      throw new CredentialAlreadyBoundException(
          String.format("X509 certificate with subject '%s' is already bound to another user",
              cert.getSubjectDn()));
    });
  }

  @Override
  public List<IamAccount> deleteInactiveProvisionedUsersSinceTime(Date timestamp) {
    checkNotNull(timestamp, "null timestamp");

    List<IamAccount> accounts =
        accountRepo.findProvisionedAccountsWithLastLoginTimeBeforeTimestamp(timestamp);

    accounts.forEach(this::deleteAccount);

    return accounts;
  }

  @Override
  public Optional<IamAccount> findByUuid(String uuid) {
    return accountRepo.findByUuid(uuid);
  }

  @Override
  public IamAccount setLabel(IamAccount account, IamLabel label) {
    account.getLabels().remove(label);
    account.getLabels().add(label);

    account.touch();

    accountRepo.save(account);

    labelSetEvent(account, label);

    return account;
  }

  @Override
  public IamAccount deleteLabel(IamAccount account, IamLabel label) {
    boolean labelRemoved = account.getLabels().remove(label);

    if (labelRemoved) {
      account.touch();
      accountRepo.save(account);
      labelRemovedEvent(account, label);
    }

    return account;
  }

  @Override
  public IamAccount setAccountEndTime(IamAccount account, Date endTime) {
    checkNotNull(account, "Cannot set endTime on a null account");

    final Date previousEndTime = account.getEndTime();
    account.setEndTime(endTime);
    account.touch();

    account.removeLabelByName(LIFECYCLE_STATUS_LABEL);

    accountRepo.save(account);

    eventPublisher
      .publishEvent(new AccountEndTimeUpdatedEvent(this, account, previousEndTime, String
        .format("Account endTime set to '%s' for user '%s'", endTime, account.getUsername())));

    return account;
  }

  @Override
  public IamAccount disableAccount(IamAccount account) {
    account.setActive(false);
    account.touch();
    accountRepo.save(account);
    eventPublisher.publishEvent(new AccountDisabledEvent(this, account));
    return account;
  }

  @Override
  public IamAccount restoreAccount(IamAccount account) {
    account.setActive(true);
    account.touch();
    accountRepo.save(account);
    eventPublisher.publishEvent(new AccountRestoredEvent(this, account));
    return account;
  }

  @Override
  public IamAccount setAttribute(IamAccount account, IamAttribute attribute) {
    account.getAttributes().remove(attribute);
    account.getAttributes().add(attribute);
    account.touch();

    accountRepo.save(account);
    attributeSetEvent(account, attribute);
    return account;
  }

  @Override
  public IamAccount deleteAttribute(IamAccount account, IamAttribute attribute) {
    boolean attributeRemoved = account.getAttributes().remove(attribute);

    if (attributeRemoved) {
      account.touch();
      accountRepo.save(account);
      attributeRemovedEvent(account, attribute);
    }

    return account;
  }

  @Override
  public IamAccount addToGroup(IamAccount account, IamGroup group) {

    Optional<IamGroup> maybeGroup =
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), group.getUuid());

    if (!maybeGroup.isPresent()) {
      account.getGroups()
        .add(IamAccountGroupMembership.forAccountAndGroup(clock.instant(), account, group));

      group.touch(clock);
      account.touch(clock);

      groupRepo.save(group);
      accountRepo.save(account);

      accountAddedToGroupEvent(account, group);
    }

    // Also add the user to any intermediate groups up to the root
    if (!isNull(group.getParentGroup())) {
      account = addToGroup(account, group.getParentGroup());
    }

    return account;
  }

  @Override
  public IamAccount removeFromGroup(IamAccount account, IamGroup group) {
    Optional<IamGroup> maybeGroup =
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), group.getUuid());

    if (maybeGroup.isPresent()) {

      Set<IamGroup> toBeDeleted = new LinkedHashSet<>();

      for (IamAccountGroupMembership gm : account.getGroups()) {
        if (gm.getGroup().isSubgroupOf(maybeGroup.get())) {
          toBeDeleted.add(gm.getGroup());
        }
      }

      toBeDeleted.add(maybeGroup.get());

      for (IamGroup dg : toBeDeleted) {
        account.getGroups()
          .remove(IamAccountGroupMembership.forAccountAndGroup(clock.instant(), account, dg));
        account.touch(clock);
        dg.touch(clock);
        accountRepo.save(account);
        groupRepo.save(dg);
        accountRemovedFromGroupEvent(account, dg);
      }
    }

    return account;
  }

  @Override
  public IamAccount saveAccount(IamAccount account) {
    account.setLastUpdateTime(Date.from(clock.instant()));
    return accountRepo.save(account);
  }

  @Override
  public Page<IamAccount> fingGroupMembers(IamGroup group, Pageable page) {
    return accountRepo.findByGroupUuid(group.getUuid(), page);
  }

  @Override
  public IamAccount addSshKey(IamAccount account, IamSshKey key) {
    if (account.getSshKeys().contains(key)) {
      return account;
    }

    Optional<IamAccount> maybeAccount = accountRepo.findBySshKeyValue(key.getValue());
    if (maybeAccount.isPresent()) {
      IamAccount otherAccount = maybeAccount.get();
      if (otherAccount.equals(account)) {
        return account;
      } else {
        throw new CredentialAlreadyBoundException(
            String.format("SSH key 'sha256:%s' already bound to a user", key.getFingerprint()));

      }
    }

    if (account.getSshKeys().isEmpty()) {
      key.setPrimary(true);
    } else if (key.isPrimary()) {
      account.getSshKeys().forEach(k -> k.setPrimary(false));
    }

    final Date keyCreationTime = Date.from(clock.instant());

    key.setCreationTime(keyCreationTime);
    key.setLastUpdateTime(keyCreationTime);

    account.getSshKeys().add(key);
    key.setAccount(account);

    accountRepo.save(account);
    return account;
  }

  @Override
  public IamAccount removeSshKey(IamAccount account, IamSshKey key) {
    if (!account.getSshKeys().contains(key)) {
      return account;
    }

    account.getSshKeys().remove(key);
    key.setAccount(null);

    final long primaryCount = account.getSshKeys().stream().filter(IamSshKey::isPrimary).count();

    if (primaryCount == 0 || primaryCount > 1) {
      account.getSshKeys().forEach(k -> k.setPrimary(false));
      account.getSshKeys().stream().findFirst().ifPresent(k -> k.setPrimary(true));
    }

    accountRepo.save(account);
    return account;
  }

  @Override
  public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
    eventPublisher = applicationEventPublisher;
  }
}
