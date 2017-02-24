package it.infn.mw.iam.api.scim.provisioning;

import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_OIDC_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_SAML_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_SSH_KEY;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_X509_CERTIFICATE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_OIDC_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_PICTURE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_SAML_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_SSH_KEY;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_X509_CERTIFICATE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_ACTIVE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_EMAIL;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_FAMILY_NAME;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_GIVEN_NAME;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_PASSWORD;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_PICTURE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_USERNAME;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.data.domain.Page;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.google.common.base.Preconditions;

import it.infn.mw.iam.api.scim.converter.OidcIdConverter;
import it.infn.mw.iam.api.scim.converter.SamlIdConverter;
import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.converter.X509CertificateConverter;
import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.api.scim.exception.ScimException;
import it.infn.mw.iam.api.scim.exception.ScimPatchOperationNotSupported;
import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.api.scim.model.ScimPatchOperation;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.paging.OffsetPageable;
import it.infn.mw.iam.api.scim.provisioning.paging.ScimPageRequest;
import it.infn.mw.iam.api.scim.updater.AccountUpdater;
import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.api.scim.updater.factory.DefaultAccountUpdaterFactory;
import it.infn.mw.iam.audit.events.account.AccountCreateEvent;
import it.infn.mw.iam.audit.events.account.AccountRemoveEvent;
import it.infn.mw.iam.audit.events.account.AccountReplaceEvent;
import it.infn.mw.iam.audit.events.account.AccountUpdateEvent;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;

@Service
public class ScimUserProvisioning
    implements ScimProvisioning<ScimUser, ScimUser>, ApplicationEventPublisherAware {

  public static final EnumSet<UpdaterType> SUPPORTED_UPDATER_TYPES = EnumSet.of(ACCOUNT_ADD_OIDC_ID,
      ACCOUNT_REMOVE_OIDC_ID, ACCOUNT_ADD_SAML_ID, ACCOUNT_REMOVE_SAML_ID, ACCOUNT_ADD_SSH_KEY,
      ACCOUNT_REMOVE_SSH_KEY, ACCOUNT_ADD_X509_CERTIFICATE, ACCOUNT_REMOVE_X509_CERTIFICATE,
      ACCOUNT_REPLACE_ACTIVE, ACCOUNT_REPLACE_EMAIL, ACCOUNT_REPLACE_FAMILY_NAME,
      ACCOUNT_REPLACE_GIVEN_NAME, ACCOUNT_REPLACE_PASSWORD, ACCOUNT_REPLACE_PICTURE,
      ACCOUNT_REPLACE_USERNAME, ACCOUNT_REMOVE_PICTURE);

  private final IamAccountRepository accountRepository;
  private final IamAuthoritiesRepository authorityRepository;
  private final DefaultAccountUpdaterFactory updatersFactory;
  private final PasswordEncoder passwordEncoder;
  private final UserConverter userConverter;
  private ApplicationEventPublisher eventPublisher;

  @Autowired
  public ScimUserProvisioning(IamAccountRepository accountRepository,
      IamAuthoritiesRepository authorityRepository, PasswordEncoder passwordEncoder,
      UserConverter userConverter, OidcIdConverter oidcIdConverter, SamlIdConverter samlIdConverter,
      SshKeyConverter sshKeyConverter, X509CertificateConverter x509CertificateConverter) {

    this.accountRepository = accountRepository;
    this.authorityRepository = authorityRepository;
    this.passwordEncoder = passwordEncoder;
    this.userConverter = userConverter;
    this.updatersFactory = new DefaultAccountUpdaterFactory(passwordEncoder, accountRepository,
        oidcIdConverter, samlIdConverter, sshKeyConverter, x509CertificateConverter);
  }

  public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
    this.eventPublisher = publisher;
  }

  private void idSanityChecks(final String id) {

    if (id == null) {
      throw new IllegalArgumentException("id cannot be null");
    }

    if (id.trim().isEmpty()) {
      throw new IllegalArgumentException("id cannot be the empty string");
    }
  }

  @Override
  public ScimUser getById(final String id) {

    idSanityChecks(id);

    IamAccount account = accountRepository.findByUuid(id)
      .orElseThrow(() -> new ScimResourceNotFoundException("No user mapped to id '" + id + "'"));

    return userConverter.toScim(account);

  }

  @Override
  public void delete(final String id) {

    idSanityChecks(id);

    IamAccount account = accountRepository.findByUuid(id)
      .orElseThrow(() -> new ScimResourceNotFoundException("No user mapped to id '" + id + "'"));

    accountRepository.delete(account);

    eventPublisher.publishEvent(
        new AccountRemoveEvent(this, account, "Removed account for user " + account.getUsername()));
  }

  private void checkForDuplicates(ScimUser user) throws ScimResourceExistsException {

    Preconditions.checkNotNull(user.getEmails());
    Preconditions.checkNotNull(user.getEmails().get(0));
    Preconditions.checkNotNull(user.getEmails().get(0).getValue());

    accountRepository.findByUsername(user.getUserName()).ifPresent(a -> {
      throw new ScimResourceExistsException("userName is already taken: " + a.getUsername());
    });

    accountRepository.findByEmail(user.getEmails().get(0).getValue()).ifPresent(a -> {
      throw new ScimResourceExistsException(
          "email already assigned to an existing user: " + a.getUserInfo().getEmail());
    });
  }

  public IamAccount createAccount(final ScimUser user) {

    checkForDuplicates(user);

    final Date creationTime = new Date();
    final String uuid = UUID.randomUUID().toString();

    IamAccount account = userConverter.fromScim(user);
    account.setUuid(uuid);
    account.setCreationTime(creationTime);
    account.setLastUpdateTime(creationTime);
    account.setUsername(user.getUserName());

    if (user.getActive() != null) {
      account.setActive(user.getActive());
    } else {
      /* if no active status is specified, disable user */
      account.setActive(false);
    }

    /* users created via SCIM are set with email-verified as true */
    account.getUserInfo().setEmailVerified(true);

    if (account.getPassword() == null) {
      account.setPassword(UUID.randomUUID().toString());
    }

    account.setPassword(passwordEncoder.encode(account.getPassword()));

    authorityRepository.findByAuthority("ROLE_USER")
      .map(a -> account.getAuthorities().add(a))
      .orElseThrow(
          () -> new IllegalStateException("ROLE_USER not found in database. This is a bug"));

    if (account.hasX509Certificates()) {

      account.getX509Certificates().forEach(cert -> checkX509CertificateNotExists(cert));

      long count = account.getX509Certificates().stream().filter(cert -> cert.isPrimary()).count();

      if (count > 1) {

        throw new ScimException("Too many primary x509 certificates provided!");
      }

      if (count == 0) {

        account.getX509Certificates().stream().findFirst().get().setPrimary(true);
      }
    }

    if (account.hasOidcIds()) {

      account.getOidcIds().forEach(oidcId -> checkOidcIdNotAlreadyBounded(oidcId));
    }

    if (account.hasSshKeys()) {

      account.getSshKeys().forEach(sshKey -> checkSshKeyNotExists(sshKey));

      long count = account.getSshKeys().stream().filter(sshKey -> sshKey.isPrimary()).count();

      if (count > 1) {

        throw new ScimException("Too many primary ssh keys provided!");
      }

      if (count == 0) {

        account.getSshKeys().stream().findFirst().get().setPrimary(true);
      }
    }

    if (account.hasSamlIds()) {

      account.getSamlIds().forEach(samlId -> checkSamlIdNotAlreadyBounded(samlId));
    }

    accountRepository.save(account);

    eventPublisher.publishEvent(
        new AccountCreateEvent(this, account, "Account created for user " + account.getUsername()));

    return account;
  }

  @Override
  public ScimUser create(final ScimUser user) {

    IamAccount account = createAccount(user);

    return userConverter.toScim(account);
  }

  private void checkX509CertificateNotExists(IamX509Certificate cert) {

    if (accountRepository.findByCertificate(cert.getCertificate()).isPresent()) {

      throw new ScimResourceExistsException(
          String.format("X509 Certificate %s is already mapped to a user", cert.getCertificate()));
    }
  }

  private void checkOidcIdNotAlreadyBounded(IamOidcId oidcId) {

    Preconditions.checkNotNull(oidcId);
    Preconditions.checkNotNull(oidcId.getIssuer());
    Preconditions.checkNotNull(oidcId.getSubject());
    accountRepository.findByOidcId(oidcId.getIssuer(), oidcId.getSubject()).ifPresent(account -> {
      throw new ScimResourceExistsException(
          String.format("OIDC id (%s,%s) already bounded to another user", oidcId.getIssuer(),
              oidcId.getSubject()));
    });
  }

  private void checkSshKeyNotExists(IamSshKey sshKey) {

    Preconditions.checkNotNull(sshKey);
    Preconditions.checkNotNull(sshKey.getValue());
    accountRepository.findBySshKeyValue(sshKey.getValue()).ifPresent(account -> {
      throw new ScimResourceExistsException(
          String.format("Ssh key (%s) already bounded to another user", sshKey.getValue()));
    });
  }

  private void checkSamlIdNotAlreadyBounded(IamSamlId samlId) {

    Preconditions.checkNotNull(samlId);
    Preconditions.checkNotNull(samlId.getIdpId());
    Preconditions.checkNotNull(samlId.getUserId());
    accountRepository.findBySamlId(samlId.getIdpId(), samlId.getUserId()).ifPresent(account -> {
      throw new ScimResourceExistsException(
          String.format("SAML id (%s,%s) already bounded to another user", samlId.getIdpId(),
              samlId.getUserId()));
    });
  }

  @Override
  public ScimListResponse<ScimUser> list(final ScimPageRequest params) {

    if (params.getCount() == 0) {
      int userCount = accountRepository.countAllUsers();
      return new ScimListResponse<>(Collections.emptyList(), userCount, 0, 1);
    }

    OffsetPageable op = new OffsetPageable(params.getStartIndex(), params.getCount());

    Page<IamAccount> results = accountRepository.findAll(op);

    List<ScimUser> resources = new ArrayList<>();

    results.getContent().forEach(a -> resources.add(userConverter.toScim(a)));

    return new ScimListResponse<>(resources, results.getTotalElements(), resources.size(),
        op.getOffset() + 1);
  }

  @Override
  public ScimUser replace(final String uuid, final ScimUser scimItemToBeUpdated) {

    // user must exist
    IamAccount existingAccount = accountRepository.findByUuid(uuid)
      .orElseThrow(() -> new ScimResourceNotFoundException("No user mapped to id '" + uuid + "'"));

    // username must be available
    final String username = scimItemToBeUpdated.getUserName();
    if (accountRepository.findByUsernameWithDifferentUUID(username, uuid).isPresent()) {
      throw new ScimResourceExistsException(
          "username " + username + " already assigned to another user");
    }

    // email must be unique
    final String updatedEmail = scimItemToBeUpdated.getEmails().get(0).getValue();
    if (accountRepository.findByEmailWithDifferentUUID(updatedEmail, uuid).isPresent()) {
      throw new ScimResourceExistsException(
          "email " + updatedEmail + " already assigned to another user");
    }

    IamAccount updatedAccount = userConverter.fromScim(scimItemToBeUpdated);

    updatedAccount.setId(existingAccount.getId());
    updatedAccount.setUuid(existingAccount.getUuid());
    updatedAccount.setCreationTime(existingAccount.getCreationTime());

    // If the active field was not provided in the input scim user,
    // use the value that was formerly set in the database
    if (scimItemToBeUpdated.getActive() == null) {
      updatedAccount.setActive(existingAccount.isActive());
    }

    if (scimItemToBeUpdated.getPassword() != null) {

    }

    updatedAccount.touch();

    accountRepository.save(updatedAccount);

    eventPublisher.publishEvent(new AccountReplaceEvent(this, updatedAccount, existingAccount,
        String.format("Replaced user %s with new user %s", updatedAccount.getUsername(),
            existingAccount.getUsername())));

    return userConverter.toScim(updatedAccount);
  }

  private void executePatchOperation(IamAccount account, ScimPatchOperation<ScimUser> op) {

    List<AccountUpdater> updaters = updatersFactory.getUpdatersForPatchOperation(account, op);

    boolean hasChanged = false;

    for (AccountUpdater u : updaters) {
      if (!SUPPORTED_UPDATER_TYPES.contains(u.getType())) {
        throw new ScimPatchOperationNotSupported(u.getType().getDescription() + " not supported");
      }
      hasChanged |= u.update();

      eventPublisher.publishEvent(new AccountUpdateEvent(this, account, u.getType(),
          String.format("Updated account information for user %s", account.getUsername())));
    }

    if (hasChanged) {

      account.touch();
      accountRepository.save(account);

    }
  }

  @Override
  public void update(final String id, final List<ScimPatchOperation<ScimUser>> operations) {

    IamAccount account = accountRepository.findByUuid(id)
      .orElseThrow(() -> new ScimResourceNotFoundException("No user mapped to id '" + id + "'"));

    operations.forEach(op -> executePatchOperation(account, op));
  }

}
