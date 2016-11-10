package it.infn.mw.iam.api.scim.provisioning;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.converter.AddressConverter;
import it.infn.mw.iam.api.scim.converter.UserConverter;
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
import it.infn.mw.iam.api.scim.updater.UserUpdater;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;
import it.infn.mw.iam.persistence.repository.IamOidcIdRepository;
import it.infn.mw.iam.persistence.repository.IamSamlIdRepository;
import it.infn.mw.iam.persistence.repository.IamSshKeyRepository;
import it.infn.mw.iam.util.ssh.InvalidSshKeyException;
import it.infn.mw.iam.util.ssh.RSAPublicKeyUtils;

@Service
public class ScimUserProvisioning implements ScimProvisioning<ScimUser, ScimUser> {

  private final UserConverter converter;
  private final AddressConverter addressConverter;

  private final UserUpdater updater;

  private final IamAccountRepository accountRepository;
  private final IamOidcIdRepository oidcIdRepository;
  private final IamSshKeyRepository sshKeyRepository;
  private final IamSamlIdRepository samlIdRepository;

  private final IamAuthoritiesRepository authorityRepository;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Autowired
  public ScimUserProvisioning(UserConverter converter, AddressConverter addressConverter,
      UserUpdater updater, IamAccountRepository accountRepo, IamOidcIdRepository oidcIdRepository,
      IamSshKeyRepository sshKeyRepository, IamSamlIdRepository samlIdRepository,
      IamAuthoritiesRepository authorityRepo) {

    this.converter = converter;
    this.addressConverter = addressConverter;
    this.updater = updater;
    this.accountRepository = accountRepo;
    this.oidcIdRepository = oidcIdRepository;
    this.sshKeyRepository = sshKeyRepository;
    this.samlIdRepository = samlIdRepository;
    this.authorityRepository = authorityRepo;

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

    return converter.toScim(account);

  }

  @Override
  public void delete(final String id) {

    idSanityChecks(id);

    IamAccount account = accountRepository.findByUuid(id)
      .orElseThrow(() -> new ScimResourceNotFoundException("No user mapped to id '" + id + "'"));

    accountRepository.delete(account);

  }

  public IamAccount createAccount(final ScimUser user) {

    Date creationTime = new Date();

    accountRepository.findByUsername(user.getUserName()).ifPresent(a -> {
      throw new ScimResourceExistsException("userName is already taken: " + a.getUsername());
    });

    final String userEmail = user.getEmails().get(0).getValue();

    accountRepository.findByEmail(userEmail).ifPresent(a -> {
      throw new ScimResourceExistsException(
          "email already assigned to an existing user: " + a.getUserInfo().getEmail());
    });

    String uuid = UUID.randomUUID().toString();

    IamAccount account = converter.fromScim(user);
    account.setUuid(uuid);
    account.setCreationTime(creationTime);
    account.setLastUpdateTime(creationTime);
    account.setUsername(user.getUserName());
    account.setActive(user.getActive() == null ? false : user.getActive());

    if (account.getPassword() == null) {
      account.setPassword(UUID.randomUUID().toString());
    }

    account.setPassword(passwordEncoder.encode(account.getPassword()));

    authorityRepository.findByAuthority("ROLE_USER")
      .map(a -> account.getAuthorities().add(a))
      .orElseThrow(
          () -> new IllegalStateException("ROLE_USER not found in database. This is a bug"));

    IamUserInfo userInfo = new IamUserInfo();

    if (user.getName() != null) {
      userInfo.setGivenName(user.getName().getGivenName());
      userInfo.setFamilyName(user.getName().getFamilyName());
      userInfo.setMiddleName(user.getName().getMiddleName());
    }

    if (user.getAddresses() != null && !user.getAddresses().isEmpty()) {
      userInfo.setAddress(addressConverter.fromScim(user.getAddresses().get(0)));
    }

    if (!user.getEmails().isEmpty()) {
      userInfo.setEmail(user.getEmails().get(0).getValue());
      userInfo.setEmailVerified(true);
    }
    account.setUserInfo(userInfo);

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

      account.getOidcIds().forEach(oidcId -> checkOidcIdNotExists(oidcId));
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

      account.getSamlIds().forEach(samlId -> checkSamlIdNotExists(samlId));
    }

    accountRepository.save(account);

    return account;
  }

  @Override
  public ScimUser create(final ScimUser user) {

    IamAccount account = createAccount(user);

    return converter.toScim(account);
  }

  private void checkX509CertificateNotExists(IamX509Certificate cert) {

    if (accountRepository.findByCertificateSubject(cert.getCertificateSubject()).isPresent()) {

      throw new ScimResourceExistsException(String
        .format("X509 Certificate %s is already mapped to a user", cert.getCertificateSubject()));
    }
  }

  private void checkOidcIdNotExists(IamOidcId oidcId) {

    if (oidcIdRepository.findByIssuerAndSubject(oidcId.getIssuer(), oidcId.getSubject())
      .isPresent()) {

      throw new ScimResourceExistsException(
          String.format("OIDC id (%s,%s) is already mapped to another user", oidcId.getIssuer(),
              oidcId.getSubject()));
    }
  }

  private void checkSshKeyNotExists(IamSshKey sshKey) {

    /* Generate fingerprint if null */
    if (sshKey.getFingerprint() == null && sshKey.getValue() != null) {

      try {
        sshKey.setFingerprint(RSAPublicKeyUtils.getSHA256Fingerprint(sshKey.getValue()));
      } catch (InvalidSshKeyException e) {
        throw new ScimException(e.getMessage());
      }
    }

    if (sshKeyRepository.findByFingerprint(sshKey.getFingerprint()).isPresent()) {

      throw new ScimResourceExistsException(
          "ssh key " + sshKey.getFingerprint() + " is already mapped to another user");
    }

  }

  private void checkSamlIdNotExists(IamSamlId samlId) {

    if (samlIdRepository.findByIdpIdAndUserId(samlId.getIdpId(), samlId.getUserId()).isPresent()) {

      throw new ScimResourceExistsException(
          String.format("Saml id {},{} is already mapped to another user", samlId.getIdpId(),
              samlId.getUserId()));
    }

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

    results.getContent().forEach(a -> resources.add(converter.toScim(a)));

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

    IamAccount updatedAccount = converter.fromScim(scimItemToBeUpdated);

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
    return converter.toScim(updatedAccount);
  }

  @Override
  public void update(final String id, final List<ScimPatchOperation<ScimUser>> operations) {

    IamAccount iamAccount = accountRepository.findByUuid(id)
      .orElseThrow(() -> new ScimResourceNotFoundException("No user mapped to id '" + id + "'"));

    for (ScimPatchOperation<ScimUser> op: operations) {

      if (op.getPath() != null) {
        throw new ScimPatchOperationNotSupported("Path " + op.getPath() + " is not supported");
      }

      switch (op.getOp()) {
        case add:
          updater.add(iamAccount, op.getValue());
          break;
        case remove:
          updater.remove(iamAccount, op.getValue());
          break;
        case replace:
          updater.replace(iamAccount, op.getValue());
          break;
      }
    }
  }

}
