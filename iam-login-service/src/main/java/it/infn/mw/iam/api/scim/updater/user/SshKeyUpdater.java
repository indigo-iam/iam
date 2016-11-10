package it.infn.mw.iam.api.scim.updater.user;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.base.Preconditions;

import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.api.scim.exception.ScimException;
import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamSshKeyRepository;
import it.infn.mw.iam.util.ssh.RSAPublicKeyUtils;

@Component
public class SshKeyUpdater implements Updater<IamAccount, List<ScimSshKey>> {

  @Autowired
  private IamAccountRepository accountRepository;
  @Autowired
  private IamSshKeyRepository sshKeyRepository;

  @Autowired
  private SshKeyConverter sshKeyConverter;

  private boolean isValid(IamAccount account, List<ScimSshKey> sshKeys) throws ScimException {

    Preconditions.checkNotNull(account);

    if (sshKeys == null) {
      return false;
    }
    if (sshKeys.isEmpty()) {
      return false;
    }
    return true;
  }

  private boolean setFirstAsPrimaryIfNone(IamAccount account) {

    if (account.getSshKeys().isEmpty()) {
      return false;
    }
    if (account.getSshKeys().stream().noneMatch(key -> key.isPrimary())) {
      account.getSshKeys().stream().findFirst().get().setPrimary(true);
      return true;
    }
    return false;
  }

  private void checkForPrimaryDuplicates(List<IamSshKey> sshKeys) {
    
    if (sshKeys.isEmpty()) {
      return;
    }
    if (sshKeys.stream().filter(key -> key.isPrimary()).count() > 1) {
      throw new ScimException("Too many primary ssh keys");
    }
  }

  @Override
  public boolean add(IamAccount account, List<ScimSshKey> sshKeys) {

    if (!isValid(account, sshKeys)) {
      return false;
    }

    boolean hasChanged = false;

    for (ScimSshKey sshKey : sshKeys) {

      hasChanged |= addSshKey(account, sshKey);
    }

    checkForPrimaryDuplicates(account.getSshKeys());
    hasChanged |= setFirstAsPrimaryIfNone(account);

    return hasChanged;
  }

  @Override
  public boolean remove(IamAccount account, List<ScimSshKey> sshKeys) {

    if (!isValid(account, sshKeys)) {
      return false;
    }

    boolean hasChanged = false;

    for (ScimSshKey sshKey : sshKeys) {

      hasChanged |= removeSshKey(account, sshKey);
    }

    hasChanged |= setFirstAsPrimaryIfNone(account);

    return hasChanged;
  }

  @Override
  public boolean replace(IamAccount account, List<ScimSshKey> sshKeys) {

    if (!isValid(account, sshKeys)) {
      return false;
    }

    boolean hasChanged = false;

    for (ScimSshKey sshKey : sshKeys) {

      hasChanged |= replaceSshKey(account, sshKey);
    }

    checkForPrimaryDuplicates(account.getSshKeys());
    hasChanged |= setFirstAsPrimaryIfNone(account);

    return hasChanged;
  }

  private boolean addSshKey(IamAccount account, ScimSshKey sshKey) {

    Preconditions.checkArgument(sshKey != null, "Null ssh key");
    Preconditions.checkArgument(sshKey.getValue() != null, "Null key value");
    Preconditions.checkArgument(sshKey.getDisplay() != null, "Null key label");

    String fingerprint = null;

    try {
      fingerprint = RSAPublicKeyUtils.getSHA256Fingerprint(sshKey.getValue());
    } catch (Throwable t) {
      throw new ScimException(t.getMessage());
    }

    if (sshKey.getFingerprint() != null) {
      Preconditions.checkArgument(sshKey.getFingerprint().equals(fingerprint));
    }

    Optional<IamAccount> sshKeyAccount = accountRepository.findBySshKeyValue(sshKey.getValue());

    if (sshKeyAccount.isPresent()) {

      if (!sshKeyAccount.get().equals(account)) {

        throw new ScimResourceExistsException(
            String.format("Ssh key (%s,%s) is already mapped to another user", sshKey.getDisplay(),
                sshKey.getFingerprint()));
      }
      return false;
    }

    IamSshKey sshKeyToCreate = sshKeyConverter.fromScim(sshKey);
    sshKeyToCreate.setAccount(account);

    if (sshKeyToCreate.getFingerprint() == null) {
      sshKeyToCreate.setFingerprint(fingerprint);
    }

    sshKeyRepository.save(sshKeyToCreate);
    account.getSshKeys().add(sshKeyToCreate);

    return true;
  }

  private boolean removeSshKey(IamAccount account, ScimSshKey sshKey) {

    Preconditions.checkArgument(sshKey != null, "Null ssh key");

    IamSshKey toRemove = account.getSshKeys()
      .stream()
      .filter(key -> key.getFingerprint().equals(sshKey.getFingerprint())
          || key.getValue().equals(sshKey.getValue()) || key.getLabel().equals(sshKey.getDisplay()))
      .findFirst()
      .orElseThrow(() -> new ScimResourceNotFoundException(String.format(
          "User %s has no %s ssh key to remove!", account.getUsername(), sshKey.getFingerprint())));

    sshKeyRepository.delete(toRemove);
    account.getSshKeys().remove(toRemove);
    return true;
  }

  private boolean replaceSshKey(IamAccount account, ScimSshKey sshKey) {
    
    Preconditions.checkArgument(sshKey != null, "Null ssh key");

    IamSshKey toReplace = account.getSshKeys()
      .stream()
      .filter(key -> key.getFingerprint().equals(sshKey.getFingerprint())
          || key.getValue().equals(sshKey.getValue()))
      .findFirst().orElseThrow(() -> new ScimResourceNotFoundException(
          String.format("Ssh key (%s) to replace not found", sshKey)));

    boolean hasChanged = false;

    if (sshKey.getDisplay() != null) {
      if (!sshKey.getDisplay().equals(toReplace.getLabel())) {
        toReplace.setLabel(sshKey.getDisplay());
        hasChanged = true;
      }
    }
    if (sshKey.isPrimary() != null) {
      if (!sshKey.isPrimary().equals(toReplace.isPrimary())) {
        toReplace.setPrimary(sshKey.isPrimary());
        hasChanged = true;
      }
    }
    
    if (hasChanged) {
      sshKeyRepository.save(toReplace);
    }
    return hasChanged;
  }
}
