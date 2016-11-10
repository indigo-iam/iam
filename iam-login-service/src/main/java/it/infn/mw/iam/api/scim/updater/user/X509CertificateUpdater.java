package it.infn.mw.iam.api.scim.updater.user;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.base.Preconditions;

import it.infn.mw.iam.api.scim.converter.X509CertificateConverter;
import it.infn.mw.iam.api.scim.exception.ScimException;
import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimX509Certificate;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamX509CertificateRepository;

@Component
public class X509CertificateUpdater implements Updater<IamAccount, List<ScimX509Certificate>> {

  @Autowired
  private X509CertificateConverter certificateConverter;

  @Autowired
  private IamAccountRepository accountRepository;
  @Autowired
  private IamX509CertificateRepository x509CertificateRepository;

  private boolean isValid(IamAccount account, List<ScimX509Certificate> certs)
      throws ScimException {

    Preconditions.checkNotNull(account);

    if (certs == null) {
      return false;
    }
    if (certs.isEmpty()) {
      return false;
    }
    return true;
  }

  @Override
  public boolean add(IamAccount account, List<ScimX509Certificate> certs) {

    if (!isValid(account, certs)) {
      return false;
    }

    boolean hasChanged = false;

    for (ScimX509Certificate cert : certs) {
      hasChanged |= addX509Certificate(account, cert);
    }

    /* if there's more than one primary x509 certificate, fails */
    if (account.getX509Certificates().stream().filter(cert -> cert.isPrimary()).count() > 1) {
      throw new ScimException("Too many primary x509 certificates");
    }
    /* if there's no primary x509 certificate, set the first as it */
    if (account.getX509Certificates().stream().noneMatch(cert -> cert.isPrimary())) {
      account.getX509Certificates().stream().findFirst().get().setPrimary(true);
      hasChanged = true;
    }

    return hasChanged;
  }

  @Override
  public boolean remove(IamAccount account, List<ScimX509Certificate> certs) {

    if (!isValid(account, certs)) {
      return false;
    }
    
    boolean hasChanged = false;

    for (ScimX509Certificate cert : certs) {
      hasChanged |= removeX509Certificate(account, cert);
    }

    if (account.hasX509Certificates()) {
      /* if there's no primary x509 certificate, set the first as it */
      if (account.getX509Certificates().stream().noneMatch(cert -> cert.isPrimary())) {
        account.getX509Certificates().stream().findFirst().get().setPrimary(true);
        hasChanged = true;
      }
    }
    return hasChanged;
  }

  @Override
  public boolean replace(IamAccount account, List<ScimX509Certificate> certs) {

    if (!isValid(account, certs)) {
      return false;
    }

    boolean hasChanged = false;

    for (ScimX509Certificate cert : certs) {
      hasChanged |= replaceX509Certificate(account, cert);
    }

    /* if there's more than one primary x509 certificate, fails */
    if (account.getX509Certificates().stream().filter(cert -> cert.isPrimary()).count() > 1) {
      throw new ScimException("Too many primary x509 certificates");
    }
    /* if there's no primary x509 certificate, set the first as it */
    if (account.getX509Certificates().stream().noneMatch(cert -> cert.isPrimary())) {
      account.getX509Certificates().stream().findFirst().get().setPrimary(true);
      hasChanged = true;
    }

    return hasChanged;
  }

  private boolean addX509Certificate(IamAccount account, ScimX509Certificate cert) {

    Preconditions.checkNotNull(cert, "X509Certificate is null");

    IamX509Certificate iamCert = certificateConverter.fromScim(cert);

    Optional<IamAccount> x509Account =
        accountRepository.findByCertificateSubject(iamCert.getCertificateSubject());

    if (x509Account.isPresent()) {

      if (!x509Account.get().equals(account)) {
        throw new ScimResourceExistsException(
            String.format("Cannot add x509 certificate: already mapped to another user"));
      }
      return false;
    }

    iamCert.setAccount(account);
    x509CertificateRepository.save(iamCert);
    account.getX509Certificates().add(iamCert);

    return true;
  }

  private boolean removeX509Certificate(IamAccount account, ScimX509Certificate cert) {

    Preconditions.checkNotNull(cert, "X509Certificate is null");

    IamX509Certificate toRemove = account.getX509Certificates()
      .stream()
      .filter(x509Cert -> x509Cert.getCertificate().equals(cert.getValue()))
      .findFirst()
      .orElseThrow(() -> new ScimResourceNotFoundException("No x509 certificate found"));

    x509CertificateRepository.delete(toRemove);
    account.getX509Certificates().remove(toRemove);
    return true;
  }

  private boolean replaceX509Certificate(IamAccount account, ScimX509Certificate cert) {
    
    Preconditions.checkNotNull(cert, "X509Certificate is null");

    IamX509Certificate toReplace = account.getX509Certificates()
      .stream()
      .filter(x509Cert -> x509Cert.getCertificate().equals(cert.getValue())
          || x509Cert.getLabel().equals(cert.getDisplay()))
      .findFirst()
      .orElseThrow(() -> new ScimResourceNotFoundException("No x509 certificate found"));

    boolean hasChanged = false;

    /* update display and primary */
    if (cert.getDisplay() != null) {
      if (!cert.getDisplay().equals(toReplace.getLabel())) {
        toReplace.setLabel(cert.getDisplay());
        hasChanged = true;
      }
    }
    if (cert.isPrimary() != null) {
      if (!cert.isPrimary().equals(toReplace.isPrimary())) {
        toReplace.setPrimary(cert.isPrimary());
        hasChanged = true;
      }
    }

    if (hasChanged) {
      x509CertificateRepository.save(toReplace);
    }
    return hasChanged;
  }

}
