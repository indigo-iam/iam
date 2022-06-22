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
package it.infn.mw.iam.api.account_linking;

import static it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType.SAML;
import static java.lang.String.format;

import java.security.Principal;
import java.util.Date;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.audit.events.account.AccountLinkedEvent;
import it.infn.mw.iam.audit.events.account.AccountUnlinkedEvent;
import it.infn.mw.iam.audit.events.account.X509CertificateLinkedEvent;
import it.infn.mw.iam.audit.events.account.X509CertificateUnlinkedEvent;
import it.infn.mw.iam.audit.events.account.X509CertificateUpdatedEvent;
import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAccountLinker;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.authn.error.AccountAlreadyLinkedError;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.model.IamX509ProxyCertificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Service
public class DefaultAccountLinkingService
    implements AccountLinkingService, ApplicationEventPublisherAware {

  final IamAccountRepository iamAccountRepository;
  final ExternalAccountLinker externalAccountLinker;
  private ApplicationEventPublisher eventPublisher;

  @Autowired
  public DefaultAccountLinkingService(IamAccountRepository repo, ExternalAccountLinker linker) {
    this.iamAccountRepository = repo;
    this.externalAccountLinker = linker;
  }

  public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
    this.eventPublisher = publisher;
  }

  private IamAccount findAccount(Principal authenticatedUser) {
    return iamAccountRepository.findByUsername(authenticatedUser.getName())
      .orElseThrow(() -> new UsernameNotFoundException(
          "No user found with username '" + authenticatedUser.getName() + "'"));
  }

  @Override
  public void linkExternalAccount(Principal authenticatedUser,
      AbstractExternalAuthenticationToken<?> externalAuthenticationToken) {

    IamAccount userAccount = findAccount(authenticatedUser);

    externalAuthenticationToken.linkToIamAccount(externalAccountLinker, userAccount);

    eventPublisher.publishEvent(new AccountLinkedEvent(this, userAccount,
        externalAuthenticationToken.toExernalAuthenticationRegistrationInfo(),
        String.format("User %s has linked a new account of type %s", userAccount.getUsername(),
            externalAuthenticationToken.toExernalAuthenticationRegistrationInfo()
              .getType()
              .toString())));
  }


  @Override
  public void unlinkExternalAccount(Principal authenticatedUser, ExternalAuthenticationType type,
      String iss, String sub, String attributeId) {

    IamAccount userAccount = findAccount(authenticatedUser);

    boolean modified = false;

    if (SAML.equals(type)) {

      IamSamlId id = new IamSamlId();
      id.setIdpId(iss);
      id.setUserId(sub);
      id.setAttributeId(attributeId);

      userAccount.getSamlIds()
        .stream()
        .filter(o -> o.equals(id))
        .findFirst()
        .ifPresent(i -> i.setAccount(null));

      modified = userAccount.getSamlIds().remove(id);

    } else {

      IamOidcId id = new IamOidcId();
      id.setIssuer(iss);
      id.setSubject(sub);

      userAccount.getOidcIds()
        .stream()
        .filter(o -> o.equals(id))
        .findFirst()
        .ifPresent(i -> i.setAccount(null));

      modified = userAccount.getOidcIds().remove(id);
    }

    if (modified) {
      userAccount.touch();
      iamAccountRepository.save(userAccount);

      eventPublisher.publishEvent(new AccountUnlinkedEvent(this, userAccount, type, iss, sub,
          String.format("User %s has unlinked an account of type %s", userAccount.getUsername(),
              type.toString())));
    }
  }

  @Override
  public void linkX509Certificate(Principal authenticatedUser,
      IamX509AuthenticationCredential x509Credential) {

    IamAccount userAccount = findAccount(authenticatedUser);

    iamAccountRepository.findByCertificateSubject(x509Credential.getSubject())
      .ifPresent(linkedAccount -> {
        if (!linkedAccount.getUuid().equals(userAccount.getUuid())) {
          throw new AccountAlreadyLinkedError(
              format("X.509 credential with subject '%s' is already linked to another user",
                  x509Credential.getSubject()));
        }
      });

    Optional<IamX509Certificate> linkedCert = userAccount.getX509Certificates()
      .stream()
      .filter(c -> c.getSubjectDn().equals(x509Credential.getSubject()))
      .findAny();

    if (linkedCert.isPresent()) {

      linkedCert.ifPresent(c -> {
        c.setSubjectDn(x509Credential.getSubject());
        c.setIssuerDn(x509Credential.getIssuer());
        c.setCertificate(x509Credential.getCertificateChainPemString());
        c.setLastUpdateTime(new Date());
      });

      userAccount.touch();
      iamAccountRepository.save(userAccount);

      eventPublisher.publishEvent(new X509CertificateUpdatedEvent(this, userAccount,
          String.format("User '%s' has updated its linked certificate with subject '%s'",
              userAccount.getUsername(), x509Credential.getSubject()),
          x509Credential));

    } else {

      Date now = new Date();
      IamX509Certificate newCert = x509Credential.asIamX509Certificate();
      newCert.setLabel(String.format("cert-%d", userAccount.getX509Certificates().size()));

      newCert.setCreationTime(now);
      newCert.setLastUpdateTime(now);

      newCert.setPrimary(true);
      newCert.setAccount(userAccount);
      userAccount.getX509Certificates().add(newCert);
      userAccount.touch();

      iamAccountRepository.save(userAccount);

      eventPublisher.publishEvent(new X509CertificateLinkedEvent(this, userAccount,
          String.format("User '%s' linked certificate with subject '%s' to his/her membership",
              userAccount.getUsername(), x509Credential.getSubject()),
          x509Credential));

    }
  }

  @Override
  public void unlinkX509Certificate(Principal authenticatedUser, String certificateSubject) {
    IamAccount userAccount = findAccount(authenticatedUser);

    boolean removed = userAccount.getX509Certificates()
      .removeIf(c -> c.getSubjectDn().equals(certificateSubject));

    if (removed) {
      userAccount.touch();
      iamAccountRepository.save(userAccount);

      eventPublisher.publishEvent(new X509CertificateUnlinkedEvent(this, userAccount,
          String.format("User '%s' unlinked certificate with subject '%s' from his/her membership",
              userAccount.getUsername(), certificateSubject),
          certificateSubject));
    }
  }

  @Override
  public void linkX509ProxyCertificate(Principal authenticatedUser,
      IamX509AuthenticationCredential x509Credential, String proxyCertificatePemString,
      Date proxyCertificateExpirationTime) {

    linkX509Certificate(authenticatedUser, x509Credential);
    IamAccount userAccount = findAccount(authenticatedUser);

    IamX509Certificate cert = userAccount.getX509Certificates()
      .stream()
      .filter(c -> c.getSubjectDn().equals(x509Credential.getSubject()))
      .findAny()
      .orElseThrow(() -> new IllegalStateException(
          "Expected certificate not found: " + x509Credential.getSubject()));


    IamX509ProxyCertificate proxy = new IamX509ProxyCertificate();
    proxy.setChain(proxyCertificatePemString);
    proxy.setCertificate(cert);
    proxy.setExpirationTime(proxyCertificateExpirationTime);
    cert.setProxy(proxy);

    userAccount.touch();
    iamAccountRepository.save(userAccount);

  }

}
