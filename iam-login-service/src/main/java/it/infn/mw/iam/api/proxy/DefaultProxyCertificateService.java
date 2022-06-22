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
package it.infn.mw.iam.api.proxy;

import static java.lang.String.format;
import static java.util.Objects.isNull;
import static java.util.stream.Collectors.toList;

import java.security.Principal;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import com.google.common.collect.Lists;

import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.emi.security.authn.x509.proxy.ProxyCertificate;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.model.IamX509ProxyCertificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.rcauth.x509.ProxyHelperService;

@Service
@ConditionalOnProperty(name = "proxycert.enabled", havingValue = "true")
public class DefaultProxyCertificateService implements ProxyCertificateService {

  final Clock clock;
  final IamAccountRepository accountRepository;
  final ProxyCertificateProperties properties;
  final ProxyHelperService proxyHelper;

  @Autowired
  public DefaultProxyCertificateService(Clock clock, IamAccountRepository accountRepository,
      ProxyCertificateProperties properties, ProxyHelperService proxyHelper) {
    this.clock = clock;
    this.accountRepository = accountRepository;
    this.properties = properties;
    this.proxyHelper = proxyHelper;
  }

  private IamAccount findAccountByPrincipal(Principal principal) {
    return accountRepository.findByUsername(principal.getName())
      .orElseThrow(() -> NoSuchAccountError.forUsername(principal.getName()));
  }

  private Optional<IamX509ProxyCertificate> resolveProxyCertificate(IamAccount account,
      ProxyCertificateRequestDTO request) {

    for (IamX509Certificate c : account.getX509Certificates()) {

      if (!isNull(c.getProxy())) {
        IamX509ProxyCertificate proxy = c.getProxy();

        if (!isNull(request.getIssuer())) {
          if (request.getIssuer().equals(c.getIssuerDn())) {
            return Optional.of(proxy);
          }  
        } else {
          return Optional.of(proxy);
        }
      }
    }

    return Optional.empty();
  }

  private void proxySanityChecks(IamAccount account, IamX509ProxyCertificate proxy) {

    Instant now = clock.instant();
    Instant proxyExpirationTime = proxy.getExpirationTime().toInstant();

    if (now.isAfter(proxyExpirationTime)) {
      throw new ProxyNotFoundError(
          format("No valid proxy found for account '%s'", account.getUsername()));
    }
  }

  private long computeProxyLifetime(ProxyCertificateRequestDTO request) {
    long proxyLifetime = properties.getMaxLifetimeSeconds();

    if (!isNull(request.getLifetimeSecs()) && request.getLifetimeSecs() > 0
        && request.getLifetimeSecs() < properties.getMaxLifetimeSeconds()) {
      proxyLifetime = request.getLifetimeSecs();
    }

    return proxyLifetime;
  }

  private ProxyCertificateDTO proxyToDto(IamX509ProxyCertificate proxy) {
    ProxyCertificateDTO dto = new ProxyCertificateDTO();
    dto.setSubject(proxy.getCertificate().getSubjectDn());
    dto.setIssuer(proxy.getCertificate().getIssuerDn());
    dto.setNotAfter(proxy.getExpirationTime());
    dto.setIdentity(proxy.getCertificate().getSubjectDn());
    return dto;
  }


  private ProxyCertificateDTO proxyToDto(ProxyCertificate proxyCert) {

    ProxyCertificateDTO dto = new ProxyCertificateDTO();

    dto.setSubject(X500NameUtils
      .getReadableForm(proxyCert.getCredential().getCertificate().getSubjectX500Principal()));
    dto.setIssuer(X500NameUtils
      .getReadableForm(proxyCert.getCredential().getCertificate().getIssuerX500Principal()));

    dto.setNotAfter(proxyCert.getCertificateChain()[0].getNotAfter());

    return dto;
  }

  @Override
  public ProxyCertificateDTO generateProxy(Principal principal,
      ProxyCertificateRequestDTO request) {

    IamAccount account = findAccountByPrincipal(principal);

    IamX509ProxyCertificate proxy =
        resolveProxyCertificate(account, request).orElseThrow(() -> new ProxyNotFoundError(
            format("No proxy found for account '%s'", account.getUsername())));

    proxySanityChecks(account, proxy);

    long proxyLifetime = computeProxyLifetime(request);

    PEMCredential pemCredential = proxyHelper.credentialFromPemString(proxy.getChain());
    ProxyCertificate proxyCert = proxyHelper.generateProxy(pemCredential, proxyLifetime);


    ProxyCertificateDTO dto = proxyToDto(proxyCert);
    dto.setIdentity(proxy.getCertificate().getSubjectDn());
    dto.setCertificateChain(proxyHelper.proxyCertificateToPemString(proxyCert));
    return dto;
  }

  @Override
  public List<ProxyCertificateDTO> listProxies(Principal principal) {
    IamAccount account = findAccountByPrincipal(principal);

    List<IamX509ProxyCertificate> proxies = Lists.newArrayList();

    for (IamX509Certificate c : account.getX509Certificates()) {
      if (c.hasProxy()) {
        proxies.add(c.getProxy());
      }
    }

    return proxies.stream().map(this::proxyToDto).collect(toList());
  }

}
