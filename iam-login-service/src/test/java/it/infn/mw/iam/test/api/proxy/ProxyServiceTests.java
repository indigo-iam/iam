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
package it.infn.mw.iam.test.api.proxy;

import static java.util.Optional.empty;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.spy;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SignatureException;
import java.security.cert.CertificateParsingException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.google.common.collect.Sets;

import eu.emi.security.authn.x509.proxy.ProxyCertificate;
import eu.emi.security.authn.x509.proxy.ProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.ProxyGenerator;
import eu.emi.security.authn.x509.proxy.ProxyType;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.api.proxy.DefaultProxyCertificateService;
import it.infn.mw.iam.api.proxy.ProxyCertificateDTO;
import it.infn.mw.iam.api.proxy.ProxyCertificateProperties;
import it.infn.mw.iam.api.proxy.ProxyCertificateRequestDTO;
import it.infn.mw.iam.api.proxy.ProxyNotFoundError;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.model.IamX509ProxyCertificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@ExtendWith(MockitoExtension.class)
class ProxyServiceTests extends ProxyCertificateTestSupport {

  @Mock
  IamAccountRepository accountRepo;

  @Mock
  ProxyCertificateProperties properties;

  @Mock
  Principal principal;

  @Mock
  ProxyCertificateRequestDTO request;

  @Mock
  IamAccount account;

  @Mock
  IamX509ProxyCertificate proxyCert;

  DefaultProxyCertificateService proxyService;

  protected String generateTest0Proxy(Instant notBefore, Instant notAfter)
      throws InvalidKeyException, CertificateParsingException, SignatureException,
      NoSuchAlgorithmException, IOException {

    ProxyCertificateOptions opts =
        new ProxyCertificateOptions(TEST_0_PEM_CREDENTIAL.getCertificateChain());
    opts.setValidityBounds(Date.from(notBefore), Date.from(notAfter));
    opts.setType(ProxyType.RFC3820);
    ProxyCertificate proxy = ProxyGenerator.generate(opts, TEST_0_PEM_CREDENTIAL.getKey());
    return proxyHelper.proxyCertificateToPemString(proxy);
  }

  @BeforeEach
  void setup() {

    proxyService = new DefaultProxyCertificateService(clock, accountRepo, properties, proxyHelper);
    lenient().when(principal.getName()).thenReturn(TEST_USER_USERNAME);
    lenient().when(account.getUsername()).thenReturn(TEST_USER_USERNAME);
    lenient().when(properties.getMaxLifetimeSeconds()).thenReturn(DEFAULT_PROXY_LIFETIME_SECONDS);
    lenient().when(request.getLifetimeSecs()).thenReturn(null);
  }

  @Test
  void testPrincipalNotFoundHandled() {
    lenient().when(accountRepo.findByUsername(TEST_USER_USERNAME)).thenReturn(empty());
    assertThrows(NoSuchAccountError.class, () -> proxyService.generateProxy(principal, request));
  }

  @Test
  void testPrincipalWithoutCertificateHandled() {
    lenient().when(account.getX509Certificates()).thenReturn(Sets.newHashSet());
    lenient().when(accountRepo.findByUsername(TEST_USER_USERNAME)).thenReturn(Optional.of(account));
    assertThrows(ProxyNotFoundError.class, () -> proxyService.generateProxy(principal, request));
  }

  @Test
  void testPrincipalWithoutProxyHandled() {
    lenient().when(account.getX509Certificates()).thenReturn(Sets.newHashSet(TEST_0_IAM_X509_CERT));
    lenient().when(accountRepo.findByUsername(TEST_USER_USERNAME)).thenReturn(Optional.of(account));
    assertThrows(ProxyNotFoundError.class, () -> proxyService.generateProxy(principal, request));
  }

  @Test
  void testExpiredProxyHandled() throws InvalidKeyException, CertificateParsingException,
      SignatureException, NoSuchAlgorithmException, IOException {

    IamX509Certificate mockedTest0Cert = spy(TEST_0_IAM_X509_CERT);
    lenient().when(mockedTest0Cert.getProxy()).thenReturn(proxyCert);

    lenient().when(proxyCert.getExpirationTime()).thenReturn(Date.from(AN_HOUR_AGO));

    lenient().when(account.getX509Certificates()).thenReturn(Sets.newHashSet(mockedTest0Cert));
    lenient().when(accountRepo.findByUsername(TEST_USER_USERNAME)).thenReturn(Optional.of(account));

    assertThrows(ProxyNotFoundError.class, () -> proxyService.generateProxy(principal, request));
  }

  @Test
  void testProxyGenerationSuccess() throws InvalidKeyException, CertificateParsingException,
      SignatureException, NoSuchAlgorithmException, IOException {
    IamX509Certificate mockedTest0Cert = spy(TEST_0_IAM_X509_CERT);
    lenient().when(mockedTest0Cert.getProxy()).thenReturn(proxyCert);

    String pemProxy = generateTest0Proxy(A_WEEK_AGO, ONE_YEAR_FROM_NOW);
    lenient().when(proxyCert.getExpirationTime()).thenReturn(Date.from(ONE_YEAR_FROM_NOW));
    lenient().when(proxyCert.getCertificate()).thenReturn(mockedTest0Cert);

    lenient().when(proxyCert.getChain()).thenReturn(pemProxy);


    lenient().when(account.getX509Certificates()).thenReturn(Sets.newHashSet(mockedTest0Cert));
    lenient().when(accountRepo.findByUsername(TEST_USER_USERNAME)).thenReturn(Optional.of(account));

    ProxyCertificateDTO dto = proxyService.generateProxy(principal, request);

    Instant notAfter = dto.getNotAfter().toInstant();

    assertThat(Duration.between(NOW, notAfter)
      .compareTo(Duration.ofSeconds(DEFAULT_PROXY_LIFETIME_SECONDS)), is(0));

    assertThat(dto.getIdentity(), is(TEST_0_SUBJECT));
    assertThat(dto.getSubject(), endsWith(TEST_0_SUBJECT));
    assertThat(dto.getIssuer(), endsWith(TEST_0_SUBJECT));
    assertThat(dto.getCertificateChain(), notNullValue());

  }

  @Test
  void testRequestLifetimeIsHonoured() throws InvalidKeyException, CertificateParsingException,
      SignatureException, NoSuchAlgorithmException, IOException {
    IamX509Certificate mockedTest0Cert = spy(TEST_0_IAM_X509_CERT);
    lenient().when(mockedTest0Cert.getProxy()).thenReturn(proxyCert);
    lenient().when(request.getLifetimeSecs()).thenReturn(TimeUnit.HOURS.toSeconds(6));

    String pemProxy = generateTest0Proxy(A_WEEK_AGO, ONE_YEAR_FROM_NOW);
    lenient().when(proxyCert.getExpirationTime()).thenReturn(Date.from(ONE_YEAR_FROM_NOW));
    lenient().when(proxyCert.getCertificate()).thenReturn(mockedTest0Cert);

    lenient().when(proxyCert.getChain()).thenReturn(pemProxy);


    lenient().when(account.getX509Certificates()).thenReturn(Sets.newHashSet(mockedTest0Cert));
    lenient().when(accountRepo.findByUsername(TEST_USER_USERNAME)).thenReturn(Optional.of(account));

    ProxyCertificateDTO dto = proxyService.generateProxy(principal, request);

    Instant notAfter = dto.getNotAfter().toInstant();

    assertThat(
        Duration.between(NOW, notAfter).compareTo(Duration.ofSeconds(TimeUnit.HOURS.toSeconds(6))),
        is(0));
  }

  @Test
  void testRequestLifetimeIsLimitedToDefaultProxyLifetime() throws InvalidKeyException,
      CertificateParsingException, SignatureException, NoSuchAlgorithmException, IOException {
    IamX509Certificate mockedTest0Cert = spy(TEST_0_IAM_X509_CERT);
    lenient().when(mockedTest0Cert.getProxy()).thenReturn(proxyCert);
    lenient().when(request.getLifetimeSecs()).thenReturn(DEFAULT_PROXY_LIFETIME_SECONDS + 1);

    String pemProxy = generateTest0Proxy(A_WEEK_AGO, ONE_YEAR_FROM_NOW);
    lenient().when(proxyCert.getExpirationTime()).thenReturn(Date.from(ONE_YEAR_FROM_NOW));
    lenient().when(proxyCert.getCertificate()).thenReturn(mockedTest0Cert);

    lenient().when(proxyCert.getChain()).thenReturn(pemProxy);


    lenient().when(account.getX509Certificates()).thenReturn(Sets.newHashSet(mockedTest0Cert));
    lenient().when(accountRepo.findByUsername(TEST_USER_USERNAME)).thenReturn(Optional.of(account));

    ProxyCertificateDTO dto = proxyService.generateProxy(principal, request);

    Instant notAfter = dto.getNotAfter().toInstant();

    assertThat(Duration.between(NOW, notAfter)
      .compareTo(Duration.ofSeconds(DEFAULT_PROXY_LIFETIME_SECONDS)), is(0));
  }


  @Test
  void testRequestIssuerIsHonoured() throws InvalidKeyException, CertificateParsingException,
      SignatureException, NoSuchAlgorithmException, IOException {

    IamX509Certificate mockedTest0Cert = spy(TEST_0_IAM_X509_CERT);
    lenient().when(mockedTest0Cert.getProxy()).thenReturn(proxyCert);

    lenient().when(request.getIssuer()).thenReturn("CN=A custom issuer");
    lenient().when(account.getX509Certificates()).thenReturn(Sets.newHashSet(mockedTest0Cert));
    lenient().when(accountRepo.findByUsername(TEST_USER_USERNAME)).thenReturn(Optional.of(account));

    assertThrows(ProxyNotFoundError.class, () -> proxyService.generateProxy(principal, request));

  }

  @Test
  void testListProxies() throws InvalidKeyException, CertificateParsingException,
      SignatureException, NoSuchAlgorithmException, IOException {

    IamX509Certificate mockedTest0Cert = spy(TEST_0_IAM_X509_CERT);
    lenient().when(mockedTest0Cert.getProxy()).thenReturn(proxyCert);
    lenient().when(proxyCert.getExpirationTime()).thenReturn(Date.from(ONE_YEAR_FROM_NOW));
    lenient().when(proxyCert.getCertificate()).thenReturn(mockedTest0Cert);

    lenient().when(account.getX509Certificates()).thenReturn(Sets.newHashSet(mockedTest0Cert));
    lenient().when(accountRepo.findByUsername(TEST_USER_USERNAME)).thenReturn(Optional.of(account));

    List<ProxyCertificateDTO> proxies = proxyService.listProxies(principal);
    assertThat(proxies, hasSize(1));
    assertThat(proxies.get(0).getSubject(), endsWith(TEST_0_SUBJECT));
  }

  @Test
  void testListProxiesNoResults() throws InvalidKeyException, CertificateParsingException,
      SignatureException, NoSuchAlgorithmException, IOException {

    IamX509Certificate mockedTest0Cert = spy(TEST_0_IAM_X509_CERT);
    lenient().when(account.getX509Certificates()).thenReturn(Sets.newHashSet(mockedTest0Cert));
    lenient().when(accountRepo.findByUsername(TEST_USER_USERNAME)).thenReturn(Optional.of(account));

    List<ProxyCertificateDTO> proxies = proxyService.listProxies(principal);
    assertThat(proxies, hasSize(0));
  }
}
