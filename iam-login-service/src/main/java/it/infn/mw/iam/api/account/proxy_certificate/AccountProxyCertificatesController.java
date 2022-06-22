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
package it.infn.mw.iam.api.account.proxy_certificate;

import static it.infn.mw.iam.api.utils.ValidationErrorUtils.stringifyValidationError;
import static java.lang.String.format;
import static org.springframework.web.bind.annotation.RequestMethod.PUT;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.emi.security.authn.x509.proxy.ProxyUtils;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account_linking.AccountLinkingService;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.api.proxy.InvalidProxyRequestError;
import it.infn.mw.iam.api.proxy.ProxyCertificateDTO;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;
import it.infn.mw.iam.authn.x509.X509CertificateVerificationResult;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.rcauth.x509.ProxyGenerationError;
import it.infn.mw.iam.rcauth.x509.ProxyHelperService;

@RestController
public class AccountProxyCertificatesController {

  public static final String INVALID_PROXY_TEMPLATE = "Invalid proxy certificate: %s";

  private final AccountUtils accountUtils;
  private final AccountLinkingService linkingService;
  private final ProxyHelperService proxyHelperService;

  @Autowired
  public AccountProxyCertificatesController(AccountUtils accountUtils,
      IamAccountRepository accountRepo, AccountLinkingService linkingService,
      ProxyHelperService proxyHelperService) {
    this.accountUtils = accountUtils;
    this.linkingService = linkingService;
    this.proxyHelperService = proxyHelperService;
  }

  private void handleValidationError(BindingResult result) {
    if (result.hasErrors()) {
      throw new InvalidProxyRequestError(
          format(INVALID_PROXY_TEMPLATE, stringifyValidationError(result)));
    }
  }

  @RequestMapping(value = "/iam/account/me/proxycert", method = PUT)
  @PreAuthorize("hasRole('USER')")
  public void addProxyCertificate(
      @RequestBody @Validated(
          value = ProxyCertificateDTO.AddProxyCertValidation.class) ProxyCertificateDTO proxyCert,
      final BindingResult validationResult, Principal authenticatedUser) {

    handleValidationError(validationResult);

    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(() -> NoSuchAccountError.forUsername(authenticatedUser.getName()));

    PEMCredential proxyCredential =
        proxyHelperService.credentialFromPemString(proxyCert.getCertificateChain());

    X509Certificate eec = ProxyUtils.getEndUserCertificate(proxyCredential.getCertificateChain());

    final String eecSubject = X500NameUtils.getReadableForm(eec.getSubjectX500Principal());

    if (account.getX509Certificates()
      .stream()
      .noneMatch(c -> c.getSubjectDn().equals(eecSubject))) {

      throw new InvalidProxyRequestError(
          format("Invalid proxy: user '%s' does not own certificate '%s'", account.getUsername(),
              eecSubject));
    }

    Date proxyCertificateExpiration = eec.getNotAfter();

    // The chain expiration time is the expiration time of the "shorter" proxy in the chain
    for (X509Certificate c : proxyCredential.getCertificateChain()) {
      if (ProxyUtils.isProxy(c) && c.getNotAfter().before(proxyCertificateExpiration)) {
        proxyCertificateExpiration = c.getNotAfter();
      }
    }
    IamX509AuthenticationCredential cred = IamX509AuthenticationCredential.builder()
      .certificateChain(new X509Certificate[] {eec})
      .subject(eecSubject)
      .issuer(X500NameUtils.getReadableForm(eec.getIssuerX500Principal()))
      .verificationResult(X509CertificateVerificationResult.success())
      .build();

    linkingService.linkX509ProxyCertificate(authenticatedUser, cred,
        proxyCert.getCertificateChain(), proxyCertificateExpiration);
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidProxyRequestError.class)
  @ResponseBody
  public ErrorDTO handleValidationError(Exception e) {
    return ErrorDTO.fromString(e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(ProxyGenerationError.class)
  @ResponseBody
  public ErrorDTO handleProxyParseError(Exception e) {
    return ErrorDTO.fromString(e.getMessage());
  }

}
