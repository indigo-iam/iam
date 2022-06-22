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
package it.infn.mw.iam.rcauth;

import static eu.emi.security.authn.x509.impl.X500NameUtils.getReadableForm;
import static it.infn.mw.iam.api.utils.ValidationErrorUtils.stringifyValidationError;
import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_DASHBOARD_ERROR_KEY;
import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.ACCOUNT_LINKING_DASHBOARD_MESSAGE_KEY;
import static it.infn.mw.iam.authn.x509.X509CertificateVerificationResult.success;
import static java.lang.String.format;
import static org.springframework.web.bind.annotation.RequestMethod.GET;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Date;

import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

import eu.emi.security.authn.x509.proxy.ProxyCertificate;
import it.infn.mw.iam.api.account_linking.DefaultAccountLinkingService;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;
import it.infn.mw.iam.rcauth.x509.ProxyHelperService;

@Controller
@ConditionalOnProperty(name = "rcauth.enabled", havingValue = "true")
public class RCAuthController {

  public static final String GETCERT_PATH = "/rcauth/getcert";
  public static final String CALLBACK_PATH = "/rcauth/cb";

  public static final String VALIDATION_ERROR_TEMPLATE =
      "Invalid RCAuth authorization response: %s";

  public static final String RCAUTH_ERROR_TEMPLATE = "RCAuth error: %s";
  public static final String RCAUTH_SUCCESS_TEMPLATE =
      "Proxy certificate with subject '%s' linked succesfully";

  final Clock clock;
  final RCAuthRequestService requestService;
  final ProxyHelperService proxyHelper;
  final DefaultAccountLinkingService linkingService;

  @Autowired
  public RCAuthController(Clock clock, RCAuthRequestService service, ProxyHelperService proxyHelper,
      DefaultAccountLinkingService ls) {
    this.clock = clock;
    this.requestService = service;
    this.proxyHelper = proxyHelper;
    this.linkingService = ls;
  }

  @RequestMapping(method = GET, value = GETCERT_PATH)
  public RedirectView requestCert(HttpSession session) {
    return new RedirectView(requestService.buildAuthorizationRequest(session));
  }


  @RequestMapping(method = GET, value = CALLBACK_PATH)
  public String rcauthCallback(Principal authenticatedUser, HttpSession session,
      RedirectAttributes attributes, @Valid RCAuthAuthorizationResponse response,
      final BindingResult validationResult) {

    if (validationResult.hasErrors()) {
      attributes.addFlashAttribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY,
          format(VALIDATION_ERROR_TEMPLATE, stringifyValidationError(validationResult)));
    } else {

      try {

        RCAuthExchangeContext ctx =
            requestService.handleAuthorizationCodeResponse(session, response);

        ProxyCertificate proxy = proxyHelper.generateProxy(ctx.getCertificate(),
            ctx.getCertificateRequest().getKeyPair().getPrivate());

        String proxyPem = proxyHelper.proxyCertificateToPemString(proxy);

        final String certificateSubject =
            getReadableForm(ctx.getCertificate().getSubjectX500Principal());

        IamX509AuthenticationCredential cred = IamX509AuthenticationCredential.builder()
          .certificateChain(new X509Certificate[] {ctx.getCertificate()})
          .subject(certificateSubject)
          .issuer(getReadableForm(ctx.getCertificate().getIssuerX500Principal()))
          .verificationResult(success())
          .build();

        linkingService.linkX509ProxyCertificate(authenticatedUser, cred, proxyPem,
            Date.from(clock.instant()));

        attributes.addFlashAttribute(ACCOUNT_LINKING_DASHBOARD_MESSAGE_KEY,
            format(RCAUTH_SUCCESS_TEMPLATE, certificateSubject));
      } catch (RCAuthError e) {
        attributes.addFlashAttribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY,
            format(RCAUTH_ERROR_TEMPLATE, e.getMessage()));
      }
    }

    return "redirect:/dashboard";
  }

}
