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
package it.infn.mw.voms.api;

import static java.lang.String.format;

import java.io.IOException;
import java.text.SimpleDateFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;
import it.infn.mw.voms.aa.AttributeAuthority;
import it.infn.mw.voms.aa.RequestContextFactory;
import it.infn.mw.voms.aa.VOMSErrorMessage;
import it.infn.mw.voms.aa.VOMSRequest;
import it.infn.mw.voms.aa.VOMSRequestContext;
import it.infn.mw.voms.aa.VOMSResponse;
import it.infn.mw.voms.aa.ac.ACGenerator;
import it.infn.mw.voms.aa.ac.VOMSResponseBuilder;
import it.infn.mw.voms.properties.VomsProperties;


@RestController
@Transactional
public class VOMSController extends VOMSControllerSupport {

  private final Logger log = LoggerFactory.getLogger(VOMSController.class);

  public static final String LEGACY_VOMS_APIS_UA = "voms APIs 2.0";

  private static final SimpleDateFormat DATE_FORMAT =
      new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");

  private final VomsProperties vomsProperties;
  private final AttributeAuthority aa;
  private final ACGenerator acGenerator;
  private final VOMSResponseBuilder responseBuilder;
  private final AUPSignatureCheckService signatureCheckService;

  public VOMSController(AttributeAuthority aa, VomsProperties props, ACGenerator acGenerator,
      VOMSResponseBuilder responseBuilder, AUPSignatureCheckService signatureCheckService) {
    this.aa = aa;
    this.vomsProperties = props;
    this.acGenerator = acGenerator;
    this.responseBuilder = responseBuilder;
    this.signatureCheckService = signatureCheckService;
  }

  protected VOMSRequestContext initVomsRequestContext(IamX509AuthenticationCredential cred,
      VOMSRequestDTO request, String userAgent) {
    VOMSRequestContext context = RequestContextFactory.newContext();

    context.getRequest().setRequesterSubject(cred.getSubject());
    context.getRequest().setRequesterIssuer(cred.getIssuer());
    context.getRequest().setHolderSubject(cred.getSubject());
    context.getRequest().setHolderIssuer(cred.getIssuer());
    context.getRequest().setHolderCert(cred.getCertificateChain()[0]);

    context.setHost(vomsProperties.getAa().getHost());
    context.setPort(vomsProperties.getAa().getPort());
    context.setVOName(vomsProperties.getAa().getVoName());
    context.setUserAgent(userAgent);

    context.getRequest().setRequestedFQANs(parseRequestedFqansString(request.getFqans()));
    context.getRequest().setRequestedValidity(getRequestedLifetime(request.getLifetime()));
    context.getRequest().setTargets(parseRequestedTargetsString(request.getTargets()));

    return context;
  }


  @GetMapping(value = "/generate-ac", produces = "text/xml; charset=utf-8")
  @PreAuthorize("hasRole('USER') and hasRole('X509')")
  public String generateAC(@RequestHeader(name = "User-Agent", required = false) String userAgent,
      @Validated VOMSRequestDTO request, BindingResult validationResult,
      Authentication authentication) throws IOException {

    if (validationResult.hasErrors()) {
      VOMSErrorMessage em =
          VOMSErrorMessage.badRequest(validationResult.getAllErrors().get(0).getDefaultMessage());
      return responseBuilder.createErrorResponse(em);
    }

    IamX509AuthenticationCredential cred =
        (IamX509AuthenticationCredential) authentication.getCredentials();

    VOMSRequestContext context = initVomsRequestContext(cred, request, userAgent);
    logRequest(context);

    if (!aa.getAttributes(context)) {

      VOMSErrorMessage em = context.getResponse().getErrorMessages().get(0);

      String responseString;
      if (LEGACY_VOMS_APIS_UA.equals(userAgent)) {
        responseString = responseBuilder.createLegacyErrorResponse(em);
      } else {
        responseString = responseBuilder.createErrorResponse(em);
      }
      logOutcome(context);
      return responseString;
    } else {
      IamAccount user = context.getIamAccount();
      if (signatureCheckService.needsAupSignature(user)) {
        VOMSErrorMessage em = VOMSErrorMessage.faildToSignAup(user.getUsername());
        return responseBuilder.createErrorResponse(em);
      }
      byte[] acBytes = acGenerator.generateVOMSAC(context);
      String responseString =
          responseBuilder.createResponse(acBytes, context.getResponse().getWarnings());
      logOutcome(context);
      return responseString;
    }
  }

  private void logRequest(VOMSRequestContext c) {
    VOMSRequest r = c.getRequest();
    log.debug(
        "VOMSRequest: [holderIssuer: {}, holderSubject: {}, requesterIssuer: {}, requesterSubject: {}, attributes: {}, FQANs: {}, validity: {}, targets: {}]",
        sanitize(r.getHolderIssuer()), sanitize(r.getHolderSubject()),
        sanitize(r.getRequesterIssuer()), sanitize(r.getRequesterSubject()),
        r.getRequestAttributes(), r.getRequestedFQANs(), r.getRequestedValidity(), r.getTargets());
  }

  private String sanitize(String str) {
    return str.replaceAll("[\n\r]", "_");
  }

  private String userStr(VOMSRequestContext c) {
    String username = c.getIamAccount().getUsername();
    String uuid = c.getIamAccount().getUuid();
    String reqSubject = sanitize(c.getRequest().getRequesterSubject());
    String reqIssuer = sanitize(c.getRequest().getRequesterIssuer());
    return format("[username: %s, uuid: %s, subjectDN: %s, issuerDN: %s]", username, uuid,
        reqSubject, reqIssuer);
  }

  private String errorResponse(VOMSRequestContext c) {
    return format("[outcome: %s, errorMessages: %s]", c.getResponse().getOutcome().name(),
        c.getResponse().getErrorMessages());
  }

  private String successResponse(VOMSRequestContext c) {
    VOMSResponse r = c.getResponse();
    return format(
        "[outcome: %s, VO: %s, uri: %s, targets: %s, issuedFQANs: %s, notAfter: %s, notBefore: %s]",
        r.getOutcome().name(), c.getVOName(), c.getHost() + ":" + c.getPort(),
        r.getTargets().toString(), r.getIssuedFQANs().toString(),
        DATE_FORMAT.format(r.getNotAfter()), DATE_FORMAT.format(r.getNotBefore()));
  }

  private void logOutcome(VOMSRequestContext c) {
    switch (c.getResponse().getOutcome()) {
      case SUCCESS:
        log.info("User {} got successful VOMS response {} ", userStr(c), successResponse(c));
        break;
      case FAILURE:
        log.info("User {} got failure VOMS response {}", userStr(c), errorResponse(c));
        break;
    }
  }
}
