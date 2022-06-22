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

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;
import it.infn.mw.voms.aa.AttributeAuthority;
import it.infn.mw.voms.aa.RequestContextFactory;
import it.infn.mw.voms.aa.VOMSErrorMessage;
import it.infn.mw.voms.aa.VOMSRequestContext;
import it.infn.mw.voms.aa.ac.ACGenerator;
import it.infn.mw.voms.aa.ac.VOMSResponseBuilder;
import it.infn.mw.voms.properties.VomsProperties;


@RestController
@Transactional
public class VOMSController extends VOMSControllerSupport {

  public static final String LEGACY_VOMS_APIS_UA = "voms APIs 2.0";

  private final VomsProperties vomsProperties;
  private final AttributeAuthority aa;
  private final ACGenerator acGenerator;
  private final VOMSResponseBuilder responseBuilder;

  @Autowired
  public VOMSController(AttributeAuthority aa, VomsProperties props, ACGenerator acGenerator,
      VOMSResponseBuilder responseBuilder) {
    this.aa = aa;
    this.vomsProperties = props;
    this.acGenerator = acGenerator;
    this.responseBuilder = responseBuilder;
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

    if (!aa.getAttributes(context)) {

      VOMSErrorMessage em = context.getResponse().getErrorMessages().get(0);

      if (LEGACY_VOMS_APIS_UA.equals(userAgent)) {
        return responseBuilder.createLegacyErrorResponse(em);
      } else {
        return responseBuilder.createErrorResponse(em);
      }

    } else {
      byte[] acBytes = acGenerator.generateVOMSAC(context);
      return responseBuilder.createResponse(acBytes, context.getResponse().getWarnings());
    }
  }
}
