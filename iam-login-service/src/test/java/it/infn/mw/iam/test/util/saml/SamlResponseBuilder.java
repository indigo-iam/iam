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
package it.infn.mw.iam.test.util.saml;

import java.util.UUID;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.SignatureBuilder;

public class SamlResponseBuilder {

  final Credential issuerCredential;

  String issuer;

  DateTime issueInstant;

  String requestId;

  Assertion assertion;

  StatusCode statusCode;

  String statusMessage;

  String recipient;

  KeyInfoGenerator keyInfoGenerator;

  public SamlResponseBuilder(Credential issuerCredential, String issuer) {
    this.issuerCredential = issuerCredential;
    this.issuer = issuer;

    X509KeyInfoGeneratorFactory x509KeyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
    x509KeyInfoGeneratorFactory.setEmitEntityCertificate(true);

    KeyInfoGeneratorManager keyInfoGeneratorManager = new KeyInfoGeneratorManager();
    keyInfoGeneratorManager.registerFactory(x509KeyInfoGeneratorFactory);

    keyInfoGenerator = keyInfoGeneratorManager.getFactory(issuerCredential).newInstance();
  }

  public SamlResponseBuilder requestId(String requestId) {
    this.requestId = requestId;
    return this;
  }

  public SamlResponseBuilder issueInstant(DateTime issueInstant) {
    this.issueInstant = issueInstant;
    return this;
  }

  public SamlResponseBuilder assertion(Assertion assertion) {
    this.assertion = assertion;
    return this;
  }

  public SamlResponseBuilder status(StatusCode statusCode) {
    this.statusCode = statusCode;
    return this;
  }

  public SamlResponseBuilder statusMessage(String statusMessage) {
    this.statusMessage = statusMessage;
    return this;
  }

  public SamlResponseBuilder recipient(String recipient) {
    this.recipient = recipient;
    return this;
  }

  private Status buildStatus() {

    StatusCodeBuilder statusCodeBuilder = (StatusCodeBuilder) Configuration.getBuilderFactory()
      .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);

    StatusCode sc = statusCode;

    if (statusCode == null) {
      sc = statusCodeBuilder.buildObject();
      sc.setValue(StatusCode.SUCCESS_URI);
    }

    StatusBuilder sb =
	(StatusBuilder) Configuration.getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);

    Status s = sb.buildObject();
    s.setStatusCode(sc);

    if (statusMessage != null) {
      StatusMessageBuilder smb = (StatusMessageBuilder) Configuration.getBuilderFactory()
	.getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);

      StatusMessage sm = smb.buildObject();
      sm.setMessage(statusMessage);
      s.setStatusMessage(sm);
    }

    return s;

  }

  private Response buildResponse() {

    IssuerBuilder issuerBuilder =
	(IssuerBuilder) Configuration.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);


    Issuer responseIssuer = issuerBuilder.buildObject();

    responseIssuer.setValue(issuer);

    ResponseBuilder responseBuilder = (ResponseBuilder) Configuration.getBuilderFactory()
      .getBuilder(Response.DEFAULT_ELEMENT_NAME);

    Response response = responseBuilder.buildObject();
    response.setID("_" + UUID.randomUUID().toString());

    if (issueInstant == null) {
      response.setIssueInstant(DateTime.now());
    } else {
      response.setIssueInstant(issueInstant);
    }

    response.setInResponseTo(requestId);

    response.setIssuer(responseIssuer);

    return response;

  }

  private Signature buildSignature() throws SecurityException {

    SignatureBuilder signatureBuilder = (SignatureBuilder) Configuration.getBuilderFactory()
      .getBuilder(Signature.DEFAULT_ELEMENT_NAME);

    Signature responseSignature = signatureBuilder.buildObject();
    responseSignature.setSigningCredential(issuerCredential);
    responseSignature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
    responseSignature.setSignatureAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA);

    responseSignature.setKeyInfo(keyInfoGenerator.generate(issuerCredential));

    return responseSignature;
  }

  public Response build() throws SecurityException {

    Status s = buildStatus();
    Response r = buildResponse();

    if (recipient != null) {
      r.setDestination(recipient);
    }

    r.setStatus(s);

    if (assertion != null) {
      r.getAssertions().add(assertion);
    }

    r.setSignature(buildSignature());

    return r;
  }

}
