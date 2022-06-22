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

import java.util.List;
import java.util.UUID;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.impl.SignatureBuilder;

import com.google.common.collect.Lists;

import it.infn.mw.iam.authn.saml.util.Saml2Attribute;
import it.infn.mw.iam.authn.saml.util.SamlAttributeNames;

public class SamlAssertionBuilder {

  final Credential serviceCredential;

  final XMLObjectBuilderFactory builderFactory;

  String issuer;

  String recipient;

  String subject;

  String requestId;

  String nameId;

  String audience;

  String nameIdFormat = NameID.PERSISTENT;

  DateTime issueInstant;

  DateTime authnInstant;

  DateTime expirationTime;

  List<Attribute> attributes = Lists.newArrayList();

  KeyInfoGenerator keyInfoGenerator;

  AttributeBuilder attributeBuilder;


  public SamlAssertionBuilder issuer(String issuer) {
    this.issuer = issuer;
    return this;
  }

  public SamlAssertionBuilder recipient(String recipient) {
    this.recipient = recipient;
    return this;
  }

  public SamlAssertionBuilder subject(String subject) {
    this.subject = subject;
    return this;
  }

  public SamlAssertionBuilder requestId(String requestId) {
    this.requestId = requestId;
    return this;
  }

  public SamlAssertionBuilder nameId(String nameId) {
    this.nameId = nameId;
    return this;
  }

  public SamlAssertionBuilder nameIdFormat(String nameIdFormat) {
    this.nameIdFormat = nameIdFormat;
    return this;
  }

  public SamlAssertionBuilder issueInstant(DateTime dt) {
    this.issueInstant = dt;
    return this;
  }

  public SamlAssertionBuilder expirationTime(DateTime dt) {
    this.expirationTime = dt;
    return this;
  }

  public SamlAssertionBuilder audience(String audience) {
    this.audience = audience;
    return this;
  }

  public SamlAssertionBuilder singleStringValuedAttribute(String name, String value) {
    this.attributes.add(buildStringAttribute(name, value));
    return this;
  }


  private AudienceRestriction buildAudienceRestriction() {
    AudienceRestrictionBuilder arb = (AudienceRestrictionBuilder) builderFactory
      .getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);

    AudienceRestriction ar = arb.buildObject();
    Audience aud =
	((AudienceBuilder) builderFactory.getBuilder(Audience.DEFAULT_ELEMENT_NAME)).buildObject();

    aud.setAudienceURI(audience);
    ar.getAudiences().add(aud);

    return ar;
  }

  private AuthnStatement buildAuthenticationStatement() {
    AuthnStatementBuilder asb =
	(AuthnStatementBuilder) builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);

    AuthnStatement as = asb.buildObject();

    if (authnInstant == null) {
      as.setAuthnInstant(issueInstant);
    } else {
      as.setAuthnInstant(authnInstant);
    }

    as.setSessionIndex("_" + UUID.randomUUID().toString());
    as.setSessionNotOnOrAfter(expirationTime);

    AuthnContext ac =
	((AuthnContextBuilder) builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME))
	  .buildObject();

    AuthnContextClassRefBuilder accrb = (AuthnContextClassRefBuilder) builderFactory
      .getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);

    AuthnContextClassRef accr = accrb.buildObject();
    accr.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

    ac.setAuthnContextClassRef(accr);

    return as;
  }

  private Attribute buildEPTIDAttribute() {
    Attribute attr = attributeBuilder.buildObject();
    attr.setName(Saml2Attribute.EPTID.getAttributeName());
    attr.setNameFormat(Attribute.URI_REFERENCE);
    
    @SuppressWarnings("unchecked")
    SAMLObjectBuilder<NameID> niBuilder =
    (SAMLObjectBuilder<NameID>) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
    
    
    NameID nid = niBuilder.buildObject();
    nid.setValue(nameId);
    nid.setFormat(nameIdFormat);
    
    XMLObjectBuilderFactory bf = Configuration.getBuilderFactory();
    XSAnyBuilder builder = (XSAnyBuilder) bf.getBuilder(XSAny.TYPE_NAME);
    XSAny attrVal = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
    
    
    attrVal.getUnknownXMLObjects().add(nid);
    attr.getAttributeValues().add(attrVal);
    
    return attr;
  }
  
  
  private Attribute buildStringAttribute(String name, String value) {
    Attribute attr = attributeBuilder.buildObject();
    attr.setName(name);
    attr.setNameFormat(Attribute.URI_REFERENCE);

    XSStringBuilder attributeValueBuilder =
	(XSStringBuilder) builderFactory.getBuilder(XSString.TYPE_NAME);

    XSString xsString =
	attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);

    xsString.setValue(value);

    attr.getAttributeValues().add(xsString);
    return attr;
  }
  
  public SamlAssertionBuilder eptid() {
    attributes.add(buildEPTIDAttribute());
    return this;
  }

  public SamlAssertionBuilder eppn(String eppn) {

    attributes.add(buildStringAttribute(SamlAttributeNames.eduPersonPrincipalName, eppn));
    return this;

  }

  public SamlAssertionBuilder epuid(String epuid) {

    attributes.add(buildStringAttribute(SamlAttributeNames.eduPersonUniqueId, epuid));
    return this;

  }

  public SamlAssertionBuilder givenName(String givenName) {

    attributes.add(buildStringAttribute(SamlAttributeNames.givenName, givenName));
    return this;

  }

  public SamlAssertionBuilder sn(String surname) {

    attributes.add(buildStringAttribute(SamlAttributeNames.sn, surname));
    return this;

  }

  public SamlAssertionBuilder mail(String mail) {

    attributes.add(buildStringAttribute(SamlAttributeNames.mail, mail));
    return this;

  }

  public SamlAssertionBuilder(Credential serviceCredential, String issuer) {
    this.issuer = issuer;
    this.builderFactory = Configuration.getBuilderFactory();
    this.serviceCredential = serviceCredential;

    X509KeyInfoGeneratorFactory x509KeyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
    x509KeyInfoGeneratorFactory.setEmitEntityCertificate(true);

    KeyInfoGeneratorManager keyInfoGeneratorManager = new KeyInfoGeneratorManager();
    keyInfoGeneratorManager.registerFactory(x509KeyInfoGeneratorFactory);

    keyInfoGenerator = keyInfoGeneratorManager.getFactory(serviceCredential).newInstance();
    attributeBuilder = (AttributeBuilder) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);

  }


  private Issuer buildIssuer() {
    @SuppressWarnings("unchecked")
    SAMLObjectBuilder<Issuer> builder =
	(SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

    Issuer iss = builder.buildObject();
    iss.setValue(issuer);

    return iss;
  }

  private SubjectConfirmation buildSubjectConfirmation() {
    @SuppressWarnings("unchecked")
    SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder =
	(SAMLObjectBuilder<SubjectConfirmation>) builderFactory
	  .getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);

    SubjectConfirmation sc = subjectConfirmationBuilder.buildObject();

    sc.setMethod(SubjectConfirmation.METHOD_BEARER);

    @SuppressWarnings("unchecked")
    SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmationDataBuilder =
	(SAMLObjectBuilder<SubjectConfirmationData>) builderFactory
	  .getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);

    SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();
    subjectConfirmationData.setRecipient(recipient);
    subjectConfirmationData.setInResponseTo(requestId);

    if (expirationTime == null) {
      expirationTime = issueInstant.plusHours(1);
    }

    subjectConfirmationData.setNotOnOrAfter(expirationTime);

    sc.setSubjectConfirmationData(subjectConfirmationData);
    return sc;

  }

  private NameID buildNameID() {
    @SuppressWarnings("unchecked")
    SAMLObjectBuilder<NameID> niBuilder =
    (SAMLObjectBuilder<NameID>) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);

    NameID nid = niBuilder.buildObject();
    nid.setValue(nameId);
    nid.setFormat(nameIdFormat);
    
    return nid;
  }
  
  private Subject buildSubject() {

    @SuppressWarnings("unchecked")
    SAMLObjectBuilder<Subject> builder =
	(SAMLObjectBuilder<Subject>) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);

    Subject sub = builder.buildObject();

    sub.setNameID(buildNameID());

    sub.getSubjectConfirmations().add(buildSubjectConfirmation());

    return sub;
  }

  private Conditions buildConditions() {

    @SuppressWarnings("unchecked")
    SAMLObjectBuilder<Conditions> cb =
	(SAMLObjectBuilder<Conditions>) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);

    Conditions conditions = cb.buildObject();
    conditions.setNotBefore(issueInstant);
    conditions.setNotOnOrAfter(issueInstant.plusHours(1));

    conditions.getAudienceRestrictions().add(buildAudienceRestriction());
    return conditions;
  }

  private AttributeStatement buildAttributeStatement() {
    @SuppressWarnings("unchecked")
    SAMLObjectBuilder<AttributeStatement> asb =
	(SAMLObjectBuilder<AttributeStatement>) builderFactory
	  .getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);

    AttributeStatement as = asb.buildObject();
    as.getAttributes().addAll(attributes);

    return as;
  }

  private KeyInfo buildKeyInfo() throws SecurityException {

    return keyInfoGenerator.generate(serviceCredential);

  }

  private Signature buildSignature() throws SecurityException {
    SignatureBuilder signatureBuilder =
	(SignatureBuilder) builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME);

    Signature assertionSignature = signatureBuilder.buildObject();
    assertionSignature.setSigningCredential(serviceCredential);
    assertionSignature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
    assertionSignature.setSignatureAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA);

    assertionSignature.setKeyInfo(buildKeyInfo());

    return assertionSignature;

  }


  public Assertion build() throws SecurityException, SignatureException, MarshallingException {

    @SuppressWarnings("unchecked")
    SAMLObjectBuilder<Assertion> builder =
	(SAMLObjectBuilder<Assertion>) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

    Assertion assertion = builder.buildObject();

    assertion.setID("_" + UUID.randomUUID().toString());

    if (issueInstant == null) {
      issueInstant = DateTime.now();
    }

    assertion.setIssuer(buildIssuer());
    assertion.setIssueInstant(issueInstant);

    assertion.getAuthnStatements().add(buildAuthenticationStatement());

    assertion.setSubject(buildSubject());
    assertion.setConditions(buildConditions());

    assertion.getAttributeStatements().add(buildAttributeStatement());

    assertion.setSignature(buildSignature());

    return assertion;
  }
}
