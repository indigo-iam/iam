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
package it.infn.mw.iam.test.ext_authn.saml;

import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.springframework.security.saml.SAMLCredential;

import it.infn.mw.iam.authn.saml.util.ChainedCollectingSamlIdResolver;
import it.infn.mw.iam.authn.saml.util.EPTIDUserIdentifierResolver;
import it.infn.mw.iam.authn.saml.util.NameIdUserIdentifierResolver;
import it.infn.mw.iam.authn.saml.util.NamedSamlUserIdentifierResolver;
import it.infn.mw.iam.authn.saml.util.PersistentNameIdUserIdentifierResolver;
import it.infn.mw.iam.authn.saml.util.Saml2Attribute;
import it.infn.mw.iam.authn.saml.util.SamlIdResolvers;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolutionResult;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolver;
import it.infn.mw.iam.persistence.model.IamSamlId;

class ResolverTests {

  @Test
  void testSamlIdResolverAttributeResolution() {
    SamlIdResolvers resolvers = new SamlIdResolvers();

    for (Saml2Attribute a : Saml2Attribute.values()) {
      assertNotNull(resolvers.byName(a.getAlias()));
    }
  }

  @Test
  void emptyNameIdResolverTest() {

    SAMLCredential cred = Mockito.mock(SAMLCredential.class);
    Mockito.when(cred.getNameID()).thenReturn(null);

    SamlUserIdentifierResolver resolver = new NameIdUserIdentifierResolver();

    Optional<IamSamlId> resolvedId =
        resolver.resolveSamlUserIdentifier(cred).getResolvedIds().stream().findFirst();

    assertFalse(resolvedId.isPresent());
  }

  @Test
  void nameIdResolverTest() {
    NameID nameId = Mockito.mock(NameID.class);
    Mockito.when(nameId.getValue()).thenReturn("nameid");
    Mockito.when(nameId.getFormat()).thenReturn("format");

    SAMLCredential cred = Mockito.mock(SAMLCredential.class);
    Mockito.when(cred.getNameID()).thenReturn(nameId);
    Mockito.when(cred.getRemoteEntityID()).thenReturn("entityId");


    SamlUserIdentifierResolver resolver = new NameIdUserIdentifierResolver();

    IamSamlId resolvedId = resolver.resolveSamlUserIdentifier(cred)
      .getResolvedIds()
      .stream()
      .findFirst()
      .orElseThrow(() -> new AssertionError("Could not resolve nameid SAML ID"));

    assertThat(resolvedId.getUserId(), Matchers.equalTo("nameid"));
    assertThat(resolvedId.getIdpId(), Matchers.equalTo("entityId"));
    assertThat(resolvedId.getAttributeId(), Matchers.equalTo("format"));
  }

  @Test
  void persistentNameIdResolverTest() {
    NameID nameId = Mockito.mock(NameID.class);
    Mockito.when(nameId.getValue()).thenReturn("nameid");
    Mockito.when(nameId.getFormat()).thenReturn("format");

    SAMLCredential cred = Mockito.mock(SAMLCredential.class);
    Mockito.when(cred.getNameID()).thenReturn(nameId);
    Mockito.when(cred.getRemoteEntityID()).thenReturn("entityId");

    SamlUserIdentifierResolver resolver = new PersistentNameIdUserIdentifierResolver();

    SamlUserIdentifierResolutionResult result = resolver.resolveSamlUserIdentifier(cred);
    assertThat(result.getResolvedIds().isEmpty(), is(true));
    assertThat(result.getErrorMessages().isEmpty(), is(false));
    assertThat(result.getErrorMessages().get(0),
        containsString("resolved NameID is not persistent"));
  }

  @Test
  void persistentNameIdResolverTestNoNameId() {

    SAMLCredential cred = Mockito.mock(SAMLCredential.class);
    Mockito.when(cred.getRemoteEntityID()).thenReturn("entityId");

    SamlUserIdentifierResolver resolver = new PersistentNameIdUserIdentifierResolver();

    SamlUserIdentifierResolutionResult result = resolver.resolveSamlUserIdentifier(cred);
    assertThat(result.getResolvedIds().isEmpty(), is(true));
    assertThat(result.getErrorMessages().isEmpty(), is(false));
    assertThat(result.getErrorMessages().get(0),
        containsString("NameID element not found in samlAssertion"));
  }

  @Test
  void persistentNameIdResolverTestResolutionSuccess() {
    NameID nameId = Mockito.mock(NameID.class);
    Mockito.when(nameId.getValue()).thenReturn("nameid");
    Mockito.when(nameId.getFormat()).thenReturn(NameIDType.PERSISTENT);

    SAMLCredential cred = Mockito.mock(SAMLCredential.class);
    Mockito.when(cred.getNameID()).thenReturn(nameId);
    Mockito.when(cred.getRemoteEntityID()).thenReturn("entityId");

    SamlUserIdentifierResolver resolver = new PersistentNameIdUserIdentifierResolver();

    SamlUserIdentifierResolutionResult result = resolver.resolveSamlUserIdentifier(cred);
    assertThat(result.getResolvedIds().isEmpty(), is(false));
    assertThat(result.getErrorMessages().isEmpty(), is(true));
    assertThat(result.getResolvedIds().get(0).getUserId(), is("nameid"));
  }

  @Test
  void mailIdResolverTest() {
    SamlIdResolvers resolvers = new SamlIdResolvers();

    SamlUserIdentifierResolver resolver = resolvers.byAttribute(Saml2Attribute.MAIL);

    assertThat(resolver, is(not(nullValue())));

    SAMLCredential cred = Mockito.mock(SAMLCredential.class);
    Mockito.when(cred.getAttributeAsString(Saml2Attribute.MAIL.getAttributeName()))
      .thenReturn("test@test.org");
    Mockito.when(cred.getRemoteEntityID()).thenReturn("entityId");

    IamSamlId resolvedId = resolver.resolveSamlUserIdentifier(cred)
      .getResolvedIds()
      .stream()
      .findFirst()
      .orElseThrow(() -> new AssertionError("Could not resolve email address SAML ID"));

    assertThat(resolvedId.getUserId(), equalTo("test@test.org"));
    assertThat(resolvedId.getAttributeId(), equalTo(Saml2Attribute.MAIL.getAttributeName()));

    assertThat(resolvedId.getIdpId(), equalTo("entityId"));
  }

  @Test
  void attributeNotFoundResolverTest() {

    SamlIdResolvers resolvers = new SamlIdResolvers();
    SamlUserIdentifierResolver resolver = resolvers.byAttribute(Saml2Attribute.SUBJECT_ID);
    assertThat(resolver, is(not(nullValue())));

    SAMLCredential cred = Mockito.mock(SAMLCredential.class);
    Mockito.when(cred.getAttributeAsString(Saml2Attribute.MAIL.getAttributeName()))
      .thenReturn("test@test.org");
    Mockito.when(cred.getRemoteEntityID()).thenReturn("entityId");

    SamlUserIdentifierResolutionResult result = resolver.resolveSamlUserIdentifier(cred);
    assertThat(result.getResolvedIds().isEmpty(), is(true));
    assertThat(result.getErrorMessages().isEmpty(), is(false));

    assertThat(result.getErrorMessages().get(0),
        containsString(format("Attribute '%s:%s' not found in assertion",
            Saml2Attribute.SUBJECT_ID.getAlias(), Saml2Attribute.SUBJECT_ID.getAttributeName())));
  }

  @Test
  void ChainedResolverReturnsErrorsIfNoMatchedSamlIds() {

    SamlIdResolvers resolvers = new SamlIdResolvers();

    SamlUserIdentifierResolver subjectIdResolver = resolvers.byAttribute(Saml2Attribute.SUBJECT_ID);

    SamlUserIdentifierResolver uniqueIdResolver = resolvers.byAttribute(Saml2Attribute.EPUID);

    SamlUserIdentifierResolver persistentNameIdResolver =
        new PersistentNameIdUserIdentifierResolver();

    SAMLCredential cred = Mockito.mock(SAMLCredential.class);
    when(cred.getAttributeAsString(Saml2Attribute.MAIL.getAttributeName()))
      .thenReturn("test@test.org");
    when(cred.getRemoteEntityID()).thenReturn("entityId");

    SamlUserIdentifierResolver resolver = new ChainedCollectingSamlIdResolver(
        asList(subjectIdResolver, uniqueIdResolver, persistentNameIdResolver));

    SamlUserIdentifierResolutionResult result = resolver.resolveSamlUserIdentifier(cred);
    assertThat(result.getResolvedIds().isEmpty(), is(true));
    assertThat(result.getErrorMessages().isEmpty(), is(false));
    assertThat(result.getErrorMessages().size(), is(3));
    assertThat(result.getErrorMessages().get(0),
        containsString(format("Attribute '%s:%s' not found in assertion",
            Saml2Attribute.SUBJECT_ID.getAlias(), Saml2Attribute.SUBJECT_ID.getAttributeName())));

    assertThat(result.getErrorMessages().get(1),
        containsString(format("Attribute '%s:%s' not found in assertion",
            Saml2Attribute.EPUID.getAlias(), Saml2Attribute.EPUID.getAttributeName())));

    assertThat(result.getErrorMessages().get(2),
        containsString("NameID element not found in samlAssertion"));
  }

  @Test
  void ChainedResolverTestSuccess() {

    SamlIdResolvers resolvers = new SamlIdResolvers();

    SamlUserIdentifierResolver subjectIdResolver = resolvers.byAttribute(Saml2Attribute.SUBJECT_ID);

    SamlUserIdentifierResolver uniqueIdResolver = resolvers.byAttribute(Saml2Attribute.EPUID);

    SamlUserIdentifierResolver persistentNameIdResolver =
        new PersistentNameIdUserIdentifierResolver();

    SAMLCredential cred = Mockito.mock(SAMLCredential.class);
    when(cred.getAttributeAsString(Saml2Attribute.EPUID.getAttributeName()))
      .thenReturn("123456789@test.org");
    when(cred.getRemoteEntityID()).thenReturn("entityId");

    SamlUserIdentifierResolver resolver = new ChainedCollectingSamlIdResolver(
        asList(subjectIdResolver, uniqueIdResolver, persistentNameIdResolver));

    SamlUserIdentifierResolutionResult result = resolver.resolveSamlUserIdentifier(cred);
    assertThat(result.getResolvedIds().isEmpty(), is(false));
    assertThat(result.getResolvedIds().get(0).getUserId(), is("123456789@test.org"));
  }

  @Test
  void returnAllMatchedSamlIdResolvers() {

    SamlIdResolvers resolvers = new SamlIdResolvers();

    SamlUserIdentifierResolver subjectIdResolver = resolvers.byAttribute(Saml2Attribute.SUBJECT_ID);

    SamlUserIdentifierResolver uniqueIdResolver = resolvers.byAttribute(Saml2Attribute.EPUID);

    SamlUserIdentifierResolver persistentNameIdResolver =
        new PersistentNameIdUserIdentifierResolver();

    SAMLCredential cred = Mockito.mock(SAMLCredential.class);
    when(cred.getAttributeAsString(Saml2Attribute.EPUID.getAttributeName()))
      .thenReturn("123456789@test.org");
    when(cred.getAttributeAsString(Saml2Attribute.SUBJECT_ID.getAttributeName()))
      .thenReturn("subject_id");

    SamlUserIdentifierResolver resolver = new ChainedCollectingSamlIdResolver(
        asList(subjectIdResolver, uniqueIdResolver, persistentNameIdResolver));

    SamlUserIdentifierResolutionResult result = resolver.resolveSamlUserIdentifier(cred);
    assertThat(result.getResolvedIds().isEmpty(), is(false));
    assertThat(result.getResolvedIds().size(), is(2));
    assertThat(result.getResolvedIds().get(0).getUserId(), is("subject_id"));
    assertThat(result.getResolvedIds().get(1).getUserId(), is("123456789@test.org"));
  }

  @Test
  void getNameTest() {

    SamlIdResolvers resolvers = new SamlIdResolvers();
    NamedSamlUserIdentifierResolver subjectIdResolver =
        resolvers.byAttribute(Saml2Attribute.SUBJECT_ID);
    assertThat(subjectIdResolver.getName(), is(Saml2Attribute.SUBJECT_ID.name()));
  }


  @Test
  void epitdAttributeIsRegisteredInResolversTest() {

    SamlIdResolvers resolvers = new SamlIdResolvers();
    SamlUserIdentifierResolver resolver = resolvers.byAttribute(Saml2Attribute.EPTID);
    assertThat(resolver, is(instanceOf(EPTIDUserIdentifierResolver.class)));
  }

  @Test
  void eptidAttributeNotFoundTest() {

    SAMLCredential cred = Mockito.mock(SAMLCredential.class);
    when(cred.getRemoteEntityID()).thenReturn("entityId");

    SamlUserIdentifierResolver resolver = new EPTIDUserIdentifierResolver();

    SamlUserIdentifierResolutionResult result = resolver.resolveSamlUserIdentifier(cred);
    assertThat(result.getResolvedIds().isEmpty(), is(true));
    assertThat(result.getErrorMessages().isEmpty(), is(false));
    assertThat(result.getErrorMessages().get(0),
        is("Attribute 'eduPersonTargetedId:urn:oid:1.3.6.1.4.1.5923.1.1.1.10' not found in "
            + "assertion"));
  }

  @Test
  void eptidAttributeValuesSanityChecksTest() {

    Attribute attribute = mock(Attribute.class);
    SAMLCredential cred = mock(SAMLCredential.class);
    XSAny attributeValue = mock(XSAny.class);
    NameID nameid = mock(NameID.class);
    XMLObject object = mock(XMLObject.class);


    when(cred.getAttribute(Saml2Attribute.EPTID.getAttributeName())).thenReturn(attribute);

    when(attribute.getAttributeValues()).thenReturn(null);
    SamlUserIdentifierResolver resolver = new EPTIDUserIdentifierResolver();

    SamlUserIdentifierResolutionResult result = resolver.resolveSamlUserIdentifier(cred);
    assertThat(result.getResolvedIds().isEmpty(), is(true));
    assertThat(result.getErrorMessages().isEmpty(), is(false));
    assertThat(result.getErrorMessages().get(0), is(
        "Malformed assertion while looking for attribute 'eduPersonTargetedId:urn:oid:1.3.6.1.4.1.5923.1.1.1.10': "
            + "remoteEntityID null or empty"));

    when(cred.getRemoteEntityID()).thenReturn("entityId");

    result = resolver.resolveSamlUserIdentifier(cred);
    assertThat(result.getResolvedIds().isEmpty(), is(true));
    assertThat(result.getErrorMessages().isEmpty(), is(false));
    assertThat(result.getErrorMessages().get(0),
        is("Attribute 'eduPersonTargetedId:urn:oid:1.3.6.1.4.1.5923.1.1.1.10' is malformed: "
            + "null or empty list of values"));

    when(attribute.getAttributeValues()).thenReturn(emptyList());
    result = resolver.resolveSamlUserIdentifier(cred);

    assertThat(result.getResolvedIds().isEmpty(), is(true));
    assertThat(result.getErrorMessages().isEmpty(), is(false));
    assertThat(result.getErrorMessages().get(0),
        is("Attribute 'eduPersonTargetedId:urn:oid:1.3.6.1.4.1.5923.1.1.1.10' is malformed: "
            + "null or empty list of values"));

    when(attribute.getAttributeValues()).thenReturn(asList(nameid, nameid, nameid));
    result = resolver.resolveSamlUserIdentifier(cred);

    assertThat(result.getResolvedIds().isEmpty(), is(true));
    assertThat(result.getErrorMessages().isEmpty(), is(false));
    assertThat(result.getErrorMessages().get(0),
        is("Attribute 'eduPersonTargetedId:urn:oid:1.3.6.1.4.1.5923.1.1.1.10' is malformed: "
            + "more than one value found"));

    when(attribute.getAttributeValues()).thenReturn(asList(object));
    result = resolver.resolveSamlUserIdentifier(cred);
    assertThat(result.getResolvedIds().isEmpty(), is(true));
    assertThat(result.getErrorMessages().isEmpty(), is(false));
    assertThat(result.getErrorMessages().get(0),
        is("Attribute 'eduPersonTargetedId:urn:oid:1.3.6.1.4.1.5923.1.1.1.10' is malformed: "
            + "attribute value is not an XSAny"));


    when(attribute.getAttributeValues()).thenReturn(asList(attributeValue));
    when(attribute.hasChildren()).thenReturn(false);
    result = resolver.resolveSamlUserIdentifier(cred);
    assertThat(result.getResolvedIds().isEmpty(), is(true));
    assertThat(result.getErrorMessages().isEmpty(), is(false));
    assertThat(result.getErrorMessages().get(0),
        is("Attribute 'eduPersonTargetedId:urn:oid:1.3.6.1.4.1.5923.1.1.1.10' is malformed: "
            + "attribute value has no children elements"));

    when(attributeValue.hasChildren()).thenReturn(true);
    when(attributeValue.getOrderedChildren()).thenReturn(asList(object));
    result = resolver.resolveSamlUserIdentifier(cred);
    assertThat(result.getResolvedIds().isEmpty(), is(true));
    assertThat(result.getErrorMessages().isEmpty(), is(false));
    assertThat(result.getErrorMessages().get(0),
        is("Attribute 'eduPersonTargetedId:urn:oid:1.3.6.1.4.1.5923.1.1.1.10' is malformed: "
            + "attribute value first children value is not a NameID"));

    when(attributeValue.getOrderedChildren()).thenReturn(asList(nameid));
    when(nameid.getFormat()).thenReturn(NameIDType.UNSPECIFIED);

    result = resolver.resolveSamlUserIdentifier(cred);
    assertThat(result.getResolvedIds().isEmpty(), is(true));
    assertThat(result.getErrorMessages().isEmpty(), is(false));
    assertThat(result.getErrorMessages().get(0),
        is("Attribute 'eduPersonTargetedId:urn:oid:1.3.6.1.4.1.5923.1.1.1.10' is malformed: "
            + "resolved NameID is not persistent: " + NameIDType.UNSPECIFIED));
  }

  @Test
  void eptidResolutionSuccess() {
    Attribute attribute = mock(Attribute.class);
    SAMLCredential cred = mock(SAMLCredential.class);
    XSAny attributeValue = mock(XSAny.class);
    NameID nameid = mock(NameID.class);

    when(cred.getRemoteEntityID()).thenReturn("entityId");
    when(cred.getAttribute(Saml2Attribute.EPTID.getAttributeName())).thenReturn(attribute);
    when(attribute.getAttributeValues()).thenReturn(asList(attributeValue));
    when(attributeValue.hasChildren()).thenReturn(true);
    when(attributeValue.getOrderedChildren()).thenReturn(asList(nameid));

    when(nameid.getFormat()).thenReturn(NameIDType.PERSISTENT);
    when(nameid.getValue()).thenReturn("nameid");
    when(nameid.getNameQualifier()).thenReturn("nameIdNameQualifier");
    when(nameid.getSPNameQualifier()).thenReturn("nameIdSPNameQualifier");

    SamlUserIdentifierResolver resolver = new EPTIDUserIdentifierResolver();
    SamlUserIdentifierResolutionResult result = resolver.resolveSamlUserIdentifier(cred);

    assertThat(result.getResolvedIds().isEmpty(), is(false));
    assertThat(result.getErrorMessages().isEmpty(), is(true));
    assertThat(result.getResolvedIds().get(0).getUserId(), is("nameid"));
    assertThat(result.getResolvedIds().get(0).getIdpId(), is("entityId"));
  }

  @Test
  void eptidResolutionSuccessNameidWithoutFormatAttribute() {
    Attribute attribute = mock(Attribute.class);
    SAMLCredential cred = mock(SAMLCredential.class);
    XSAny attributeValue = mock(XSAny.class);
    NameID nameid = mock(NameID.class);

    when(cred.getRemoteEntityID()).thenReturn("entityId");
    when(cred.getAttribute(Saml2Attribute.EPTID.getAttributeName())).thenReturn(attribute);
    when(attribute.getAttributeValues()).thenReturn(asList(attributeValue));
    when(attributeValue.hasChildren()).thenReturn(true);
    when(attributeValue.getOrderedChildren()).thenReturn(asList(nameid));

    when(nameid.getValue()).thenReturn("nameid");
    when(nameid.getNameQualifier()).thenReturn("nameIdNameQualifier");
    when(nameid.getSPNameQualifier()).thenReturn("nameIdSPNameQualifier");

    SamlUserIdentifierResolver resolver = new EPTIDUserIdentifierResolver();
    SamlUserIdentifierResolutionResult result = resolver.resolveSamlUserIdentifier(cred);

    assertThat(result.getResolvedIds().isEmpty(), is(false));
    assertThat(result.getErrorMessages().isEmpty(), is(true));
    assertThat(result.getResolvedIds().get(0).getUserId(), is("nameid"));
    assertThat(result.getResolvedIds().get(0).getIdpId(), is("entityId"));
  }
}
