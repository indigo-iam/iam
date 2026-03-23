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
package it.infn.mw.iam.authn.saml.profile;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.xml.namespace.QName;

import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import it.infn.mw.iam.config.saml.IamSamlProperties.AuthnContextProperties;

public class IamSSOProfile extends WebSSOProfileImpl {

  private final AuthnContextProperties authnContextProperties;

  public IamSSOProfile(AuthnContextProperties authnContextProperties) {
    this.authnContextProperties = authnContextProperties;
  }

  private void spidNameIDPolicy(AuthnRequest request) {
    @SuppressWarnings("unchecked")
    SAMLObjectBuilder<NameIDPolicy> builder = (SAMLObjectBuilder<NameIDPolicy>) builderFactory
      .getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME);
    NameIDPolicy nameIDPolicy = builder.buildObject();
    nameIDPolicy.setFormat(NameID.TRANSIENT);
    request.setNameIDPolicy(nameIDPolicy);
  }

  private void spidIssuer(SAMLMessageContext context, AuthnRequest request) {
    request.getIssuer().setFormat(NameID.ENTITY);
    request.getIssuer().setNameQualifier(context.getLocalEntityId());
  }

  private void spidAuthenticationContexts(IamSSOProfileOptions options, AuthnRequest request) {

    SAMLObjectBuilder<RequestedAuthnContext> builder =
        getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);

    RequestedAuthnContext authnContext = builder.buildObject();
    authnContext.setComparison(options.getAuthnContextComparisonEnum().getComparison());

    SAMLObjectBuilder<AuthnContextClassRef> contextRefBuilder =
        getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);

    AuthnContextClassRef authnContextClassRef = contextRefBuilder.buildObject();
    authnContextClassRef.setAuthnContextClassRef(options.getSpidAuthenticationLevel().getUrl());
    authnContext.getAuthnContextClassRefs().add(authnContextClassRef);
    request.setRequestedAuthnContext(authnContext);
  }

  @SuppressWarnings("unchecked")
  private <T extends SAMLObject> SAMLObjectBuilder<T> getBuilder(QName elementName) {
    return (SAMLObjectBuilder<T>) builderFactory.getBuilder(elementName);
  }

  private void configureAuthnContext(AuthnRequest request) {

    if (!authnContextProperties.isEnabled()) {
      // Actively clear any AuthnContext the parent class may have already set.
      // This ensures NO RequestedAuthnContext is sent letting the IdP decide.
      request.setRequestedAuthnContext(null);
      return;
    }

    // Clear and replace with the configured list (admin-defined or defaults)
    SAMLObjectBuilder<RequestedAuthnContext> builder =
        getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
    RequestedAuthnContext requestedAuthnContext = builder.buildObject();
    request.setRequestedAuthnContext(requestedAuthnContext);

    SAMLObjectBuilder<AuthnContextClassRef> contextRefBuilder =
        getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);

    for (String ref : authnContextProperties.getClassRefs()) {
      AuthnContextClassRef classRef = contextRefBuilder.buildObject();
      classRef.setAuthnContextClassRef(ref);
      requestedAuthnContext.getAuthnContextClassRefs().add(classRef);
    }
  }

  @Override
  protected AuthnRequest getAuthnRequest(SAMLMessageContext context, WebSSOProfileOptions options,
      AssertionConsumerService assertionConsumer, SingleSignOnService bindingService)
      throws SAMLException, MetadataProviderException {

    AuthnRequest request =
        super.getAuthnRequest(context, options, assertionConsumer, bindingService);

    configureAuthnContext(request);

    if (options instanceof IamSSOProfileOptions) {
      IamSSOProfileOptions ssoOptions = (IamSSOProfileOptions) options;
      if (ssoOptions.getSpidIdp()) {
        spidNameIDPolicy(request);
        spidIssuer(context, request);
        spidAuthenticationContexts(ssoOptions, request);
        request.setIsPassive((Boolean) null);
        request.setAttributeConsumingServiceIndex(ssoOptions.getAttributeConsumerIndex());
      }
    }
    return request;
  }
}
