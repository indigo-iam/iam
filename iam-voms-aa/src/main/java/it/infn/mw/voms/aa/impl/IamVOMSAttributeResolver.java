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
package it.infn.mw.voms.aa.impl;

import static java.util.Comparator.comparing;

import java.util.Set;

import org.italiangrid.voms.ac.impl.VOMSGenericAttributeImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountGroupMembership;
import it.infn.mw.iam.persistence.model.IamAttribute;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.voms.aa.VOMSErrorMessage;
import it.infn.mw.voms.aa.VOMSRequestContext;
import it.infn.mw.voms.aa.VOMSResponse.Outcome;
import it.infn.mw.voms.api.VOMSFqan;
import it.infn.mw.voms.properties.VomsProperties;

public class IamVOMSAttributeResolver implements AttributeResolver {
  public static final Logger LOG = LoggerFactory.getLogger(IamVOMSAttributeResolver.class);

  private final IamLabel vomsRoleLabel;
  private final FQANEncoding fqanEncoding;

  public IamVOMSAttributeResolver(VomsProperties properties, FQANEncoding fqanEncoding) {
    vomsRoleLabel = IamLabel.builder().name(properties.getAa().getOptionalGroupLabel()).build();
    this.fqanEncoding = fqanEncoding;
  }

  protected boolean iamGroupIsVomsGroup(VOMSRequestContext context, IamGroup g) {
    final String voName = context.getVOName();
    final boolean nameMatches = g.getName().equals(voName) || g.getName().startsWith(voName + "/");

    return nameMatches && !g.getLabels().contains(vomsRoleLabel);
  }

  protected void noSuchUserError(VOMSRequestContext context) {
    VOMSErrorMessage m = VOMSErrorMessage.noSuchUser(context.getRequest().getHolderSubject(),
        context.getRequest().getHolderIssuer());

    context.getResponse().setOutcome(Outcome.FAILURE);
    context.getResponse().getErrorMessages().add(m);
    context.setHandled(true);
  }

  protected void noSuchAttributeError(VOMSRequestContext context, VOMSFqan fqan) {
    VOMSErrorMessage m = VOMSErrorMessage.noSuchAttribute(fqan.getFqan());

    context.getResponse().setOutcome(Outcome.FAILURE);
    context.getResponse().getErrorMessages().add(m);
    context.setHandled(true);
  }


  protected boolean iamGroupIsVomsRole(IamGroup g) {
    return g.getLabels().contains(vomsRoleLabel);
  }

  protected boolean groupMatchesFqan(IamGroup g, VOMSFqan fqan) {
    final String name = fqan.asIamGroupName();
    final boolean nameMatches = name.equals(g.getName());
    if (fqan.isRoleFqan()) {
      return nameMatches && g.getLabels().contains(vomsRoleLabel);
    } else {
      return nameMatches;
    }
  }

  protected void issueRequestedFqan(VOMSRequestContext context, VOMSFqan fqan) {
    if (context.getIamAccount()
      .getGroups()
      .stream()
      .map(IamAccountGroupMembership::getGroup)
      .anyMatch(g -> groupMatchesFqan(g, fqan))) {
      LOG.debug("Issuing fqan: {}", fqan.getFqan());
      context.getResponse().getIssuedFQANs().add(fqanEncoding.encodeFQAN(fqan.getFqan()));
    } else {
      noSuchAttributeError(context, fqan);
    }
  }


  protected void issueCompulsoryGroupFqan(VOMSRequestContext context, IamGroup g) {
    final String fqan = "/" + g.getName();
    if (context.getResponse().getIssuedFQANs().add(fqanEncoding.encodeFQAN(fqan))) {
      LOG.debug("Issued compulsory fqan: {}", fqan);
    }
  }

  protected boolean requestAccountIsMemberOfGroup(VOMSRequestContext context, String groupName) {
    IamAccount account = context.getIamAccount();
    return account.getGroups().stream().anyMatch(g -> g.getGroup().getName().equals(groupName));
  }

  protected void resolveRequestedFQANs(VOMSRequestContext requestContext) {
    requestContext.getRequest()
      .getRequestedFQANs()
      .forEach(f -> issueRequestedFqan(requestContext, f));
  }

  protected void resolveCompulsoryFQANs(VOMSRequestContext requestContext) {

    requestContext.getIamAccount()
      .getGroups()
      .stream()
      .sorted(comparing(gm -> gm.getGroup().getName()))
      .filter(g -> iamGroupIsVomsGroup(requestContext, g.getGroup()))
      .forEach(g -> issueCompulsoryGroupFqan(requestContext, g.getGroup()));

    if (requestContext.getResponse().getIssuedFQANs().isEmpty()) {
      noSuchUserError(requestContext);
    }
  }



  @Override
  public void resolveFQANs(VOMSRequestContext requestContext) {

    requestContext.getRequest()
      .getRequestedFQANs()
      .forEach(f -> issueRequestedFqan(requestContext, f));

    resolveCompulsoryFQANs(requestContext);

  }

  @Override
  public void resolveGAs(VOMSRequestContext requestContext) {

    Set<IamAttribute> attrs = requestContext.getIamAccount().getAttributes();
    for (IamAttribute a : attrs) {
      VOMSGenericAttributeImpl attr = new VOMSGenericAttributeImpl();
      attr.setName(a.getName());
      attr.setValue(a.getValue());
      attr.setContext(requestContext.getVOName());

      LOG.debug("Issuing generic attribute: {}", attr);
      requestContext.getResponse().getIssuedGAs().add(attr);
    }
  }

}
