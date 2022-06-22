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

import static com.google.common.base.Preconditions.checkNotNull;
import static it.infn.mw.voms.aa.VOMSResponse.Outcome.SUCCESS;
import static it.infn.mw.voms.aa.VOMSWarningMessage.shortenedAttributeValidity;

import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.voms.aa.AttributeAuthority;
import it.infn.mw.voms.aa.VOMSErrorMessage;
import it.infn.mw.voms.aa.VOMSRequest;
import it.infn.mw.voms.aa.VOMSRequestContext;
import it.infn.mw.voms.aa.VOMSResponse.Outcome;
import it.infn.mw.voms.properties.VomsProperties;

public class VOMSAAImpl implements AttributeAuthority {

  private final IamVOMSAccountResolver accountResolver;
  private final AttributeResolver attributeResolver;
  private final VomsProperties vomsProperties;
  private final Clock clock;

  public VOMSAAImpl(IamVOMSAccountResolver accountResolver, AttributeResolver attributeResolver,
      VomsProperties props, Clock clock) {
    this.accountResolver = accountResolver;
    this.attributeResolver = attributeResolver;
    this.vomsProperties = props;
    this.clock = clock;
  }

  protected void checkMembershipValidity(VOMSRequestContext context) {

    IamAccount account = context.getIamAccount();
    VOMSRequest r = context.getRequest();

    if (!account.isActive()) {
      failResponse(context,
          VOMSErrorMessage.suspendedUser(r.getHolderSubject(), r.getHolderIssuer()));
      context.setHandled(true);
    }
  }

  private void handleRequestedValidity(VOMSRequestContext context) {

    final long MAX_VALIDITY = vomsProperties.getAa().getMaxAcLifetimeInSeconds();

    long validity = MAX_VALIDITY;
    long requestedValidity = context.getRequest().getRequestedValidity();

    if (requestedValidity > 0 && requestedValidity < MAX_VALIDITY) {
      validity = requestedValidity;
    }

    if (requestedValidity > MAX_VALIDITY) {
      context.getResponse().getWarnings().add(shortenedAttributeValidity(context.getVOName()));
    }

    Instant now = clock.instant();

    Date startDate = Date.from(now);
    Date endDate = Date.from(now.plusSeconds(validity));

    context.getResponse().setNotAfter(endDate);
    context.getResponse().setNotBefore(startDate);
  }

  private void requestSanityChecks(VOMSRequest request) {

    checkNotNull(request);
    checkNotNull(request.getRequesterSubject());
    checkNotNull(request.getHolderSubject());

  }

  private void resolveAccount(VOMSRequestContext context) {
    Optional<IamAccount> account = accountResolver.resolveAccountFromRequest(context);

    if (account.isPresent()) {
      context.setIamAccount(account.get());
    } else {

      VOMSErrorMessage m = VOMSErrorMessage.noSuchUser(context.getRequest().getHolderSubject(),
          context.getRequest().getHolderIssuer());

      context.getResponse().setOutcome(Outcome.FAILURE);
      context.getResponse().getErrorMessages().add(m);
      context.setHandled(true);
    }
  }


  @Override
  public boolean getAttributes(VOMSRequestContext context) {

    requestSanityChecks(context.getRequest());

    if (!context.isHandled()) {
      resolveAccount(context);
    }

    if (!context.isHandled()) {
      checkMembershipValidity(context);
    }

    if (!context.isHandled()) {
      resolveFQANs(context);
      resolveGAs(context);
    }

    if (!context.isHandled()) {
      handleRequestedValidity(context);
    }

    context.setHandled(true);

    return context.getResponse().getOutcome() == SUCCESS;
  }


  private void resolveFQANs(VOMSRequestContext context) {
    attributeResolver.resolveFQANs(context);
  }

  private void resolveGAs(VOMSRequestContext context) {
    attributeResolver.resolveGAs(context);
  }

  protected void failResponse(VOMSRequestContext context, VOMSErrorMessage em) {

    context.getResponse().setOutcome(Outcome.FAILURE);
    context.getResponse().getErrorMessages().add(em);
  }
}
