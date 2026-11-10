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
package it.infn.mw.iam.core.oauth;

import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.CONSENT_TRANSACTION_ID;

import java.util.Map;
import java.util.Objects;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;

@SuppressWarnings("deprecation")
public class ConsentTransactionUserApprovalHandler implements UserApprovalHandler {

  private final UserApprovalHandler delegate;

  public ConsentTransactionUserApprovalHandler(UserApprovalHandler delegate) {
    this.delegate = Objects.requireNonNull(delegate);
  }

  @Override
  public boolean isApproved(AuthorizationRequest authorizationRequest,
      Authentication userAuthentication) {

    return delegate.isApproved(authorizationRequest, userAuthentication);
  }

  @Override
  public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest,
      Authentication userAuthentication) {

    return delegate.checkForPreApproval(authorizationRequest, userAuthentication);
  }

  @Override
  public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest,
      Authentication userAuthentication) {

    validateConsentTransaction(authorizationRequest);

    return delegate.updateAfterApproval(authorizationRequest, userAuthentication);
  }

  @Override
  public Map<String, Object> getUserApprovalRequest(AuthorizationRequest authorizationRequest,
      Authentication userAuthentication) {

    return delegate.getUserApprovalRequest(authorizationRequest, userAuthentication);
  }

  private void validateConsentTransaction(AuthorizationRequest request) {
    Object expected = request.getExtensions().get(CONSENT_TRANSACTION_ID);

    Map<String, String> approvalParameters = request.getApprovalParameters();

    String submitted =
        approvalParameters == null ? null : approvalParameters.get(CONSENT_TRANSACTION_ID);

    if (!(expected instanceof String) || ((String) expected).isBlank()
        || !expected.equals(submitted)) {
      throw new InvalidConsentTransactionException();
    }
  }
}
