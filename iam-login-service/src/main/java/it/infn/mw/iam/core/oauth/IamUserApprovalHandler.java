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

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.openid.connect.token.TofuUserApprovalHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.persistence.model.IamAccount;

@Component("iamUserApprovalHandler")
public class IamUserApprovalHandler extends TofuUserApprovalHandler {

  @Autowired
  private ClientDetailsEntityService clientDetailsService;

  @Autowired
  private ClientService clientService;

  @Autowired
  private AccountUtils accountUtils;

  @Override
  public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest,
      Authentication userAuthentication) {

    AuthorizationRequest request =
        super.updateAfterApproval(authorizationRequest, userAuthentication);

    ClientDetailsEntity client = clientDetailsService.loadClientByClientId(request.getClientId());

    IamAccount account = accountUtils.getAuthenticatedUserAccount(userAuthentication)
      .orElseThrow(() -> NoSuchAccountError.forUsername(userAuthentication.getName()));

    if (client.getClientName().startsWith("oidc-agent:")) {
      clientService.linkClientToAccount(client, account);
    }

    return request;
  }

}
