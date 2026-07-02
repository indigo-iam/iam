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

package it.infn.mw.iam.api.account.approved_site;

import java.util.List;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.openid.connect.model.ApprovedSite;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.approved_site.dto.ApprovedSiteWithClientDetailsDTO;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.client.util.ClientSuppliers;
import it.infn.mw.iam.persistence.model.IamAccount;


@RestController
@RequestMapping("/iam/api")
@PreAuthorize("hasRole('ROLE_USER')")
public class ApprovedSiteController {

  private final ApprovedSiteService approvedSiteService;
  private final ClientService clientService;
  private final AccountUtils accountUtils;

  public ApprovedSiteController(ApprovedSiteService approvedSiteService,
      ClientService clientService, AccountUtils accountUtils) {
    this.approvedSiteService = approvedSiteService;
    this.clientService = clientService;
    this.accountUtils = accountUtils;
  }

  @GetMapping(value = "/approved")
  public List<ApprovedSiteWithClientDetailsDTO> getAllApprovedSites() {
    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(() -> new IllegalStateException("No iam account found for authenticated user"));

    return approvedSiteService.getByUserId(account.getUsername())
      .stream()
      .map(this::toDto)
      .toList();
  }

  private ApprovedSiteWithClientDetailsDTO toDto(ApprovedSite approvedSite) {

    ClientDetailsEntity client = clientService.findClientByClientId(approvedSite.getClientId())
      .orElseThrow(ClientSuppliers.clientNotFound(approvedSite.getClientId()));

    ApprovedSiteWithClientDetailsDTO dto = new ApprovedSiteWithClientDetailsDTO();
    dto.setId(approvedSite.getId());
    dto.setUserId(approvedSite.getUserId());
    dto.setClientId(approvedSite.getClientId());
    dto.setClientName(client.getClientName());
    dto.setClientDescription(client.getClientDescription());
    dto.setAuthorizationDate(approvedSite.getCreationDate());
    dto.setAccessDate(approvedSite.getAccessDate());
    dto.setTimeoutDate(approvedSite.getTimeoutDate());
    dto.setAllowedScopes(approvedSite.getAllowedScopes());

    return dto;
  }
}
