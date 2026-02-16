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
package it.infn.mw.iam.core.oauth.approvedsite;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import it.infn.mw.iam.persistence.model.ApprovedSite;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;

public interface ApprovedSiteService {

  public ApprovedSite createApprovedSite(ClientDetailsEntity client, IamAccount account,
      Date timeoutDate, Set<String> allowedScopes);

  public Collection<ApprovedSite> getAll();

  public Collection<ApprovedSite> getByClientAndUser(ClientDetailsEntity client,
      IamAccount account);

  public ApprovedSite save(ApprovedSite approvedSite);

  public ApprovedSite getById(Long id);

  public void remove(ApprovedSite approvedSite);

  public Collection<ApprovedSite> getByUser(IamAccount account);

  public Collection<ApprovedSite> getByClient(ClientDetailsEntity client);

  public void clearApprovedSitesForClient(ClientDetailsEntity client);

  public void clearExpiredSites();

  public List<OAuth2AccessTokenEntity> getApprovedAccessTokens(ApprovedSite approvedSite);

}
