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
package it.infn.mw.iam.core.oauth.consent;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.openid.connect.model.ApprovedSite;

public interface ApprovedSiteService {

  public ApprovedSite createApprovedSite(ClientDetailsEntity client, String userId, Date timeoutDate, Set<String> allowedScopes);

  public Optional<ApprovedSite> getById(Long id);

  public List<ApprovedSite> getAll();

  public List<ApprovedSite> getByUserId(String userId);

  public Collection<ApprovedSite> getByClientId(String clientId);

  public List<ApprovedSite> getByClientIdAndUserId(String clientId, String userId);

  public ApprovedSite save(ApprovedSite approvedSite);

  public void remove(ApprovedSite approvedSite);

  public void clearApprovedSitesForClient(String clientId);

  public boolean isExpired(ApprovedSite approvedSite);

}
