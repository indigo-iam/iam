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
package it.infn.mw.iam.core.stats;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.springframework.stereotype.Service;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;

import it.infn.mw.iam.persistence.repository.IamApprovedSiteRepository;
import it.infn.mw.iam.persistence.repository.UserClientCounts;

@Service
public class DefaultStatsService implements StatsService {

  private IamApprovedSiteRepository approvedSiteRepo;

  public DefaultStatsService(IamApprovedSiteRepository approvedSiteRepo) {

    this.approvedSiteRepo = approvedSiteRepo;
  }

  private Supplier<Map<String, Integer>> summaryCache = createSummaryCache();

  private Supplier<Map<String, Integer>> createSummaryCache() {

    return Suppliers.memoizeWithExpiration(new Supplier<Map<String, Integer>>() {
      @Override
      public Map<String, Integer> get() {
        return computeSummaryStats();
      }
    }, 10, TimeUnit.MINUTES);
  }

  @Override
  public Map<String, Integer> getSummaryStats() {

    return summaryCache.get();
  }

  private Map<String, Integer> computeSummaryStats() {

    long total = approvedSiteRepo.count();
    UserClientCounts ucc = approvedSiteRepo.findDistinctUserAndClientCounts();

    Map<String, Integer> e = new HashMap<>();
    e.put("approvalCount", Long.valueOf(total).intValue());
    e.put("userCount", Long.valueOf(ucc.getUserCount()).intValue());
    e.put("clientCount", Long.valueOf(ucc.getClientCount()).intValue());
    return e;
  }

  @Override
  public ClientStat getCountForClientId(String clientId) {

    return new ClientStat(approvedSiteRepo.findByClientId(clientId).size());
  }

  @Override
  public void resetCache() {

    summaryCache = createSummaryCache();
  }

}

