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
package it.infn.mw.iam.core.client;

import java.util.Date;
import java.util.List;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@Component
@Profile("openid-federation")
public class ExpiredFederationClientScheduler {

  public static final long ONE_SECOND_MSEC = 1000;
  public static final long ONE_MINUTE_MSEC = 60 * ONE_SECOND_MSEC;
  public static final long TEN_MINUTES_MSEC = 10 * ONE_MINUTE_MSEC;
  public static final long ONE_HOUR_MSEC = 60 * ONE_MINUTE_MSEC;
  public static final long ONE_DAY_MSEC = 24 * ONE_HOUR_MSEC;

  @Autowired
  IamClientRepository clientRepo;

  @Autowired
  ClientService clientService;

  @Scheduled(fixedDelay = ONE_DAY_MSEC, initialDelay = TEN_MINUTES_MSEC)
  public void disableExpiredClients() {
    List<ClientDetailsEntity> clients = clientRepo.findActiveClientsExpiredBefore(new Date());
    for (ClientDetailsEntity client : clients) {
      clientService.updateClientStatus(client, false, "expired_client_task");
    }
  }
}
