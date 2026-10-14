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
package it.infn.mw.iam.core.oidc;

import java.util.Date;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpSession;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

@Service
public class MaxAgeService {

  public void enforceMaxAge(Map<String, String> params, Optional<ClientDetailsEntity> client,
      HttpSession session) {

    Integer max = client.map(ClientDetailsEntity::getDefaultMaxAge).orElse(null);

    String maxAge = params.get(ConnectRequestParameters.MAX_AGE);

    if (maxAge != null) {
      max = Integer.parseInt(maxAge);
    }

    if (max == null) {
      return;
    }

    Date authTime = (Date) session.getAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP);

    if (authTime == null) {
      return;
    }

    long seconds = (new Date().getTime() - authTime.getTime()) / 1000;

    if (seconds > max) {
      SecurityContextHolder.getContext().setAuthentication(null);
    }
  }
}
