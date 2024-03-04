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
package it.infn.mw.iam.core;

import java.util.Calendar;

import org.mitre.data.DefaultPageCriteria;
import org.mitre.data.PageCriteria;
import org.mitre.oauth2.repository.AuthorizationCodeRepository;
import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("defaultOAuth2AuthorizationCodeService")
@Primary
public class IamOAuth2AuthorizationCodeService extends DefaultOAuth2AuthorizationCodeService {

  public static final Logger LOG = LoggerFactory.getLogger(IamOAuth2AuthorizationCodeService.class);

  @Autowired
  private AuthorizationCodeRepository authorizationCodeRepository;

  @Value("${task.authorizationCodeCleanupCount}")
  long codeCleanupCount;
  
  
  @Override
  @Transactional(value="defaultTransactionManager")
  public void clearExpiredAuthorizationCodes() {

    LOG.debug("Cleaning expired authorization codes ...");
    PageCriteria pageCriteria = new DefaultPageCriteria(0, Long.valueOf(codeCleanupCount).intValue());
    long startedAt = Calendar.getInstance().getTimeInMillis();
    long deleted = authorizationCodeRepository.deleteExpiredCodes(pageCriteria);
    if (deleted > 0) {
      LOG.info("Cleared {} expired authorization codes in {} secs", deleted, (Calendar.getInstance().getTimeInMillis() - startedAt) / 1000);
    }
  }
  
}
