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
package it.infn.mw.iam.notification.service.resolver;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Service
public class DefaultAddressResolutionService implements AddressResolutionService {
  public static final Logger LOG = LoggerFactory.getLogger(DefaultAddressResolutionService.class);

  public static final String VO_ADMINS = "admins";
  public static final String GROUP_MANAGERS = "gm:";
  public static final String ROLE_ADMIN = "ROLE_ADMIN";
  public static final String ROLE_GM_TEMPLATE = "ROLE_GM:%s";

  final IamAccountByAuthorityAddressResolver resolver;

  @Autowired
  public DefaultAddressResolutionService(IamAccountRepository repo) {
    this.resolver = new IamAccountByAuthorityAddressResolver(repo);
  }

  @Override
  public List<String> resolveAddressesForAudience(String name) {
    checkNotNull(name);
    List<String> result;
    
    if (VO_ADMINS.equals(name)) {
      result = resolver.resolveEmailAddressForContext(ROLE_ADMIN);
      LOG.debug("Resolved VO admins email addressess to: {}", result);
    } else if (name.startsWith(GROUP_MANAGERS)) {
      final String groupName = name.substring(3);
      result = resolver
        .resolveEmailAddressForContext(String.format(ROLE_GM_TEMPLATE, groupName));
      LOG.debug("Resolved group managers email addressess for group {} to: {}", groupName, result);
    } else {
      throw new InvalidAudience(name);
    }
    
    return result;
    
  }
}
