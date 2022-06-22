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

import java.util.Collection;
import java.util.Optional;
import java.util.function.Supplier;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;

import com.google.common.base.Strings;
import com.google.common.collect.Sets;

@SuppressWarnings("deprecation")
public class IAMClientUserDetailsService implements ClientUserDetailsService {
  private static final GrantedAuthority ROLE_CLIENT = new SimpleGrantedAuthority("ROLE_CLIENT");

  private final ClientDetailsEntityService clientService;

  public IAMClientUserDetailsService(ClientDetailsEntityService clientService) {
    this.clientService = clientService;
  }

  private Supplier<UsernameNotFoundException> unknownClientError(String clientId) {
    return () -> new UsernameNotFoundException("Unknown client: " + clientId);
  }

  @Override
  public UserDetails loadUserByUsername(String clientId) throws UsernameNotFoundException {

    try {
      ClientDetailsEntity client = Optional.ofNullable(clientService.loadClientByClientId(clientId))
        .orElseThrow(unknownClientError(clientId));

      final String password = Strings.nullToEmpty(client.getClientSecret());

      final boolean accountEnabled = true;
      final boolean accountNonExpired = true;
      final boolean credentialsNonExpired = true;
      final boolean accountNonLocked = true;

      Collection<GrantedAuthority> authorities = Sets.newHashSet(client.getAuthorities());
      authorities.add(ROLE_CLIENT);

      return new User(clientId, password, accountEnabled, accountNonExpired, credentialsNonExpired,
          accountNonLocked, authorities);

    } catch (InvalidClientException e) {
      throw unknownClientError(clientId).get();
    }
  }

  @Override
  public ClientDetailsEntityService getClientDetailsService() {

    return clientService;
  }

}
