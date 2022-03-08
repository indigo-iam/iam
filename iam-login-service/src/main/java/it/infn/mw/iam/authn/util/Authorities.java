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
package it.infn.mw.iam.authn.util;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class Authorities {

  public static final GrantedAuthority ROLE_OWNER = new SimpleGrantedAuthority("ROLE_ADMIN");
  public static final GrantedAuthority ROLE_ADMIN = new SimpleGrantedAuthority("ROLE_ADMIN");
  public static final GrantedAuthority ROLE_USER = new SimpleGrantedAuthority("ROLE_USER");
  public static final GrantedAuthority ROLE_CLIENT = new SimpleGrantedAuthority("ROLE_CLIENT");
  public static final GrantedAuthority ROLE_PRE_AUTHENTICATED =
      new SimpleGrantedAuthority("ROLE_PRE_AUTHENTICATED");

  private Authorities() {
    // prevent instantiation
  }

}
