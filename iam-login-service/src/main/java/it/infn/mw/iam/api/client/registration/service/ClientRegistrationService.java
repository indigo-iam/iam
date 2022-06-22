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
package it.infn.mw.iam.api.client.registration.service;

import java.text.ParseException;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;

import org.springframework.security.core.Authentication;

import it.infn.mw.iam.api.common.client.RegisteredClientDTO;

public interface ClientRegistrationService {

  RegisteredClientDTO registerClient(@Valid RegisteredClientDTO request,
      Authentication authentication) throws ParseException;

  RegisteredClientDTO retrieveClient(@NotBlank String clientId,
      Authentication authentication);

  RegisteredClientDTO updateClient(@NotBlank String clientId, @Valid RegisteredClientDTO request,
      Authentication authentication) throws ParseException;

  void deleteClient(@NotBlank String clientId, Authentication authentication);

  RegisteredClientDTO redeemClient(@NotBlank String clientId,
      @NotBlank String registrationAccessToken,
      Authentication authentication);

}
