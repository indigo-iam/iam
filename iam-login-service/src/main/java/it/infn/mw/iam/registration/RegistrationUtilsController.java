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
package it.infn.mw.iam.registration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Transactional
public class RegistrationUtilsController {

  final RegistrationRequestService service;

  @Autowired
  public RegistrationUtilsController(RegistrationRequestService service) {
    this.service = service;
  }

  @RequestMapping(value = "/registration/username-available/{username:.+}",
      method = RequestMethod.GET)
  public Boolean usernameAvailable(@PathVariable("username") String username) {
    return service.usernameAvailable(username);
  }

  @RequestMapping(value = "/registration/email-available/{email:.+}", method = RequestMethod.GET)
  public Boolean emailAvailable(@PathVariable("email") String email) {
    return service.emailAvailable(email);
  }
  
}
