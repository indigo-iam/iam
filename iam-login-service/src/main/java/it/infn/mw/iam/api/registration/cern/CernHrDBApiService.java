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
package it.infn.mw.iam.api.registration.cern;

import java.util.Optional;

import org.springframework.context.annotation.Profile;
import org.springframework.web.client.RestClientException;

import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;

@Profile("cern")
public interface CernHrDBApiService {

  /**
   * Returns an @Optional object that contains the @VOPersonDTO related to the CERN person ID
   * provided as parameter or empty if not found.
   * 
   * @param personId
   * @return
   * @throws RestClientException in case of ApiErrors
   */
  Optional<VOPersonDTO> getHrDbPersonRecord(String personId) throws RestClientException;

}
