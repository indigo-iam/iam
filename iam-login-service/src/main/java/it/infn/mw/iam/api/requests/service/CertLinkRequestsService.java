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
package it.infn.mw.iam.api.requests.service;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.requests.model.CertLinkRequestDTO;

public interface CertLinkRequestsService {

  CertLinkRequestDTO createCertLinkRequest(CertLinkRequestDTO certLinkRequest);

  void deleteCertLinkRequest(String requestId);

  CertLinkRequestDTO approveCertLinkRequest(String requestId);

  CertLinkRequestDTO rejectCertLinkRequest(String requestId, String motivation);

  CertLinkRequestDTO getCertLinkRequestDetails(String requestId);

  ListResponseDTO<CertLinkRequestDTO> listCertLinkRequests(String username, String subject,
      String status, OffsetPageable pageRequest);

}