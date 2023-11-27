/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2023
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
package it.infn.mw.iam.api.client.last_used;

import java.util.Optional;

import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.client.last_used.service.ClientLastUsedService;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.PagingUtils;
import it.infn.mw.iam.persistence.model.IamClientLastUsed;

@RestController
@RequestMapping(ClientLastUsedAPIController.ENDPOINT)
public class ClientLastUsedAPIController {
    public static final String ENDPOINT = "/iam/api/clients2";
    private final ClientLastUsedService service;

    public ClientLastUsedAPIController(ClientLastUsedService service) {
        this.service = service;
    }

    @GetMapping
    public ListResponseDTO<IamClientLastUsed> retrieveClients(
            @RequestParam final Optional<Integer> count,
            @RequestParam final Optional<Integer> startIndex) {

        Pageable pageable =
                PagingUtils.buildPageRequest(count, startIndex, Sort.by("lastUsed").descending());

        return service.getAllClients(pageable);

    }
}
