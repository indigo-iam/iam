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

package it.infn.mw.iam.authn;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;

import it.infn.mw.iam.api.client.service.ClientService;

public class PublicClientAwareCcFilter extends ClientCredentialsTokenEndpointFilter {

    private final ClientService clientService;

    public PublicClientAwareCcFilter(String tokenEndpoint, ClientService clientService) {
        super(tokenEndpoint);
        this.clientService = clientService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
            HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        String clientId = request.getParameter("client_id");

        if (clientId != null) {
            Optional<ClientDetailsEntity> client = clientService.findClientByClientId(clientId);

            // Bypass only for public clients
            if (client.isPresent() &&
                    client.get().getTokenEndpointAuthMethod() == AuthMethod.NONE) {
                return new UsernamePasswordAuthenticationToken(clientId, "", Collections.emptyList());
            }
        }

        // Default behavior for confidential clients
        return super.attemptAuthentication(request, response);
    }
}
