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
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.api.registration.cern.dto.CernTokenResponse;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.config.cern.CernProperties;

@Service
@Profile("cern")
public class DefaultCernSecurityBlockingService implements CernSecurityBlockingApiService {

    public static final Logger LOG = LoggerFactory.getLogger(DefaultCernSecurityBlockingService.class);
    
    public static final String IDENTITY_API_PATH_TEMPLATE = "/api-access/token/Identity/";

    private String cachedToken;
    private Instant tokenExpiry;
    final RestTemplateFactory rtFactory;
    final CernProperties properties;

    public DefaultCernSecurityBlockingService(RestTemplateFactory rtFactory, CernProperties properties) {
        this.rtFactory = rtFactory;
        this.properties = properties;
    }

    private HttpHeaders buildAuthHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + getAccessToken());
        return headers;
    }

    private String getAccessToken() {

        Instant now = Instant.now();

        if (cachedToken != null && tokenExpiry != null && now.isBefore(tokenExpiry)) {
            LOG.debug("Using cached access token, expires at {}", tokenExpiry);
            return cachedToken;
        }
        LOG.debug("Requesting new access token from CERN Security Blocking API");
        RestTemplate rt = rtFactory.newRestTemplate();


        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", properties.getBlocking().getClientId());
        form.add("client_secret", properties.getBlocking().getClientSecret());
        form.add("audience", properties.getBlocking().getAudience());

        HttpEntity<MultiValueMap<String, String>> request =
                new HttpEntity<>(form, headers);

            LOG.debug("Requesting access token with client_id: {}, audience: {}, token_url: {}", properties.getBlocking().getClientId(), properties.getBlocking().getAudience(), properties.getBlocking().getTokenUrl());
        try {
            ResponseEntity<CernTokenResponse> response = rt.exchange(
                        properties.getBlocking().getTokenUrl(),
                        HttpMethod.POST,
                        request,
                        CernTokenResponse.class
                    );
            CernTokenResponse body = response.getBody();
            if (body == null) {
                LOG.warn("CERN security blocking token endpoint returned empty body");
                throw new CernSecurityBlockingError("CERN security blocking token endpoint returned empty body");
            }

            cachedToken = body.getAccessToken();
            LOG.debug("Received new access token, expires in {} seconds", body.getExpiresIn());

            tokenExpiry = now.plusSeconds(body.getExpiresIn() - properties.getBlocking().getGracePeriod());  
        } catch (RestClientException e) {
            throw new CernSecurityBlockingError("Error fetching security blocking api access token: " + e.getMessage(), e);
        }


        return cachedToken;
    }

    @Override
    public Optional<VOPersonDTO> getSecurityBlockingRecord(String username) {
        RestTemplate restTemplate = rtFactory.newRestTemplate();

        String url = String.format("%s%s", properties.getBlocking().getAuthorizationUrl(),
                                String.format(IDENTITY_API_PATH_TEMPLATE, username));

        LOG.debug("Checking security blocking for person {} at URL {}", username, url);

        try {
            ResponseEntity<VOPersonDTO> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(buildAuthHeaders()),
                    VOPersonDTO.class
            );
            return Optional.ofNullable(response.getBody());
        } catch (HttpClientErrorException.NotFound e) {
            return Optional.empty();
        } catch (RestClientException e) {
            throw new CernSecurityBlockingError("Error fetching security blocking record: " + e.getMessage(), e);
        }
    }


}