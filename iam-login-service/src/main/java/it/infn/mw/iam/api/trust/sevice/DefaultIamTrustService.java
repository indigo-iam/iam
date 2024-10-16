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
package it.infn.mw.iam.api.trust.sevice;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.net.ssl.X509TrustManager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.common.ListResponseDTO;

@Service
public class DefaultIamTrustService implements IamTrustService {

    @Autowired
    X509TrustManager trustManager;

    @Cacheable(TRUST_CACHE_KEY)
    public ListResponseDTO<String> getTrusts() throws NoSuchAlgorithmException, KeyStoreException {
        ListResponseDTO.Builder<String> resultBuilder = ListResponseDTO.builder();

        List<String> authoritites = Arrays.stream(trustManager.getAcceptedIssuers())
            .map(X509Certificate::getSubjectX500Principal)
            .map(principal -> principal.getName("RFC2253"))
            .collect(Collectors.toList());

        return resultBuilder.resources(authoritites).build();
    }

}
