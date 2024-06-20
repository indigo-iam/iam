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
package it.infn.mw.iam.api.trust;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.web.bind.annotation.GetMapping;

import it.infn.mw.iam.api.common.ListResponseDTO;



@RestController
@RequestMapping("/iam/api/trusts")
public class IamTrustController {
    public static final String TRUST_CACHE_KEY = "trusts";

    @GetMapping
    @Cacheable(TRUST_CACHE_KEY)
    public ListResponseDTO<String> getTrust() throws NoSuchAlgorithmException, KeyStoreException {
        ListResponseDTO.Builder<String> resultBuilder = ListResponseDTO.builder();

        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init((KeyStore) null);

        List<TrustManager> trustManagers = Arrays.asList(trustManagerFactory.getTrustManagers());
        List<String> certificates = trustManagers.stream()
            .filter(X509TrustManager.class::isInstance)
            .map(X509TrustManager.class::cast)
            .map(trustManager -> Arrays.asList(trustManager.getAcceptedIssuers()))
            .flatMap(Collection::stream)
            .map(X509Certificate::getSubjectX500Principal)
            .map(principal -> principal.getName("RFC2253"))
            .collect(Collectors.toList());

        return resultBuilder.resources(certificates).build();
    }

}
