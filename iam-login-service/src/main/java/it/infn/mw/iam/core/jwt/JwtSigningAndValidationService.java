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
package it.infn.mw.iam.core.jwt;

import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Map;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;

public interface JwtSigningAndValidationService {

    /**
     * Get all public keys
     * @return the map of all the public keys identified by their kid
     */
    public Map<String, JWK> getAllPublicKeys();

    /**
     * Checks the signature of the given JWT against all configured signers.
     *
     * @param jwtString
     *            the string representation of the JWT
     * @return true if at least one of the signers validates the given JWT
     * @throws NoSuchAlgorithmException
     */
    public boolean validateSignature(SignedJWT jwtString);

    /**
     * Sign the given JWT using the default algorithm and key.
     *
     * @param jwt the JWT to sign
     * @throws NoSuchAlgorithmException
     */
    public void signJwt(SignedJWT jwt);

    /**
     * Get the default signing algorithm to use.
     * @return the default signing algorithm
     */
    public JWSAlgorithm getDefaultSigningAlgorithm();

    /**
     * Get the list of all the supported signing algorithms.
     * @return the list of all the supported signing algorithms
     */
    public Collection<JWSAlgorithm> getAllSigningAlgsSupported();

    /**
     * Sign a JWT using the selected algorithm.
     *
     * @param jwt the JWT to sign
     * @param alg the name of the algorithm to use, as specified in JWS s.6
     */
    public void signJwt(SignedJWT jwt, JWSAlgorithm alg);

    /**
     * Get the list of the kid of the default signer object.
     * @return the kid of the default signer object
     */
    public String getDefaultSignerKeyId();

}
