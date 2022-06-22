/*
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
(function () {
    'use strict';
    angular.module('dashboardApp')
        .factory('AccountLinkingService', AccountLinkingService);

    AccountLinkingService.$inject = ['$http'];

    function AccountLinkingService($http) {
        var OIDC_RESOURCE = '/iam/account-linking/OIDC';
        var SAML_RESOURCE = '/iam/account-linking/SAML';
        var X509_RESOURCE = '/iam/account-linking/X509';

        var service = {
            unlinkOidcAccount: unlinkOidcAccount,
            unlinkSamlAccount: unlinkSamlAccount,
            unlinkX509Certificate: unlinkX509Certificate,
            getOidcProviders: getOidcProviders,
            getWayfLoginButtonConfiguration: getWayfLoginButtonConfiguration,
            getSamlLoginShortcuts: getSamlLoginShortcuts
        };

        return service;

        function unlinkOidcAccount(account) {
            return $http.delete(
                OIDC_RESOURCE, {
                    params: account
                });
        }

        function unlinkSamlAccount(account) {
            return $http.delete(
                SAML_RESOURCE, {
                    params: account
                });
        }

        function unlinkX509Certificate(cert) {
            return $http.delete(
                X509_RESOURCE, {
                    params: {
                        certificateSubject: cert.subjectDn
                    }
                });
        }

        function getOidcProviders() {
            return $http.get('/iam/config/oidc/providers', {
                cache: true
            });
        }

        function getWayfLoginButtonConfiguration() {
            return $http.get("/iam/config/saml/wayf-login-button", {
                cache: true
            });
        }

        function getSamlLoginShortcuts() {

            return $http.get("/iam/config/saml/shortcuts", {
                cache: true
            });
        }
    }
})();