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

    angular
        .module('dashboardApp')
        .service('ClientRegistrationService', ClientRegistrationService);

    /** @ngInject */
    function ClientRegistrationService($http, $q, $httpParamSerializer, HttpUtilsService, Utils) {

        var ownedClientsEndpoint = "/iam/account/me/clients";
        var clientRegistrationEndpoint = "/iam/api/client-registration";

        var defaultRequestConfig = {
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
        };

        var service = {
            retrieveOwnedClients: retrieveOwnedClients,
            retrieveClient: retrieveClient,
            registerClient: registerClient,
            redeemClient: redeemClient,
            deleteClient: deleteClient,
            saveClient: saveClient,
            newClient: newClient
        };

        return service;

        function retrieveOwnedClients(startIndex, count) {
            var params = $httpParamSerializer({
                'startIndex': startIndex,
                'count': count
            });
            var url = ownedClientsEndpoint + '?' + params;
            return HttpUtilsService.doGet(url);
        }

        function registerClient(client) {
            return $http.post(clientRegistrationEndpoint, client, defaultRequestConfig).then(function (res) {
                return res.data;
            }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function retrieveClient(clientId) {
            var url = clientRegistrationEndpoint + '/' + clientId;
            return HttpUtilsService.doGet(url);
        }

        function redeemClient(clientId, rat) {
            var url = clientRegistrationEndpoint + '/' + clientId + '/redeem';
            return $http.post(url, rat, defaultRequestConfig).then(function (res) {
                return res.data;
            }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function saveClient(clientId, client) {
            var url = clientRegistrationEndpoint + '/' + clientId;
            return $http.put(url, client, defaultRequestConfig).then(function (res) {
                return res.data;
            }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function deleteClient(clientId) {
            var url = clientRegistrationEndpoint + '/' + clientId;
            return $http.delete(url).then(function (res) {
                return res.data;
            }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function newClient() {

            var email = Utils.getLoggedUser().info.email;

            var newClient =
            {
                client_name: "Change me please!",
                grant_types: ["authorization_code"],
                redirect_uris: ["http://localhost/example"],
                scope: "openid profile email",
                token_endpoint_auth_method: "client_secret_basic",
                contacts: [email],
            };
            return newClient;
        }
    }
}());