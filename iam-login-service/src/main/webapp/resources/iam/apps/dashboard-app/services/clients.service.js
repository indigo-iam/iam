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

    angular.module('dashboardApp').factory('ClientsService', ClientsService);

    ClientsService.$inject = ['$http', '$q', '$httpParamSerializer', 'HttpUtilsService', 'Utils'];

    function ClientsService($http, $q, $httpParamSerializer, HttpUtilsService, Utils) {
        var clientsEndpoint = "/iam/api/clients";
        var searchEndpoint = "/iam/api/search/clients";

        var defaultRequestConfig = {
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
        };

        var service = {
            retrieveClients: retrieveClients,
            retrieveClient: retrieveClient,
            searchClients: searchClients,
            createClient: createClient,
            saveClient: saveClient,
            deleteClient: deleteClient,
            rotateClientSecret: rotateClientSecret,
            rotateRegistrationAccessToken: rotateRegistrationAccessToken,
            retrieveClientOwners: retrieveClientOwners,
            assignClientOwner: assignClientOwner,
            removeClientOwner: removeClientOwner,
            newClient: newClient,
            getClientList: getClientList
        };

        return service;
        
        function getClientList(){
        	return $http.get(clientsEndpoint);
        }

        function endpoint(clientId) {
            return clientsEndpoint + '/' + clientId;
        }

        function ownerEndpoint(clientId) {
            return clientsEndpoint + '/' + clientId + '/owners';
        }


        function retrieveClientOwners(clientId, startIndex, count) {
            var params = $httpParamSerializer({
                'startIndex': startIndex,
                'count': count,
            });

            var url = ownerEndpoint(clientId) + '?' + params;

            return HttpUtilsService.doGet(url);
        }

        function assignClientOwner(clientId, accountId) {
            var url = ownerEndpoint(clientId) + '/' + accountId;
            return $http.post(url).then(function (res) {
                return res.data;
            }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function removeClientOwner(clientId, accountId) {
            var url = ownerEndpoint(clientId) + '/' + accountId;
            return $http.delete(url).then(function (res) {
                return res;
            }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function retrieveClients(startIndex, count, drOnly) {
            var params = $httpParamSerializer({
                'startIndex': startIndex,
                'count': count,
                'drOnly': drOnly
            });

            var url = clientsEndpoint + '?' + params;

            return HttpUtilsService.doGet(url);
        }

        function retrieveClient(clientId) {
            return HttpUtilsService.doGet(endpoint(clientId));
        }

        function createClient(client) {
            return $http.post(clientsEndpoint, client, defaultRequestConfig).then(function (res) {
                return res.data;
            }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function saveClient(clientId, client) {
            return $http.put(endpoint(clientId), client, defaultRequestConfig).then(function (res) {
                return res.data;
            }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function deleteClient(clientId) {
            return $http.delete(endpoint(clientId)).then(function (res) {
                return res.data;
            }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function searchClients(searchType, search, startIndex, count, drOnly) {
            var params = $httpParamSerializer({
                'searchType': searchType,
                'search': search,
                'startIndex': startIndex,
                'count': count,
                'drOnly': drOnly
            });
            var url = searchEndpoint + '?' + params;

            return HttpUtilsService.doGet(url);
        }

        function rotateClientSecret(clientId) {
            return $http.post(endpoint(clientId) + "/secret").then(function (res) {
                return res.data;
            }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function rotateRegistrationAccessToken(clientId) {
            return $http.post(endpoint(clientId) + "/rat").then(function (res) {
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
})();