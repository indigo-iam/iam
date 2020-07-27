/*
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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

    angular.module('dashboardApp').factory('ScopesService', ScopesService);

    ScopesService.$inject = ['$q', '$http', '$httpParamSerializer'];

    function ScopesService($q, $http, $httpParamSerializer) {
        var service = {
            getAllScopes: getAllScopes,
            updateScopeById: updateScopeById,
            addScope: addScope,
            removeScope: removeScope
        };

        var urlScopes = "/api/scopes";

        return service;

        function doGet() {
            return $http.get(urlScopes);
        }

        function doPut(scope) {
            return $http.put(urlScopes + '/' + scope.id, scope);
        }

        function doDelete(scope) {
            return $http.delete(urlScopes + "/" + scope.id );
        }

        function doPost(data) {
            return $http.post(urlScopes, data);
        }

        function getAllScopes() {
            console.debug("Getting All Scopes... ");
            return doGet();
        }

        function updateScopeById(scope) {
            console.debug("updateScopeById: ", scope.id, scope.value);
            return doPut(scope);
        }

        function addScope(scope) {
            console.debug("addScope: ", scope.id, scope.value);
            return doPost(scope);
        }

        function removeScope(scope) {
            console.debug("removeScope: ", scope.id, scope.value)
            return doDelete(scope);
        }



    }
})();