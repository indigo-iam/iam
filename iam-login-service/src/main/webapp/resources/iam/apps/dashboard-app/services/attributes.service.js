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
    angular.module('dashboardApp').factory('AttributesService', AttributesService);

    AttributesService.$inject = ['$q', '$http', 'Utils'];

    function AttributesService($q, $http, Utils) {

        var service = {
            getAccountAttributes: getAccountAttributes,
            getAccountAttributesForAuthenticatedUser: getAccountAttributesForAuthenticatedUser,
            setAccountAttribute: setAccountAttribute,
            deleteAccountAttribute: deleteAccountAttribute
        };

        return service;

        function getAccountAttributes(uuid) {
            return $http.get("/iam/account/" + uuid + "/attributes").then(
                function (res) {
                    return res.data;
                }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function getAccountAttributesForAuthenticatedUser() {
            var accountId = Utils.getLoggedUser().info.sub;
            return getAccountAttributes(accountId);
        }

        function setAccountAttribute(uuid, attr) {
            return $http.put("/iam/account/" + uuid + "/attributes", attr).then(function (res) {
                return res.data;
            }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function deleteAccountAttribute(uuid, attr) {
            var params = {
                name: attr.name
            };

            return $http.delete("/iam/account/" + uuid + "/attributes", {
                params: params
            }).then(
                function (res) {
                    return res.data;
                }).catch(function (res) {
                return $q.reject(res);
            });
        }
    }
})();