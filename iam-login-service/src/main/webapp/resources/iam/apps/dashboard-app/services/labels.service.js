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
    angular.module('dashboardApp').factory('LabelsService', LabelsService);

    LabelsService.$inject = ['$q', '$http', 'Utils'];

    function LabelsService($q, $http, Utils) {

        var service = {
            getAccountLabels: getAccountLabels,
            getAccountLabelsForAuthenticatedUser: getAccountLabelsForAuthenticatedUser,
            getGroupLabels: getGroupLabels,
            setGroupLabel: setGroupLabel,
            deleteGroupLabel: deleteGroupLabel
        };

        return service;

        function getAccountLabels(uuid) {
            return $http.get("/iam/account/" + uuid + "/labels").then(
                function (res) {
                    return res.data;
                }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function getAccountLabelsForAuthenticatedUser() {
            var accountId = Utils.getLoggedUser().info.sub;
            return getAccountLabels(accountId);
        }

        function setGroupLabel(uuid, label) {
            return $http.put("/iam/group/" + uuid + "/labels", label).then(function (res) {
                return res.data;
            }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function getGroupLabels(uuid) {
            return $http.get("/iam/group/" + uuid + "/labels").then(
                function (res) {
                    return res.data;
                }).catch(function (res) {
                return $q.reject(res);
            });
        }

        function deleteGroupLabel(uuid, label) {
            var params = {
                name: label.name,
                prefix: label.prefix
            };

            return $http.delete("/iam/group/" + uuid + "/labels", {
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