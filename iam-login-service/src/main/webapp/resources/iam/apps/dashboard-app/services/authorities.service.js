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
'use strict'

angular.module('dashboardApp').factory('Authorities', Authorities);

Authorities.$inject = ['$http', '$interpolate'];

function Authorities($http, $interpolate) {
    var AUTH_RESOURCE = $interpolate("/iam/account/{{id}}/authorities");
    var ADMIN_ROLE_RESOURCE = $interpolate("/iam/account/{{id}}/authorities?authority=ROLE_ADMIN");

    var service = {
        assignAdminPrivileges: assignAdminPrivileges,
        revokeAdminPrivileges: revokeAdminPrivileges,
        getAuthorities: getAuthorities
    };

    return service;

    function resourcePath(accountId) {
        return AUTH_RESOURCE({
            id: accountId
        });
    }

    function adminRoleResourcePath(accountId) {
        return ADMIN_ROLE_RESOURCE({
            id: accountId
        });
    }

    function assignAdminPrivileges(accountId) {
        return $http.post(adminRoleResourcePath(accountId));
    }

    function revokeAdminPrivileges(accountId) {

        return $http.delete(adminRoleResourcePath(accountId));
    }

    function getAuthorities(accountId) {

        return $http.get(resourcePath(accountId));
    }

}