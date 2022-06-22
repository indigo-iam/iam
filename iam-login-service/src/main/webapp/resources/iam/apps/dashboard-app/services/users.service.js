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
'use strict';

angular.module('dashboardApp').factory('UsersService', UsersService);

UsersService.$inject = ['$q', '$rootScope', '$http', '$httpParamSerializer'];

function UsersService($q, $rootScope, $http, $httpParamSerializer) {
    var service = {
        getUsersFilteredAndSortedBy: getUsersFilteredAndSortedBy,
        getUsersFilteredBy: getUsersFilteredBy,
        getUsersSortedBy: getUsersSortedBy,
        getUsersCount: getUsersCount,
        getUsers: getUsers
    };

    var urlUsers = "/iam/account/search";

    return service;

    function doGet(queryStr) {
        var url = urlUsers + '?' + queryStr;
        return $http.get(url);
    }

    function getUsersFilteredAndSortedBy(startIndex, count, filter, sortBy, sortDir) {
        console.debug("getUsersFilteredAndSortedBy: ", startIndex, count, filter, sortBy, sortDir);
        return doGet($httpParamSerializer({
            'startIndex': startIndex,
            'count': count,
            'filter': filter,
            'sortBy': sortBy,
            'sortDirection': sortDir
        }));
    }

    function getUsersFilteredBy(startIndex, count, filter) {
        console.debug("getUsersFilteredBy: ", startIndex, count, filter);
        return doGet($httpParamSerializer({
            'startIndex': startIndex,
            'count': count,
            'filter': filter
        }));
    }

    function getUsersSortedBy(startIndex, count, sortBy, sortDir) {
        console.debug("getUsersSortedBy: ", startIndex, count, sortBy, sortDir);
        return doGet($httpParamSerializer({
            'startIndex': startIndex,
            'count': count,
            'sortBy': sortBy,
            'sortDirection': sortDir
        }));
    }

    function getUsers(startIndex, count) {
        console.debug("getUsers: ", startIndex, count);
        return doGet($httpParamSerializer({
            'startIndex': startIndex,
            'count': count
        }));
    }

    function getUsersCount() {
        console.debug("getUsersCount");
        return doGet($httpParamSerializer({
            'count': 0
        }));
    }
}