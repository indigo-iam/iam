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

    angular.module('dashboardApp').factory('GroupsService', GroupsService);

    GroupsService.$inject = ['$q', '$http', '$httpParamSerializer'];

    function GroupsService($q, $http, $httpParamSerializer) {
        var service = {
            getGroupsFilteredAndSortBy: getGroupsFilteredAndSortBy,
            getGroupsFilteredBy: getGroupsFilteredBy,
            getGroupsSortBy: getGroupsSortBy,
            getGroupsCount: getGroupsCount,
            getGroups: getGroups,
            getAllGroups: getAllGroups,
            setGroupDescription: setGroupDescription
        };

        var urlGroups = "/iam/group/search";

        return service;

        function doGet(queryStr) {
            var url = urlGroups + '?' + queryStr;
            return $http.get(url);
        }

        function getGroupsFilteredAndSortBy(startIndex, count, filter, sortBy, sortDir) {
            console.debug("getGroupsFilteredAndSortBy: ", startIndex, count, filter, sortBy, sortDir);
            return doGet($httpParamSerializer({
                'startIndex': startIndex,
                'count': count,
                'filter': filter,
                'sortBy': sortBy,
                'sortDirection': sortDir
            }));
        }

        function getGroupsFilteredBy(startIndex, count, filter) {
            console.debug("getGroupsFilteredBy: ", startIndex, count, filter);
            return doGet($httpParamSerializer({
                'startIndex': startIndex,
                'count': count,
                'filter': filter
            }));
        }

        function getGroupsSortBy(startIndex, count, sortBy, sortDir) {
            console.debug("getGroupsSortBy: ", startIndex, count, sortBy, sortDir);
            return doGet($httpParamSerializer({
                'startIndex': startIndex,
                'count': count,
                'sortBy': sortBy,
                'sortDirection': sortDir
            }));
        }

        function getGroups(startIndex, count) {
            console.debug("getGroups: ", startIndex, count);
            return doGet($httpParamSerializer({
                'startIndex': startIndex,
                'count': count
            }));
        }

        function getGroupsCount() {
            console.debug("getGroupsCount");
            return doGet($httpParamSerializer({
                'count': 0
            }));
        }

        function setGroupDescription(group) {

            var handleSuccess = function (res) {
                return res;
            };

            var handleError = function (res) {
                console.warn("Error in setGroupDescription()", res.statusText);
                return res;
            };

            return $http.put("/iam/group/" + group.id, group).then(handleSuccess).catch(handleError);
        }

        function getAllGroups() {
            var results = [];

            var handleResults = function (res) {
                results = results.concat(res.data.Resources);

                if (res.data.totalResults == res.data.itemsPerPage) {
                    return results;
                } else {
                    var promises = [];

                    var numCalls = Math.floor(res.data.totalResults / res.data.itemsPerPage);

                    if (res.data.totalResults % res.data.itemsPerPage > 0) {
                        numCalls = numCalls + 1;
                    }

                    var appendResults = function (sc) {
                        results = results.concat(sc.data.Resources);
                        return sc;
                    };

                    for (var i = 1; i < numCalls; i++) {
                        var startIndex = i * res.data.itemsPerPage + 1;
                        promises.push($http.get("/iam/group/search?startIndex=" + startIndex).then(appendResults));
                    }

                    return $q.all(promises).then(function (res) {
                        return results;
                    });
                }
            };

            var handleError = function (res) {
                console.warn("Error in getAllGroups()", res.statusText);
                return res;
            };

            return $http.get("/iam/group/search").then(handleResults).catch(handleError);
        }
    }
})();