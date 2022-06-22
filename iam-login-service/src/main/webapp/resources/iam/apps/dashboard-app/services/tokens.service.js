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

angular.module('dashboardApp').factory('TokensService', TokensService);

TokensService.$inject = [ '$q', '$rootScope', '$http', '$httpParamSerializer' ];

function TokensService($q, $rootScope, $http, $httpParamSerializer) {
    var service = {
        getAccessTokens : getAccessTokens,
        getAccessToken : getAccessToken,
        getAccessTokensFilteredByUser : getAccessTokensFilteredByUser,
        getAccessTokensFilteredByClient : getAccessTokensFilteredByClient,
        getAccessTokensFilteredByUserAndClient : getAccessTokensFilteredByUserAndClient,
        revokeAccessToken : revokeAccessToken,
        getRefreshToken : getRefreshToken,
        getRefreshTokensFilteredByUser : getRefreshTokensFilteredByUser,
        getRefreshTokensFilteredByClient : getRefreshTokensFilteredByClient,
        getRefreshTokensFilteredByUserAndClient : getRefreshTokensFilteredByUserAndClient,
        getRefreshTokens : getRefreshTokens,
        revokeRefreshToken : revokeRefreshToken,
        getAccessTokensCount : getAccessTokensCount,
        getRefreshTokensCount : getRefreshTokensCount
    };

    var urlAccessTokens = "/iam/api/access-tokens";
    var urlRefreshTokens = "/iam/api/refresh-tokens";

    return service;

    function getAccessTokensFilteredByUser(startIndex, count, userName) {
        console.debug("Getting access-tokens offset-limit: ", startIndex, count);
        console.debug("Filtered user: ", userName);
        var qs = $httpParamSerializer({
            'startIndex' : startIndex,
            'count' : count,
            'userId' : userName
        });
        var url = urlAccessTokens + '?' + qs;
        return $http.get(url);
    }

    function getRefreshTokensFilteredByUser(startIndex, count, userName) {
      console.debug("Getting refresh-tokens offset-limit: ", startIndex, count);
      console.debug("Filtered user: ", userName);
      var qs = $httpParamSerializer({
          'startIndex' : startIndex,
          'count' : count,
          'userId' : userName
      });
      var url = urlRefreshTokens + '?' + qs;
      return $http.get(url);
    }

    function getAccessTokensFilteredByClient(startIndex, count, clientId) {
        console.debug("Getting access-tokens offset-limit: ", startIndex, count);
        console.debug("Filtered client: ", clientId);
        var qs = $httpParamSerializer({
            'startIndex' : startIndex,
            'count' : count,
            'clientId' : clientId
        });
        var url = urlAccessTokens + '?' + qs;
        return $http.get(url);
    }

    function getRefreshTokensFilteredByClient(startIndex, count, clientId) {
      console.debug("Getting refresh-tokens offset-limit: ", startIndex, count);
      console.debug("Filtered client: ", clientId);
      var qs = $httpParamSerializer({
          'startIndex' : startIndex,
          'count' : count,
          'clientId' : clientId
      });
      var url = urlRefreshTokens + '?' + qs;
      return $http.get(url);
  }

    function getAccessTokensFilteredByUserAndClient(startIndex, count, userName, clientId) {
        console.debug("Getting access-tokens offset-limit: ", startIndex, count);
        console.debug("Filtered user and client: ", userName, clientId);
        var qs = $httpParamSerializer({
            'startIndex' : startIndex,
            'count' : count,
            'clientId' : clientId,
            'userId' : userName
        });
        var url = urlAccessTokens + '?' + qs;
        return $http.get(url);
    }

    function getRefreshTokensFilteredByUserAndClient(startIndex, count, userName, clientId) {
        console.debug("Getting refresh-tokens offset-limit: ", startIndex, count);
        console.debug("Filtered user and client: ", userName, clientId);
        var qs = $httpParamSerializer({
            'startIndex' : startIndex,
            'count' : count,
            'clientId' : clientId,
            'userId' : userName
        });
        var url = urlRefreshTokens + '?' + qs;
        return $http.get(url);
    }

    function getAccessTokens(startIndex, count) {
      console.debug("Getting access-tokens offset-limit: ", startIndex, count);
      var qs = $httpParamSerializer({
          'startIndex' : startIndex,
          'count' : count
      });
      var url = urlAccessTokens + '?' + qs;
      return $http.get(url);
    }

    function getRefreshTokens(startIndex, count) {
      console.debug("Getting refresh-tokens offset-limit: ", startIndex, count);
      var qs = $httpParamSerializer({
          'startIndex' : startIndex,
          'count' : count
      });
      var url = urlRefreshTokens + '?' + qs;
      return $http.get(url);
    }

    function getAccessToken(id) {
        console.debug("Getting access-token with id: ", id);
        var url = urlAccessTokens + '/' + id;
        return $http.get(url);
    }

    function revokeAccessToken(id) {
      console.debug("Revoking access-token with id: ", id);
      var url = urlAccessTokens + '/' + id;
      return $http.delete(url);
    }

    function getRefreshToken(id) {
      console.debug("Getting refresh-token with id: ", id);
      var url = urlRefreshTokens + '/' + id;
      return $http.get(url);
    }

    function revokeRefreshToken(id) {
      console.debug("Revoking refresh-token with id: ", id);
      var url = urlRefreshTokens + '/' + id;
      return $http.delete(url);
    }

    function getAccessTokensCount() {
      var qs = $httpParamSerializer({
          'count' : 0
      });
      var url = urlAccessTokens + '?' + qs;
      return $http.get(url);
    }

    function getRefreshTokensCount() {
      var qs = $httpParamSerializer({
          'count' : 0
      });
      var url = urlRefreshTokens + '?' + qs;
      return $http.get(url);
    }

}