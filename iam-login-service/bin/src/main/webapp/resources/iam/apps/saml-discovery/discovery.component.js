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
(function() {
  'use strict';

  angular.module('discoveryApp').component('discovery', {
    templateUrl: '/resources/iam/apps/saml-discovery/discovery.component.html',

    controller: DiscoveryController

  });

  DiscoveryController.$inject =
      ['$timeout', '$scope', '$http', '$cookies', '$window'];

  function DiscoveryController($timeout, $scope, $http, $cookies, $window) {
    var COOKIE_KEY = 'iam:idp-selection:cookie';
    
    var self = this;

    $scope.rememberChoice = 'n';
    $scope.hasRememberCookie = false;
    
    self.lookupIdpChoice = function(){
      var idpCookie = $cookies.get(COOKIE_KEY);
      if (idpCookie){
        $scope.hasRememberCookie = true;
        $scope.idpSelected = angular.fromJson(idpCookie);
      }
    };

    self.clearIdpChoice = function(){
      $cookies.remove(COOKIE_KEY);
      $scope.hasRememberCookie = false;
    };

    self.storeIdpChoice = function(){
      if ($scope.rememberChoice === 'y'){
        $cookies.putObject(COOKIE_KEY, $scope.idpSelected);
      }
    };

    $scope.lookupIdp = function(val) {

      var result =
          $http.get('/saml/idps', {params: {q: val}}).then(function(response) {
            return response.data;
          });

      return result;
    };

    $scope.reset = function() {

      $scope.idpSelected = null;
      self.clearIdpChoice();
      $timeout(function() {
        $window.document.getElementById('idp-selection-input').focus();
      }, 0);
    };

    $scope.ok = function() {
      self.storeIdpChoice();
      $window.location.href = '/saml/login?idp=' + $scope.idpSelected.entityId;
    };

    $scope.cancel = function() { $uibModalInstance.close(); };

    self.lookupIdpChoice();

  }

})();