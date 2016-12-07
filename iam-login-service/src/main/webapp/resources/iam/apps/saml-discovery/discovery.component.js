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