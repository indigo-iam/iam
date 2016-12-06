(function() {
  'use strict';

  angular.module('discoveryApp').component('discovery', {
    templateUrl: '/resources/iam/apps/saml-discovery/discovery.component.html',

    controller: DiscoveryController

  });

  DiscoveryController.$inject =
      ['$timeout', '$scope', '$http', '$cookies', '$window'];

  function DiscoveryController($timeout, $scope, $http, $cookies, $window) {
    var self = this;

    $scope.lookupIdp = function(val) {

      var result =
          $http.get('/saml/idps', {params: {q: val}}).then(function(response) {
            return response.data;
          });

      return result;
    };

    $scope.reset = function() {
      $scope.idpSelected = null;
      $timeout(function() {
        $window.document.getElementById('idp-selection-input').focus();
      }, 0);
    };

    $scope.ok = function() {
      $window.location.href = '/saml/login?idp=' + $scope.idpSelected.entityId;
    };

    $scope.cancel = function() { $uibModalInstance.close(); };
  }

})();