(function() {
  'use strict';
  angular.module('dashboardApp')
      .factory('AccountLinkingService', AccountLinkingService);

  AccountLinkingService.$inject = ['$http'];

  function AccountLinkingService($http) {
    var OIDC_RESOURCE = '/iam/account-linking/OIDC';
    var SAML_RESOURCE = '/iam/account-linking/SAML';

    var service = {
      unlinkOidcAccount: unlinkOidcAccount,
      unlinkSamlAccount: unlinkSamlAccount
    };

    return service;

    function unlinkOidcAccount(account) {
      return $http.delete(
          OIDC_RESOURCE, {params: {iss: account.iss, sub: account.sub}});
    }

    function unlinkSamlAccount(account) {
      return $http.delete(
          SAML_RESOURCE, {params: {iss: account.iss, sub: account.sub}});
    }
  }

})();