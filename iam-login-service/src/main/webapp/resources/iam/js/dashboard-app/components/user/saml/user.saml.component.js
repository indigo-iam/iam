(function() {
  'use strict';

  function LinkSamlController(AccountLinkingService, $uibModalInstance, action, account) {
    var self = this;

    self.enabled = true;
    self.action = action;
    self.actionUrl = '/iam/account-linking/SAML';
    self.type = 'SAML';
    self.account = account;

    self.doLink = function() {
      self.enabled = false;
      document.getElementById("link-account-form").submit();
    };

    self.doUnlink = function() {
      self.enabled = false;
      AccountLinkingService.unlinkSamlAccount(self.account).then(function(response){
        $uibModalInstance.close(response);
      }).catch(function(error){
        console.error(error);
      });
    };

    self.cancel = function() { $uibModalInstance.dismiss('Dismissed'); };
  }

  function IdpSelectionController(
      $scope, $http, $uibModalInstance, $window, $timeout) {
    $scope.ok = function() {
      $window.location.href = '/saml/login?idp=' + $scope.idpSelected.entityId;
    };

    $scope.cancel = function() { $uibModalInstance.close(); };

    $scope.reset = function() {
      $scope.idpSelected = null;
      $timeout(function() {
        $window.document.getElementById('idp-selection-input').focus();
      }, 0);
    };

    $scope.lookupIdp = function(val) {

      var result =
          $http.get('/saml/idps', {params: {q: val}}).then(function(response) {
            return response.data;
          });

      return result;
    };
  }

  function UserSamlController(toaster, $uibModal, ModalService, scimFactory) {
    var self = this;

    self.indigoUser = function() {
      return self.user['urn:indigo-dc:scim:schemas:IndigoUser'];
    };

    self.$onInit = function() {
      console.log('UserSamlController onInit');
      self.enabled = true;
    };

    self.isVoAdmin = function() { return self.userCtrl.isVoAdmin(); };

    self.isMe = function() { return self.userCtrl.isMe(); };

    self.handleSuccess = function(user) {
      self.enabled = true;
      self.userCtrl.loadUser().then(function(user) {
        toaster.pop({
          type: 'success',
          body:
              `User '${user.name.formatted}' SAML accounts updated succesfully`
        });
      });
    };
    
    self.openLinkSamlAccountDialog = function() {
      var modalInstance = $uibModal.open({
        templateUrl:
            '/resources/iam/js/dashboard-app/components/common/user.linking.dialog.html',
        controller: LinkSamlController,
        controllerAs: '$ctrl',
        resolve: {action: function() { return 'link'; }, account: undefined}
      });

      modalInstance.result.then(self.handleSuccess);

    };

    self.openAddSamlAccountDialog = function() {
      var modalInstance = $uibModal.open({
        templateUrl:
            '/resources/iam/template/dashboard/user/addsamlaccount.html',
        controller: 'AddSamlAccountController',
        controllerAs: 'addSamlAccountCtrl',
        resolve: {user: function() { return self.user; }}
      });

      modalInstance.result.then(self.handleSuccess);
    };

    self.openRemoveSamlAccountDialog = function(samlId) {
      var account = `${samlId.idpId} : ${samlId.userId}`;

      var modalOptions = {
        closeButtonText: 'Cancel',
        actionButtonText: 'Remove SAML Account',
        headerText:
            `Remove SAML account from user '${self.user.name.formatted}'`,
        bodyText:
            `Are you sure you want to remove the following SAML Account from user '${self.user.name.formatted}'?`,
        bodyDetail: account
      };

      ModalService.showModal({}, modalOptions).then(function() {
        scimFactory.removeSamlId(self.user.id, samlId)
            .then(self.handleSuccess)
            .catch(self.userCtrl.handleError);
      });
    };

    self.openUnlinkSamlAccountDialog = function(samlId) {
      var modalInstance = $uibModal.open({
        templateUrl:
            '/resources/iam/js/dashboard-app/components/common/user.linking.dialog.html',
        controller: LinkSamlController,
        controllerAs: '$ctrl',
        resolve: {
          action: function() { return 'unlink'; },
          account: function() {
            return { iss: samlId.idpId, sub: samlId.userId }
          }
        }
      });

      modalInstance.result.then(self.handleSuccess);

    };

    self.hasSamlIds = function() {
      var samlIds = self.getSamlIds();

      if (samlIds) {
        return samlIds.length > 0;
      }

      return false;
    };

    self.getSamlIds = function() {
      if (self.indigoUser()) {
        return self.indigoUser().samlIds;
      }

      return undefined;
    };
  }

  angular.module('dashboardApp').component('userSaml', {
    require: {userCtrl: '^user'},
    bindings: {user: '='},
    templateUrl:
        '/resources/iam/js/dashboard-app/components/user/saml/user.saml.component.html',
    controller: [
      'toaster', '$uibModal', 'ModalService', 'scimFactory', UserSamlController
    ]
  });
})();