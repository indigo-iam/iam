(function() {
  'use strict';

  function LinkOidcController(AccountLinkingService, $uibModalInstance, action, account) {
    var self = this;

    self.action = action;
    self.actionUrl = '/iam/account-linking/OIDC';
    self.type = 'google';
    self.account = account;
    self.enabled = true;

    self.doLink = function() {
      self.enabled = false;
      document.getElementById("link-account-form").submit();
    };

    self.doUnlink = function() {
      self.enabled = false;
      AccountLinkingService.unlinkOidcAccount(self.account).then(function(response){
        $uibModalInstance.close(response);
      }).catch(function(error){
        console.error(error);
      });
    };

    self.cancel = function() { $uibModalInstance.dismiss('Dismissed'); };
  }

  function UserOidcController($uibModal, toaster, ModalService, scimFactory) {
    var self = this;

    self.indigoUser = function() {
      return self.user['urn:indigo-dc:scim:schemas:IndigoUser'];
    };

    self.isMe = function() { return self.userCtrl.isMe(); };

    self.isVoAdmin = function() { return self.userCtrl.isVoAdmin(); };

    self.$onInit = function() {
      console.log('UserOidcController onInit');
      self.enabled = true;
    };

    self.handleSuccess = function(user) {
      self.enabled = true;
      self.userCtrl.loadUser().then(function(user) {
        toaster.pop({
          type: 'success',
          body:
              `User '${user.name.formatted}' OpenID-Connect accounts updated succesfully`
        });
      });
    };

    self.hasOidcIds = function() {
      var oidcIds = self.getOidcIds();

      if (oidcIds) {
        return oidcIds.length > 0;
      }

      return false;
    };

    self.getOidcIds = function() {
      if (self.indigoUser()) {
        return self.indigoUser().oidcIds;
      }

      return undefined;
    };

    self.openAddOidcAccountDialog = function() {
      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/template/dashboard/user/addoidc.html',
        controller: 'AddOIDCAccountController',
        controllerAs: 'addOidcCtrl',
        resolve: {user: function() { return self.user; }}
      });

      modalInstance.result.then(self.handleSuccess);
    };

    self.openLinkOidcAccountDialog = function() {
      var modalInstance = $uibModal.open({
        templateUrl:
            '/resources/iam/js/dashboard-app/components/common/user.linking.dialog.html',
        controller: LinkOidcController,
        controllerAs: '$ctrl',
        resolve: {action: function() { return 'link'; }, account: undefined}
      });

      modalInstance.result.then(self.handleSuccess);
    };

    self.openUnlinkOidcAccountDialog = function(oidcId) {

      var modalInstance = $uibModal.open({
        templateUrl:
            '/resources/iam/js/dashboard-app/components/common/user.linking.dialog.html',
        controller: LinkOidcController,
        controllerAs: '$ctrl',
        resolve: {
          action: function() { return 'unlink'; },
          account: function() {
            return { iss: oidcId.issuer, sub: oidcId.subject }
          }
        }
      });

      modalInstance.result.then(self.handleSuccess);
    };



    self.openRemoveOidcAccountDialog = function(oidcId) {
      var account = `${oidcId.issuer} : ${oidcId.subject}`;

      var modalOptions = {
        closeButtonText: 'Cancel',
        actionButtonText: `Remove OpenID-Connect Account'`,
        headerText:
            `Remove OpenID-Connect Account from user '${self.user.name.formatted}'`,
        bodyText:
            `Are you sure you want to remove the following Open ID Account from user '${self.user.name.formatted}'?`,
        bodyDetail: account
      };

      ModalService.showModal({}, modalOptions).then(function() {
        scimFactory
            .removeOpenIDAccount(self.user.id, oidcId.issuer, oidcId.subject)
            .then(self.handleSuccess)
            .catch(self.userCtrl.handleError);
      });
    };
  }

  angular.module('dashboardApp').component('userOidc', {
    require: {userCtrl: '^user'},
    bindings: {user: '='},
    templateUrl:
        '/resources/iam/js/dashboard-app/components/user/oidc/user.oidc.component.html',
    controller: [
      '$uibModal', 'toaster', 'ModalService', 'scimFactory', UserOidcController
    ]
  });
})();