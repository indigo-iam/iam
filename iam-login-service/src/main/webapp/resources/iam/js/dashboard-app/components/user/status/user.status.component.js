(function() {
  'use strict';

  function UserStatusController(toaster, Utils, ModalService, scimFactory) {
    var self = this;

    self.$onInit = function() {
      self.enabled = true;
    };

    self.handleError = function(error) {
      self.userCtrl.handleError(error);
      self.enabled = true;
    };

    self.handleSuccess = function() {
      self.enabled = true;
      self.userCtrl.loadUser().then(function(user) {
        if (user.active) {
          toaster.pop({
            type: 'success',
            body:
                `User '${user.name.formatted}' has been restored successfully.`
          });
        } else {
          toaster.pop({
            type: 'success',
            body: `User '${user.name.formatted}' is now disabled.`
          });
        }
      });
    };

    self.enableUser = function() {
      return scimFactory.setUserActiveStatus(self.user.id, true)
          .then(self.handleSuccess)
          .catch(self.handleError);
    };

    self.disableUser = function() {
      return scimFactory.setUserActiveStatus(self.user.id, false)
          .then(self.handleSuccess)
          .catch(self.handleError);
    };


    self.openDialog = function() {

      var modalOptions = null;
      var updateStatusFunc = null;

      if (self.user.active) {
        modalOptions = {
          closeButtonText: 'Cancel',
          actionButtonText: 'Disable user',
          headerText: 'Disable ' + self.user.name.formatted,
          bodyText:
              `Are you sure you want to disable user '${self.user.name.formatted}'?`
        };
        updateStatusFunc = self.disableUser;

      } else {
        modalOptions = {
          closeButtonText: 'Cancel',
          actionButtonText: 'Restore user',
          headerText: 'Restore ' + self.user.name.formatted,
          bodyText:
              `Are you sure you want to restore user '${self.user.name.formatted}'?`
        };
        updateStatusFunc = self.enableUser;
      }

      self.enable = false;
      ModalService.showModal({}, modalOptions)
          .then(function() { updateStatusFunc(); })
          .catch(function() {

          });
    };


    self.isMe = function() { return Utils.isMe(self.user.id); };
  }

  angular.module('dashboardApp').component('userStatus', {
    require: {userCtrl: '^user'},
    bindings: {user: '='},
    templateUrl:
        '/resources/iam/js/dashboard-app/components/user/status/user.status.component.html',
    controller: [
      'toaster', 'Utils', 'ModalService', 'scimFactory', UserStatusController
    ]
  });

})();