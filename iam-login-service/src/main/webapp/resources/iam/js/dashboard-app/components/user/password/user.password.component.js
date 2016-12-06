(function() {
  'use strict';

  function UserPasswordController(
      toaster, Utils, ModalService, ResetPasswordService, $uibModal) {
    var self = this;

    self.$onInit = function() {
      console.log('UserPasswordController onInit');
      self.enabled = true;
      self.user = self.userCtrl.user;
    };

    self.isMe = function() { return self.userCtrl.isMe(); };

    self.doPasswordReset = function() {

      ResetPasswordService.forgotPassword(self.user.emails[0].value)
          .then(
              function(response) {
                toaster.pop({
                  type: 'success',
                  body:
                      'A password reset link has just been sent to the user email address'
                });
              },
              function(error) { toaster.pop({type: 'error', body: error}); });
    };

    self.openResetPasswordModal = function() {
      self.enabled = false;

      var modalOptions = {
        closeButtonText: 'Cancel',
        actionButtonText: 'Send password reset e-mail',
        headerText: 'Send password reset e-mail',
        bodyText:
            `Are you sure you want to send the password reset e-mail to ${self.user.name.formatted}?`
      };

      ModalService.showModal({}, modalOptions)
          .then(
              function() {
                self.doPasswordReset();
                self.enabled = true;

              },
              function() { self.enabled = true; });

    };

    self.openEditPasswordModal = function() {

      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/template/dashboard/home/editpassword.html',
        controller: 'EditPasswordController',
        controllerAs: 'editPasswordCtrl',
        resolve: {user: function() { return self.user; }}
      });

      modalInstance.result.then(function(msg) {
        toaster.pop({type: 'success', body: msg});
      });
    };
  }



  angular.module('dashboardApp').component('userPassword', {
    require: {userCtrl: '^user'},
    templateUrl:
        '/resources/iam/js/dashboard-app/components/user/password/user.password.component.html',
    controller: [
      'toaster', 'Utils', 'ModalService', 'ResetPasswordService', '$uibModal',
      UserPasswordController
    ]
  });
})();