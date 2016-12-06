(function() {
  'use strict';

  function UserEditController(toaster, Utils, $uibModal) {
    var self = this;

    self.$onInit = function() {
      console.log('userEditController onInit');
      self.enabled = true;
    };

    self.handleSuccess = function() {
      self.enabled = true;
      self.userCtrl.loadUser().then(function(user) {
        toaster.pop({
          type: 'success',
          body: `User '${user.name.formatted}' updated succesfully.`
        });
      });
    };

    self.openDialog = function() {
      self.enabled = false;
      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/template/dashboard/user/edituser.html',
        controller: 'EditUserController',
        controllerAs: 'editUserCtrl',
        resolve: {user: function() { return self.user; }}
      });

      modalInstance.result.then(self.handleSuccess);

    };
  }

  angular.module('dashboardApp').component('userEdit', {
    require: {userCtrl: '^user'},
    templateUrl:
        '/resources/iam/js/dashboard-app/components/user/edit/user.edit.component.html',
    bindings: {user: '='},
    controller: ['toaster', 'Utils', '$uibModal', UserEditController]
  });
})();