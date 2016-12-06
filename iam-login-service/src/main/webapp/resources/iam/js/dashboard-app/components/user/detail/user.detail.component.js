(function() {
  'use strict';

  function UserDetailController(Utils) {
    var self = this;

    self.$onInit = function() { console.log('userDetailController onInit'); };
    
    self.isVoAdmin = function() {
      return Utils.userIsVoAdmin(self.user);
    };
  }

  angular.module('dashboardApp').component('userDetail', {
    templateUrl: "/resources/iam/js/dashboard-app/components/user/detail/user.detail.component.html",
    bindings: {user: '<'},
    controller: ['Utils',UserDetailController]
  });
})();