(function() {
  'use strict';

  function UserController(
      $timeout, $cookies, $rootScope, $uibModal, ModalService, scimFactory,
      UserService, Utils, toaster) {
    var self = this;

    self.$onInit = function() {
      console.log('userController onInit');
      self.loaded = true;
      $timeout(self.showAccountLinkingFeedback, 0);
    };

    self.isVoAdmin = function() { return Utils.isAdmin(); };

    self.userIsVoAdmin = function() { return Utils.userIsVoAdmin(self.user); };

    self.showAccountLinkingFeedback = function() {
      if (_accountLinkingError){
        toaster.pop({type: 'error', body: _accountLinkingError});
        _accountLinkingError = '';
      }
       
      if (_accountLinkingMessage) {
        toaster.pop({type: 'success', body: _accountLinkingMessage});
        _accountLinkingMessage = '';
      }
    };

    self.isMe = function() { return Utils.isMe(self.user.id); };

    self.handleError = function(error) {
      console.error(error);
      toaster.pop({type: 'error', body: error});
    };

    self.openLoadingModal = function() {
      $rootScope.pageLoadingProgress = 0;
      self.modal = $uibModal.open({
        animation: false,
        templateUrl: '/resources/iam/template/dashboard/loading-modal.html'
      });

      return self.modal.opened;
    };

    self.closeLoadingModal = function() {
      $rootScope.pageLoadingProgress = 100;
      self.modal.dismiss('Cancel');
    };

    self.loadUser = function() {

      return self.openLoadingModal()
          .then(function() {
            if (self.isMe()) {
              return UserService.getMe();
            } else {
              return UserService.getUser(self.user.id);
            }
          })
          .then(function(user) {
            self.user = user;
            self.closeLoadingModal();
            return user;
          })
          .catch(self.handleError);
    };
  }


  angular.module('dashboardApp').component('user', {
    templateUrl:
        '/resources/iam/js/dashboard-app/components/user/user.component.html',
    bindings: {user: '<'},
    controller: [
      '$timeout', '$cookies', '$rootScope', '$uibModal', 'ModalService',
      'scimFactory', 'UserService', 'Utils', 'toaster', UserController
    ]
  });
})();