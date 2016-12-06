'use strict';

angular.module('dashboardApp', [
  'ui.router', 'ui.bootstrap', 'ui.bootstrap.tpls', 'ui.select', 'ngCookies',
  'ngSanitize', 'relativeDate', 'ngResource', 'toaster'
]);

angular.module('dashboardApp')
    .run(function(
        $window, $rootScope, $state, $stateParams, $q, $uibModal, $trace, Utils,
        scimFactory, UserService, RegistrationRequestService,
        LoadTemplatesService) {

      $state.defaultErrorHandler(function(error) { console.error(error); });

      $rootScope.iamVersion = getIamVersion();
      $rootScope.iamCommitId = getIamGitCommitId();
      
      LoadTemplatesService.loadTemplates();

      $trace.enable('TRANSITION');

      // Offline dialog
      $rootScope.closeOfflineDialog = function() {

        console.log('into: closeOfflineDialog');

        if ($rootScope.offlineDialog) {
          console.log('Closing offline dialog');
          $rootScope.offlineDialog.dismiss('Back online');
          $rootScope.offlineDialog = undefined;
        }
      };

      $rootScope.openOfflineDialog = function() {

        if (!$rootScope.offlineDialog) {
          console.log('Opening offline dialog');
          $rootScope.offlineDialog = $uibModal.open({
            animation: false,
            backdrop: 'static',
            keyboard: false,
            templateUrl: 'noConnectionTemplate.html'
          });
        }
      };

      $rootScope.reloadInfo = function() {

        var promises = [];
        promises.push(UserService.updateLoggedUserInfo());

        if ($rootScope.isRegistrationEnabled && Utils.isAdmin()) {
          promises.push(RegistrationRequestService.listPending().then(function(
              r) { $rootScope.loggedUser.pendingRequests = r.data; }));
        }

        return $q.all(promises).catch(function(error){
          console.error("Error loading logged user info"+error);
        });
      };

      $rootScope.reloadInfo();

      // ctrl+R refresh
      $rootScope.reload = function() { $window.location.reload(); };

      // refresh last state loaded
      $rootScope.refresh = function() {

        $rootScope.closeOfflineDialog();
        $state.transitionTo(
            $state.current, $stateParams,
            {reload: true, inherit: false, notify: true});
      };

      $('#body').show();

    });