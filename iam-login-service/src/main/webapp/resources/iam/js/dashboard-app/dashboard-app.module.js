'use strict';

angular.module('dashboardApp', [ 'ui.router', 'ui.bootstrap',
		'ui.bootstrap.tpls', 'ui.select', 'ngAnimate', 'ngSanitize',
		'relativeDate' ]);

angular.module('dashboardApp').run(
		function($window, $rootScope, $state, $stateParams, $uibModal, Utils,
				scimFactory, RegistrationRequestService) {

	// Offline dialog
	$rootScope.closeOfflineDialog = function() {

		console.log("into: closeOfflineDialog");

		if ($rootScope.offlineDialog) {

			console.log("Closing offline dialog");
			$rootScope.offlineDialog.dismiss("Back online");
			$rootScope.offlineDialog = undefined;
		}
	}
	
	$rootScope.openOfflineDialog = function() {
		
		if (!$rootScope.offlineDialog) {
			
			console.log("Opening offline dialog");
			$rootScope.offlineDialog = $uibModal
				.open({
					animation : false,
					backdrop  : 'static',
					keyboard  : false,
					templateUrl: "noConnectionTemplate.html"
				});
		}
	}

	// logged user
	$rootScope.loggedUser = Utils.getLoggedUser();
	$rootScope.isRegistrationEnabled = Utils.isRegistrationEnabled();

	$rootScope.reloadUser = function() {
		scimFactory.getMe().then(function(response) {
			console.log(response);
			$rootScope.loggedUser.me = response.data;
		}, function(error) {
			console.error(error);
		});
	}

	$rootScope.reloadUser();

	if ($rootScope.isRegistrationEnabled) {
		RegistrationRequestService.listPending().then(function(response) {
			console.log(response.data);
			$rootScope.loggedUser.pendingRequests = response.data;
		}, function(error) {
			console.error(error);
			$rootScope.loggedUser.pendingRequests = undefined;
		});
	}

	scimFactory.getUsers(1, 1).then(function(response) {
		console.log(response.data);
		$rootScope.loggedUser.totUsers = response.data.totalResults;
	}, function(error) {
		console.error(error);
		$rootScope.loggedUser.totUsers = undefined;
	});

	scimFactory.getGroups(1, 1).then(function(response) {
		console.log(response.data);
		$rootScope.loggedUser.totGroups = response.data.totalResults;
	}, function(error) {
		console.error(error);
		$rootScope.loggedUser.totGroups = undefined;
	});

	// ctrl+R refresh
	$rootScope.reload = function() {
		$window.location.reload();
	}

	// refresh last state loaded
	$rootScope.refresh = function() {

		$rootScope.closeOfflineDialog();
		$state.transitionTo($state.current, $stateParams, {
			reload : true,
			inherit : false,
			notify : true
		});
	}
});