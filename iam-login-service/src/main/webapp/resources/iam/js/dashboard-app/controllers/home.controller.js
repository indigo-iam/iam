'use strict';

angular.module('dashboardApp').controller('HomeController', HomeController);

HomeController.$inject = [ '$scope', '$state', '$cookies', 'Utils', 'scimFactory', 'ModalService', '$uibModal' ];

function HomeController($scope, $state, $cookies, Utils, scimFactory, ModalService, $uibModal) {

	var home = this;

	home.loadUserData = loadUserData;
	home.showSshKeyValue = showSshKeyValue;
	home.showCertValue = showCertValue;
	home.openEditPasswordDialog = openEditPasswordDialog;
	home.openEditUserDialog = openEditUserDialog;

	home.loaded = false;
	home.isEditUserDisabled = false;

	home.linkOidcAccount = linkOidcAccount;
	home.unlinkOidcAccount = unlinkOidcAccount;
	home.showAccountLinkingFeedback = showAccountLinkingFeedback;

	home.loadUserData();
	home.showAccountLinkingFeedback();

	function showAccountLinkingFeedback(){

		var accountLinkingError = $cookies.get('account-linking.error');
		
		if (accountLinkingError){
			$scope.operationResult = Utils.buildErrorResult(angular.fromJson(accountLinkingError));
			$cookies.remove('account-linking.error');
		}

		var accountLinkingMessage = $cookies.get('account-linking.message');
		if (accountLinkingMessage){
			$scope.operationResult = Utils.buildSuccessOperationResult(angular.fromJson(accountLinkingMessage));
			$cookies.remove('account-linking.message');
		}
	}

	function loadUserData() {
		scimFactory.getMe().then(function(response) {
			$scope.user = response.data;
			home.loaded = true;
		}, function(error) {
			$scope.operationResult = Utils.buildErrorOperationResult(error);
		});
	}

	function showSshKeyValue(value) {
		ModalService.showModal({}, {
			closeButtonText: null,
			actionButtonText: 'OK',
			headerText: 'SSH Key value',
			bodyText: `${value}`
		});
	}

	function showCertValue(cert) {
		ModalService.showModal({}, {
			closeButtonText: null,
			actionButtonText: 'OK',
			headerText: 'x509 Certificate value',
			bodyText: `${cert.value}`
		});
	}

	function openEditPasswordDialog() {

		var modalInstance = $uibModal
				.open({
					templateUrl : '/resources/iam/template/dashboard/home/editpassword.html',
					controller : 'EditPasswordController',
					controllerAs : 'editPasswordCtrl',
					resolve : {
						user : function() {
							return $scope.user;
						}
					}
				});
		modalInstance.result.then(function() {
			$scope.operationResult = Utils.buildSuccessOperationResult("User's info updated successfully");
		}, function() {
			console.info('Modal dismissed at: ', new Date());
		});
	}

	function openEditUserDialog() {

		home.isEditUserDisabled = true;

		var modalInstance = $uibModal
				.open({
					templateUrl : '/resources/iam/template/dashboard/home/edituser.html',
					controller : 'EditMeController',
					controllerAs : 'editMeCtrl',
					resolve : {
						user : function() {
							return $scope.user;
						}
					}
				});
		modalInstance.result.then(function() {
			home.loadUserData();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's info updated successfully");
			home.isEditUserDisabled = false;
		}, function() {
			console.log('Modal dismissed at: ', new Date());
			home.isEditUserDisabled = false;
		});
	}

	function linkOidcAccount(){

		var opts = {
			type: 'Google',
			action: 'link'
		}

		var modal = $uibModal
				.open({
					templateUrl : '/resources/iam/template/dashboard/home/account-link-dialog.html',
					controller: 'AccountLinkingController',
					controllerAs: 'ctrl',
					resolve: {
						opts: function(){
							return opts;
						}
					}
				});

		modal.result.then(function(){
			home.loadUserData();
			$scope.operationResult = Utils.buildSuccessOperationResult("Account linked successfully");
		}, function(){
			console.log('Modal dismissed at: ', new Date());
		});
	
	}

	function unlinkOidcAccount(){

	}
}