'use strict';

angular.module('dashboardApp').controller('UserController', UserController);

UserController.$inject = [ '$scope', '$rootScope', '$state', '$uibModal', 'Utils', 'scimFactory', 'ModalService', 'ResetPasswordService' ];

function UserController($scope, $rootScope, $state, $uibModal, Utils, scimFactory, ModalService, ResetPasswordService) {

	var userCtrl = this;

	// methods
	userCtrl.isPageLoaded = isPageLoaded;
	userCtrl.loadUserData = loadUserData;
	userCtrl.showSshKeyValue = showSshKeyValue;
	userCtrl.showCertValue = showCertValue;
	userCtrl.openAddGroupDialog = openAddGroupDialog;
	userCtrl.openAddOIDCAccountDialog = openAddOIDCAccountDialog;
	userCtrl.openAddSshKeyDialog = openAddSshKeyDialog;
	userCtrl.openAddSamlAccountDialog = openAddSamlAccountDialog;
	userCtrl.openAddX509CertificateDialog = openAddX509CertificateDialog;
	userCtrl.openEditUserDialog = openEditUserDialog;
	userCtrl.deleteGroup = deleteGroup;
	userCtrl.deleteOidcAccount = deleteOidcAccount;
	userCtrl.deleteSshKey = deleteSshKey;
	userCtrl.deleteX509Certificate = deleteX509Certificate;
	userCtrl.deleteSamlId = deleteSamlId;
	userCtrl.setActive = setActive;
	userCtrl.doPasswordReset = doPasswordReset;
	userCtrl.sendResetMail = sendResetMail;

	// do
	console.log("User ID: ", $state.params.id);
	userCtrl.id = $state.params.id;

	userCtrl.isEditUserDisabled = false;
	userCtrl.isSendResetDisabled = false;
	userCtrl.isEnableUserDisabled = false;
	userCtrl.loadUserData();

	function loadUserData() {

		$rootScope.pageLoadingProgress = 0;
		userCtrl.loadingModal = $uibModal
		.open({
			animation: false,
			templateUrl : '/resources/iam/template/dashboard/loading-modal.html'
		});

		userCtrl.loadingModal.opened.then(function() {

			$rootScope.pageLoadingProgress = 30;

			scimFactory.getUser(userCtrl.id).then(function(response) {

					$scope.user = response.data;
					$rootScope.userLoadingProgress = 100;
					userCtrl.loadingModal.dismiss("Done");

				}, function(error) {

					$scope.operationResult = Utils.buildErrorOperationResult(error);
					userCtrl.loadingModal.dismiss("Error");
				});
		});
	}

	function isPageLoaded() {

		return $rootScope.pageLoadingProgress == 100;
	}

	function doPasswordReset() {
		
		ResetPasswordService.forgotPassword($scope.user.emails[0].value).then(
			function(response) {
				ModalService.showModal({}, {
					closeButtonText: null,
					user: $scope.user.name.formatted,
					actionButtonText: 'OK',
					headerText: 'Password reset requested',
					bodyText: `A password reset link has just been sent to your e-mail address`
				});
			}, function(error) {
				$scope.operationResult = Utils.buildErrorOperationResult(error);
			});
	}

	function sendResetMail() {

		userCtrl.isSendResetDisabled = true;
		var modalOptions = {
				closeButtonText: 'Cancel',
				actionButtonText: 'Send password reset e-mail',
				headerText: 'Send password reset e-mail',
				bodyText: `Are you sure you want to send the password reset e-mail to ${$scope.user.name.formatted}?`	
			};
				
		ModalService.showModal({}, modalOptions).then(
			function (){
				userCtrl.doPasswordReset();
				userCtrl.isSendResetDisabled = false;
			}, function () {
				userCtrl.isSendResetDisabled = false;
			});
	}

	function openEditUserDialog() {

		userCtrl.isEditUserDisabled = true;

		var modalInstance = $uibModal
				.open({
					templateUrl : '/resources/iam/template/dashboard/user/edituser.html',
					controller : 'EditUserController',
					controllerAs : 'editUserCtrl',
					resolve : {
						user : function() {
							return $scope.user;
						}
					}
				});
		modalInstance.result.then(function() {
			userCtrl.loadUserData();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's info updated successfully");
			userCtrl.isEditUserDisabled = false;
		}, function() {
			console.log('Modal dismissed at: ', new Date());
			userCtrl.isEditUserDisabled = false;
		});
	}
	
	function openAddGroupDialog() {
		var modalInstance = $uibModal
				.open({
					templateUrl : '/resources/iam/template/dashboard/user/addusergroup.html',
					controller : 'AddUserGroupController',
					controllerAs : 'addGroupCtrl',
					resolve : {
						user : function() {
							return $scope.user;
						}
					}
				});
		modalInstance.result.then(function() {
			console.info("Added group");
			userCtrl.loadUserData();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's memberships updated successfully");
		}, function() {
			console.log('Modal dismissed at: ', new Date());
		});
	}

	function openAddOIDCAccountDialog() {
		var modalInstance = $uibModal.open({
			templateUrl : '/resources/iam/template/dashboard/user/addoidc.html',
			controller : 'AddOIDCAccountController',
			controllerAs : 'addOidcCtrl',
			resolve : {
				user : function() {
					return $scope.user;
				}
			}
		});
		modalInstance.result.then(function() {
			console.info("Added oidc account");
			userCtrl.loadUserData();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's Open ID Account created successfully");
		}, function() {
			console.log('Modal dismissed at: ', new Date());
		});
	}

	function openAddSshKeyDialog() {
		var modalInstance = $uibModal.open({
			templateUrl : '/resources/iam/template/dashboard/user/addsshkey.html',
			controller : 'AddSshKeyController',
			controllerAs : 'addSshKeyCtrl',
			resolve : {
				user : function() {
					return $scope.user;
				}
			}
		});
		modalInstance.result.then(function() {
			console.info("Added ssh key");
			userCtrl.loadUserData();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's SSH Key added successfully");
		}, function(error) {
			console.log('Modal dismissed at: ', new Date());
		});
	}

	function openAddSamlAccountDialog() {
		var modalInstance = $uibModal
				.open({
					templateUrl : '/resources/iam/template/dashboard/user/addsamlaccount.html',
					controller : 'AddSamlAccountController',
					controllerAs : 'addSamlAccountCtrl',
					resolve : {
						user : function() {
							return $scope.user;
						}
					}
				});
		modalInstance.result.then(function() {
			console.info("Added saml account");
			userCtrl.loadUserData();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's SAML Account created successfully");
		}, function() {
			console.log('Modal dismissed at: ', new Date());
		});
	}

	function openAddX509CertificateDialog() {
		var modalInstance = $uibModal
				.open({
					templateUrl : '/resources/iam/template/dashboard/user/addx509certificate.html',
					controller : 'AddX509CertificateController',
					controllerAs : 'addX509CertCtrl',
					resolve : {
						user : function() {
							return $scope.user;
						}
					}
				});
		modalInstance.result.then(function() {
			console.info("Added x509 certificate");
			userCtrl.loadUserData();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's x509 Certificate added successfully");
		}, function() {
			console.log('Modal dismissed at: ', new Date());
		});
	}

	function deleteGroup(group) {
		
		var modalOptions = {
			closeButtonText: 'Cancel',
			actionButtonText: 'Remove user from group',
			headerText: 'Remove ' + $scope.user.name.formatted + ' from ' + group.display,
			bodyText: `Are you sure you want to remove «${$scope.user.name.formatted}» from «${group.display}»?`	
		};
			
		ModalService.showModal({}, modalOptions).then(
			function (){
				scimFactory.removeUserFromGroup(group.value, $scope.user.id,
						$scope.user.meta.location, $scope.user.name.formatted)
					.then(function(response) {
						console.info("Removed group", group);
						userCtrl.loadUserData();
						$scope.operationResult = Utils.buildSuccessOperationResult("Group membership removed successfully");
					}, function(error) {
						$scope.operationResult = Utils.buildErrorOperationResult(error);
					});
			});
	}

	function showSshKeyValue(sshKey) {

		ModalService.showModal({}, {
			closeButtonText: null,
			actionButtonText: 'OK',
			headerText: sshKey.display,
			bodyText: `${sshKey.value}`
		});
	}

	function showCertValue(cert) {

		ModalService.showModal({}, {
			closeButtonText: null,
			actionButtonText: 'OK',
			headerText: cert.display,
			bodyText: `${cert.value}`
		});
	}

	function deleteOidcAccount(oidcId) {

		var summary = oidcId.issuer + " - " + oidcId.subject;
		
		var modalOptions = {
				closeButtonText: 'Cancel',
				actionButtonText: 'Remove Open ID Account',
				headerText: 'Remove Open ID Account',
				bodyText: `Are you sure you want to remove the following Open ID Account?`,
				bodyDetail: `${summary}`
			};
				
			ModalService.showModal({}, modalOptions).then(
				function (){
					scimFactory.removeOpenIDAccount($scope.user.id, oidcId.issuer,
							oidcId.subject)
						.then(function(response) {
							console.info("Remove OIDC Account", oidcId.issuer, oidcId.subject);
							userCtrl.loadUserData();
							$scope.operationResult = Utils.buildSuccessOperationResult("Open ID Account has been removed successfully");
						}, function(error) {
							$scope.operationResult = Utils.buildErrorOperationResult(error);
						});
				});
	}

	function deleteSshKey(sshKey) {
		
		var modalOptions = {
				closeButtonText: 'Cancel',
				actionButtonText: 'Remove ssh key',
				headerText: 'Remove ssh key «' + sshKey.display + '»',
				bodyText: `Are you sure you want to remove '${sshKey.display} ssh key?`
			};
				
			ModalService.showModal({}, modalOptions).then(
				function (){
					scimFactory.removeSshKey($scope.user.id, sshKey.fingerprint)
						.then(function(response) {
							console.info("Removed SSH Key", sshKey.display, sshKey.fingerprint);
							userCtrl.loadUserData();
							$scope.operationResult = Utils.buildSuccessOperationResult("Ssh key has been removed successfully");
						}, function(error) {
							$scope.operationResult = Utils.buildErrorOperationResult(error);
						});
				});
	}

	function deleteX509Certificate(x509cert) {

		var modalOptions = {
				closeButtonText: 'Cancel',
				actionButtonText: 'Remove x509 Certificate',
				headerText: 'Remove «' + x509cert.display + '» x509 certificate?',
				bodyText: `Are you sure you want to remove «${x509cert.display}» x509 Certificate?`,
			};
				
			ModalService.showModal({}, modalOptions).then(
				function (){
					scimFactory.removeX509Certificate($scope.user.id, x509cert.value)
						.then(function(response) {
							console.info("Removed x509 Certificate", x509cert.display);
							userCtrl.loadUserData();
							$scope.operationResult = Utils.buildSuccessOperationResult("X509 Certificate has been removed successfully");
						}, function(error) {
							$scope.operationResult = Utils.buildErrorOperationResult(error);
						});
				});
	}

	function deleteSamlId(samlId) {

		var summary = samlId.idpId + " - " + samlId.userId;
		
		var modalOptions = {
				closeButtonText: 'Cancel',
				actionButtonText: 'Remove SAML Account',
				headerText: 'Remove SAML account',
				bodyText: `Are you sure you want to remove the following SAML Account?`,
				bodyDetail: `${summary}`	
			};
				
			ModalService.showModal({}, modalOptions).then(
				function (){
					scimFactory.removeSamlId($scope.user.id, samlId)
						.then(function(response) {
							console.info("Removed SAML Id", samlId.idpId, samlId.userId);
							userCtrl.loadUserData();
							$scope.operationResult = Utils.buildSuccessOperationResult("SAML Account has been removed successfully");
						}, function(error) {
							$scope.operationResult = Utils.buildErrorOperationResult(error);
						});
				});
	}

	function setActive(status) {

		userCtrl.isEnableUserDisabled = true;
		var modalOptions = {};
		
		if (status) {
			
			modalOptions = {
				closeButtonText: 'Cancel',
				actionButtonText: 'Enable user',
				headerText: 'Enable ' + $scope.user.name.formatted,
				bodyText: `Are you sure you want to enable '${$scope.user.name.formatted}'?`	
			};
		} else {
			
			modalOptions = {
				closeButtonText: 'Cancel',
				actionButtonText: 'Disable user',
				headerText: 'Disable ' + $scope.user.name.formatted,
				bodyText: `Are you sure you want to disable '${$scope.user.name.formatted}'?`	
			};
		}
		
		ModalService.showModal({}, modalOptions).then(
			function (){
				scimFactory.setUserActiveStatus($scope.user.id, status)
					.then(function(response) {
						userCtrl.loadUserData();
						if (status) {
							$scope.operationResult = Utils.buildSuccessOperationResult("User " + $scope.user.name.formatted + " enabled");
						} else {
							$scope.operationResult = Utils.buildSuccessOperationResult("User " + $scope.user.name.formatted + " disabled");
						}
						userCtrl.isEnableUserDisabled = false;
					}, function(error) {
						$scope.operationResult = Utils.buildErrorOperationResult(error);
						userCtrl.isEnableUserDisabled = false;
					});
			}, function () {
				userCtrl.isEnableUserDisabled = false;
			});
	}
}
