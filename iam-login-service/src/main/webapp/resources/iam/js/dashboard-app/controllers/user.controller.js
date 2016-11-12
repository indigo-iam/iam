'use strict';

angular.module('dashboardApp').controller('UserController', UserController);

UserController.$inject = [ '$scope', '$rootScope', '$state', '$uibModal', '$filter', 'filterFilter', 'Utils', 'scimFactory', 'ModalService', 'ResetPasswordService', 'RegistrationRequestService' ];

function UserController($scope, $rootScope, $state, $uibModal, $filter, filterFilter, Utils, scimFactory, ModalService, ResetPasswordService, RegistrationRequestService) {

	var user = this;

	console.log("User ID: ", $state.params.id);

	user.id = $state.params.id;

	user.userInfo = {};

	// methods
	user.getIndigoUserInfo = getIndigoUserInfo;
	user.showSshKeyValue = showSshKeyValue;
	user.showCertValue = showCertValue;
	user.openAddGroupDialog = openAddGroupDialog;
	user.openAddOIDCAccountDialog = openAddOIDCAccountDialog;
	user.openAddSshKeyDialog = openAddSshKeyDialog;
	user.openAddSamlAccountDialog = openAddSamlAccountDialog;
	user.openAddX509CertificateDialog = openAddX509CertificateDialog;
	user.openEditUserDialog = openEditUserDialog;
	user.deleteGroup = deleteGroup;
	user.deleteOidcAccount = deleteOidcAccount;
	user.deleteSshKey = deleteSshKey;
	user.deleteX509Certificate = deleteX509Certificate;
	user.deleteSamlId = deleteSamlId;
	user.setActive = setActive;
	
	// password reset
	user.doPasswordReset = doPasswordReset;
	user.sendResetMail = sendResetMail;

	user.getIndigoUserInfo();

	function getIndigoUserInfo() {

		$rootScope.pageLoadingProgress = 0;

		user.loadingModal = $uibModal
		.open({
			animation: false,
			templateUrl : '/resources/iam/template/dashboard/loading-modal.html'
		});

		user.loadingModal.opened.then(function() {

			$rootScope.pageLoadingProgress = 50;

			scimFactory.getUser(user.id).then(function(response) {

				user.userInfo = response.data;
				console.log("Added indigoUserInfo: ", user.userInfo);

				$rootScope.pageLoadingProgress = 100;
				user.loadingModal.dismiss("Cancel");

			}, function(error) {

				$rootScope.pageLoadingProgress = 100;
				console.error("getUser", error)
				user.loadingModal.dismiss("Error");
				$scope.operationResult = Utils.buildErrorOperationResult(error);
			});

		});

	}

	function doPasswordReset() {
		
		ResetPasswordService.forgotPassword(user.userInfo.emails[0].value).then(
			function(response) {
				ModalService.showModal({}, {
					closeButtonText: null,
					user: user.userInfo.name.formatted,
					actionButtonText: 'OK',
					headerText: 'Password reset requested',
					bodyText: `A password reset link has just been sent to your e-mail address`
				});
			}, function(error) {
				$scope.operationResult = Utils.buildErrorOperationResult(error);
			});
	}

	function sendResetMail() {
		
		var modalOptions = {
				closeButtonText: 'Cancel',
				actionButtonText: 'Send password reset e-mail',
				headerText: 'Send password reset e-mail',
				bodyText: `Are you sure you want to send the password reset e-mail to ${user.userInfo.name.formatted}?`	
			};
				
			ModalService.showModal({}, modalOptions).then(
				function (){
					user.doPasswordReset();
				});
	}

	function openEditUserDialog() {

		var modalInstance = $uibModal
				.open({
					templateUrl : '/resources/iam/template/dashboard/user/edituser.html',
					controller : 'EditUserController',
					controllerAs : 'editUserCtrl',
					resolve : {
						user : function() {
							console.log(user.userInfo);
							return user.userInfo;
						}
					}
				});
		modalInstance.result.then(function() {
			getIndigoUserInfo();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's info updated successfully");
		}, function() {
			console.info('Modal dismissed at: ', new Date());
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
							return user.userInfo;
						}
					}
				});
		modalInstance.result.then(function() {
			console.info("Added group");
			getIndigoUserInfo();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's memberships updated successfully");
		}, function() {
			console.info('Modal dismissed at: ', new Date());
		});
	}

	function openAddOIDCAccountDialog() {
		var modalInstance = $uibModal.open({
			templateUrl : '/resources/iam/template/dashboard/user/addoidc.html',
			controller : 'AddOIDCAccountController',
			controllerAs : 'addOidcCtrl',
			resolve : {
				user : function() {
					return user.userInfo;
				}
			}
		});
		modalInstance.result.then(function() {
			console.info("Added oidc account");
			getIndigoUserInfo();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's Open ID Account created successfully");
		}, function() {
			console.info('Modal dismissed at: ', new Date());
		});
	}

	function openAddSshKeyDialog() {
		var modalInstance = $uibModal.open({
			templateUrl : '/resources/iam/template/dashboard/user/addsshkey.html',
			controller : 'AddSshKeyController',
			controllerAs : 'addSshKeyCtrl',
			resolve : {
				user : function() {
					return user.userInfo;
				}
			}
		});
		modalInstance.result.then(function() {
			console.info("Added ssh key");
			getIndigoUserInfo();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's SSH Key added successfully");
		}, function(error) {
			console.info('Modal dismissed at: ', new Date());
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
							return user.userInfo;
						}
					}
				});
		modalInstance.result.then(function() {
			console.info("Added saml account");
			getIndigoUserInfo();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's SAML Account created successfully");
		}, function() {
			console.info('Modal dismissed at: ', new Date());
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
							return user.userInfo;
						}
					}
				});
		modalInstance.result.then(function() {
			console.info("Added x509 certificate");
			getIndigoUserInfo();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's x509 Certificate added successfully");
		}, function() {
			console.info('Modal dismissed at: ', new Date());
		});
	}

	function deleteGroup(group) {
		
		var modalOptions = {
			closeButtonText: 'Cancel',
			actionButtonText: 'Remove user from group',
			headerText: 'Remove ' + user.userInfo.name.formatted + ' from ' + group.display,
			bodyText: `Are you sure you want to remove «${user.userInfo.name.formatted}» from «${group.display}»?`	
		};
			
		ModalService.showModal({}, modalOptions).then(
			function (){
				scimFactory.removeUserFromGroup(group.value, user.userInfo.id,
						user.userInfo.meta.location, user.userInfo.name.formatted)
					.then(function(response) {
						console.log("Deleted: ", group);
						getIndigoUserInfo();
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
					scimFactory.removeOpenIDAccount(user.userInfo.id, oidcId.issuer,
							oidcId.subject)
						.then(function(response) {
							console.log("Removed: ", oidcId.issuer, oidcId.subject);
							getIndigoUserInfo();
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
					scimFactory.removeSshKey(user.userInfo.id, sshKey.fingerprint)
						.then(function(response) {
							console.log("Removed: ", sshKey.display, sshKey.fingerprint);
							getIndigoUserInfo();
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
					scimFactory.removeX509Certificate(user.userInfo.id, x509cert.value)
						.then(function(response) {
							console.log("Removed: ", x509cert.display);
							getIndigoUserInfo();
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
					scimFactory.removeSamlId(user.userInfo.id, samlId)
						.then(function(response) {
							console.log("Removed: ", samlId.idpId, samlId.userId);
							getIndigoUserInfo();
							$scope.operationResult = Utils.buildSuccessOperationResult("SAML Account has been removed successfully");
						}, function(error) {
							$scope.operationResult = Utils.buildErrorOperationResult(error);
						});
				});
	}

	function setActive(status) {

		var modalOptions = {};
		
		if (status) {
			
			modalOptions = {
				closeButtonText: 'Cancel',
				actionButtonText: 'Enable user',
				headerText: 'Enable ' + user.userInfo.name.formatted,
				bodyText: `Are you sure you want to enable '${user.userInfo.name.formatted}'?`	
			};
		} else {
			
			modalOptions = {
				closeButtonText: 'Cancel',
				actionButtonText: 'Disable user',
				headerText: 'Disable ' + user.userInfo.name.formatted,
				bodyText: `Are you sure you want to disable '${user.userInfo.name.formatted}'?`	
			};
		}
		
		ModalService.showModal({}, modalOptions).then(
			function (){
				scimFactory.setUserActiveStatus(user.userInfo.id, status)
					.then(function(response) {
						getIndigoUserInfo();
						if (status) {
							$scope.operationResult = Utils.buildSuccessOperationResult("User " + user.userInfo.name.formatted + " enabled");
						} else {
							$scope.operationResult = Utils.buildSuccessOperationResult("User " + user.userInfo.name.formatted + " disabled");
						}
					}, function(error) {
						$scope.operationResult = Utils.buildErrorOperationResult(error);
					});
			});
	}
}
