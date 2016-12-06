'use strict';

angular.module('dashboardApp').controller('UserController', UserController);

UserController.$inject = [ '$scope', '$rootScope', '$state', '$uibModal', '$filter', '$q', 
                           'filterFilter', 'Utils', 'scimFactory', 'ModalService', 
						   'ResetPasswordService', 'RegistrationRequestService', 'UserService'];

function UserController($scope, $rootScope, $state, $uibModal, $filter, $q, filterFilter, 
		Utils, scimFactory, ModalService, ResetPasswordService, RegistrationRequestService,
		UserService, user) {

	var vm = this;
	vm.id = $state.params.id;

	vm.user = user;
	
	// methods
	vm.loadUserInfo = loadUserInfo;
	vm.showSshKeyValue = showSshKeyValue;
	vm.showCertValue = showCertValue;
	vm.openAddGroupDialog = openAddGroupDialog;
	vm.openAddOIDCAccountDialog = openAddOIDCAccountDialog;
	vm.openAddSshKeyDialog = openAddSshKeyDialog;
	vm.openAddSamlAccountDialog = openAddSamlAccountDialog;
	vm.openAddX509CertificateDialog = openAddX509CertificateDialog;
	vm.openEditUserDialog = openEditUserDialog;
	vm.deleteGroup = deleteGroup;
	vm.deleteOidcAccount = deleteOidcAccount;
	vm.deleteSshKey = deleteSshKey;
	vm.deleteX509Certificate = deleteX509Certificate;
	vm.deleteSamlId = deleteSamlId;
	vm.setActive = setActive;
	vm.openLoadingModal = openLoadingModal;
	vm.closeLoadingModal = closeLoadingModal;
	vm.closeLoadingModalAndSetError = closeLoadingModalAndSetError;
	
	vm.isVoAdmin = isVoAdmin;
	vm.openAssignVoAdminPrivilegesDialog = openAssignVoAdminPrivilegesDialog;
	vm.openRevokeVoAdminPrivilegesDialog = openRevokeVoAdminPrivilegesDialog;
	vm.isMe = isMe;

	vm.isEditUserDisabled = false;
	vm.isSendResetDisabled = false;
	vm.isEnableUserDisabled = false;
	
	// password reset
	vm.doPasswordReset = doPasswordReset;
		
	function getUser() {
		UserService.getUser(vm.id).then(function(user){
			vm.user = user;
		}).catch(function(error){
			$scope.operationResult = Utils.buildErrorResult(error.message || error);
		});
	}
	
	function openLoadingModal() {
		$rootScope.pageLoadingProgress = 0;
		vm.loadingModal = $uibModal.open({
			animation: false,
			templateUrl : '/resources/iam/template/dashboard/loading-modal.html'
		});

		return vm.loadingModal.opened;
	}
	
	function closeLoadingModal(){
		$rootScope.pageLoadingProgress = 100;
		vm.loadingModal.dismiss("Cancel");
	}
	
	function closeLoadingModalAndSetError(error){
		$rootScope.pageLoadingProgress = 100;
		vm.loadingModal.dismiss("Error");
		$scope.operationResult = Utils.buildErrorOperationResult(error);
	}
	
	function doPasswordReset() {
		
		ResetPasswordService.forgotPassword($scope.vm.emails[0].value).then(
			function(response) {
				ModalService.showModal({}, {
					closeButtonText: null,
					user: $scope.user.name.formatted,
					actionButtonText: 'OK',
					headerText: 'Password reset requested for user',
					bodyText: `A password reset link has just been sent to your e-mail address`
				});
			}, function(error) {
				$scope.operationResult = Utils.buildErrorOperationResult(error);
			});
	}

	function sendResetMail() {

		vm.isSendResetDisabled = true;
		var modalOptions = {
				closeButtonText: 'Cancel',
				actionButtonText: 'Send password reset e-mail',
				headerText: 'Send password reset e-mail',
				bodyText: `Are you sure you want to send the password reset e-mail to ${$scope.vm.name.formatted}?`	
			};
				
		ModalService.showModal({}, modalOptions).then(
			function (){
				vm.doPasswordReset();
				vm.isSendResetDisabled = false;
			}, function () {
				vm.isSendResetDisabled = false;
			});
	}

	function openEditUserDialog() {

		vm.isEditUserDisabled = true;

		var modalInstance = $uibModal
				.open({
					templateUrl : '/resources/iam/template/dashboard/user/editvm.html',
					controller : 'EditUserController',
					controllerAs : 'editUserCtrl',
					resolve : {
						user : function() {
							return $scope.user;
						}
					}
				});
		
		modalInstance.result.then(function() {
			loadUserInfo();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's info updated successfully");
			vm.isEditUserDisabled = false;
		}, function() {
			console.log('Modal dismissed at: ', new Date());
			vm.isEditUserDisabled = false;
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
			loadUserInfo();
			$scope.operationResult = Utils.buildSuccessOperationResult("User's groups updated successfully");
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

			loadUserInfo();
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

			loadUserInfo();
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

			loadUserInfo();
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

			loadUserInfo();
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

						console.log("Removed group: ", group);
						loadUserInfo();
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
							loadUserInfo();
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
							loadUserInfo();
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

							loadUserInfo();
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
							loadUserInfo();
							$scope.operationResult = Utils.buildSuccessOperationResult("SAML Account has been removed successfully");

						}, function(error) {
							$scope.operationResult = Utils.buildErrorOperationResult(error);
						});
				});
	}

	function setActive(status) {

		vm.isEnableUserDisabled = true;
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

						loadUserInfo();
						
						if (status) {
							$scope.operationResult = Utils.buildSuccessOperationResult("User " + $scope.user.name.formatted + " enabled");
						} else {
							$scope.operationResult = Utils.buildSuccessOperationResult("User " + $scope.user.name.formatted + " disabled");
						}
						vm.isEnableUserDisabled = false;
					}, function(error) {
						$scope.operationResult = Utils.buildErrorOperationResult(error);
						vm.isEnableUserDisabled = false;
					});
			}, function () {
				vm.isEnableUserDisabled = false;
			});
	}
	
	function openRevokeVoAdminPrivilegesDialog() {
		var modalInstance = $uibModal
		.open({
			templateUrl : '/resources/iam/template/dashboard/user/revoke-vo-admin-privileges.html',
			controller : 'AccountPrivilegesController',
			controllerAs : 'ctrl',
			resolve : {
				user : function() {
					return user;
				}
			}
		});
		
		modalInstance.result.then(function() {
			loadUserInfo();
			$scope.operationResult = Utils.buildSuccessOperationResult("Vo admin privileges revoked succesfully");
		}, function() {
			console.info('Modal dismissed at: ', new Date());
		});
	}
	
	function openAssignVoAdminPrivilegesDialog() {
		var modalInstance = $uibModal
		.open({
			templateUrl : '/resources/iam/template/dashboard/user/assign-vo-admin-privileges.html',
			controller : 'AccountPrivilegesController',
			controllerAs : 'ctrl',
			resolve : {
				user : function() {
					return user;
				}
			}
		});
		
		modalInstance.result.then(function() {
			loadUserInfo();
			$scope.operationResult = Utils.buildSuccessOperationResult("Vo admin privileges assigned succesfully");
		}, function() {
			console.info('Modal dismissed at: ', new Date());
		});
	}
	
	function isMe(){
		var authenticatedUserSub = getUserInfo().sub; 
		return vm.id == authenticatedUserSub;
	}
	
	
	
	function isVoAdmin() {
		if (vm.authorities){
			if (vm.authorities.indexOf("ROLE_ADMIN") > -1){
				return true;
			}
		}
		
		return false;
	}
}
