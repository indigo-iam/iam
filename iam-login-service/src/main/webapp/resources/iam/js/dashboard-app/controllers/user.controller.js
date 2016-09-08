'use strict';

angular.module('dashboardApp').controller('UserController', UserController);

UserController.$inject = [ '$state', '$uibModal', '$filter', 'Utils', 'scimFactory' ];

function UserController($state, $uibModal, $filter, Utils, scimFactory) {

	var user = this;

	console.log("User ID: ", $state.params.id);

	user.id = $state.params.id;

//	if (!Utils.isMeOrAdmin(user.id)) {
//		$state.go("unauthorized");
//		return;
//	}
	
	user.groups = [];
	user.oGroups = [];

	user.userInfo = {};

	// methods
	user.getIndigoUserInfo = getIndigoUserInfo;
	user.getAllGroups = getAllGroups;
	user.getNotMemberGroups = getNotMemberGroups;
	user.showSshKeyValue = showSshKeyValue;
	user.showCertValue = showCertValue;
	user.openAddGroupDialog = openAddGroupDialog;
	user.openAddOIDCAccountDialog = openAddOIDCAccountDialog;
	user.openAddSshKeyDialog = openAddSshKeyDialog;
	user.openAddSamlAccountDialog = openAddSamlAccountDialog;
	user.openAddX509CertificateDialog = openAddX509CertificateDialog;
	user.deleteGroup = deleteGroup;
	user.deleteOidcAccount = deleteOidcAccount;
	user.deleteSshKey = deleteSshKey;
	user.deleteX509Certificate = deleteX509Certificate;
	user.deleteSamlId = deleteSamlId;
	user.setActive = setActive;

	getIndigoUserInfo();
	getAllGroups(1, 10);

	function getIndigoUserInfo() {
		scimFactory.getUser(user.id).then(function(response) {
			user.userInfo = response.data;
			console.log("Added indigoUserInfo: ", user.userInfo);
		}, function(error) {
			$state.go("error", {
				"error": error
			});
		});
	}

	function getAllGroups(startIndex, count) {

		scimFactory
				.getGroups(startIndex, count)
				.then(
						function(response) {

							angular.forEach(response.data.Resources, function(
									group) {
								user.groups.push(group);
							});
							user.groups = $filter('orderBy')(user.groups,
									"displayName", false);

							if (response.data.totalResults > (response.data.startIndex + response.data.itemsPerPage)) {
								user.getAllGroups(startIndex + count, count);
							} else {
								user.oGroups = getNotMemberGroups();
							}
						}, function(error) {
							$state.go("error", {
								"error": error
							});
						});
	}

	function getNotMemberGroups() {

		return user.groups.filter(function(group) {
			for ( var i in user.userInfo.groups) {
				if (group.id === user.userInfo.groups[i].value) {
					return false;
				}
			}
			return true;
		});
	}

	function openAddGroupDialog() {
		user.oGroups = getNotMemberGroups();
		var modalInstance = $uibModal
				.open({
					templateUrl : '/resources/iam/template/dashboard/user/addusergroup.html',
					controller : 'AddUserGroupController',
					controllerAs : 'addGroupCtrl',
					resolve : {
						user : function() {
							return user.userInfo;
						},
						oGroups : function() {
							return user.oGroups;
						}
					}
				});
		modalInstance.result.then(function() {
			console.info("Added group");
			getIndigoUserInfo();
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
		}, function() {
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
		}, function() {
			console.info('Modal dismissed at: ', new Date());
		});
	}

	function deleteGroup(group) {

		scimFactory.removeUserFromGroup(group.value, user.userInfo.id,
				user.userInfo.meta.location, user.userInfo.name.formatted)
				.then(function(response) {
					console.log("Deleted: ", group);
					getIndigoUserInfo();
				}, function(error) {
					$state.go("error", {
						"error": error
					});
				});
	}

	function showSshKeyValue(value) {
		alert(value);
	}

	function showCertValue(cert) {
		alert(cert.value);
	}

	function deleteOidcAccount(oidcId) {

		scimFactory.removeOpenIDAccount(user.userInfo.id, oidcId.issuer,
				oidcId.subject).then(function(response) {
			console.log("Removed: ", oidcId.issuer, oidcId.subject);
			getIndigoUserInfo();
		}, function(error) {
			$state.go("error", {
				"error": error
			});
		});
	}

	function deleteSshKey(sshKey) {

		scimFactory.removeSshKey(user.userInfo.id, sshKey.fingerprint).then(
				function(response) {
					console
							.log("Removed: ", sshKey.display,
									sshKey.fingerprint);
					getIndigoUserInfo();
				}, function(error) {
					$state.go("error", {
						"error": error
					});
				});
	}

	function deleteX509Certificate(x509cert) {

		scimFactory.removeX509Certificate(user.userInfo.id, x509cert.value)
				.then(function(response) {
					console.log("Removed: ", x509cert.display);
					getIndigoUserInfo();
				}, function(error) {
					$state.go("error", {
						"error": error
					});
				});
	}

	function deleteSamlId(samlId) {

		scimFactory.removeSamlId(user.userInfo.id, samlId).then(
				function(response) {
					console.log("Removed: ", samlId.idpId, samlId.userId);
					getIndigoUserInfo();
				}, function(error) {
					$state.go("error", {
						"error": error
					});
				});
	}

	function setActive(status) {

		scimFactory.setUserActiveStatus(user.userInfo.id, status).then(
				function(response) {
					console.log("Set active as: ", status);
					getIndigoUserInfo();
				}, function(error) {
					$state.go("error", {
						"error": error
					});
				});
	}
}