'use strict';

angular.module('dashboardApp').controller('AddUserGroupController',
		AddUserGroupController);

AddUserGroupController.$inject = [ '$scope', '$state', '$filter', 'Utils', '$q',
		'$uibModalInstance', '$sanitize', 'scimFactory', 'user' ];

function AddUserGroupController($scope, $state, $filter, Utils, $q, $uibModalInstance,
		$sanitize, scimFactory, user) {

	var addGroupCtrl = this;

	// methods
	addGroupCtrl.cancel = cancel;
	addGroupCtrl.lookupGroups = lookupGroups;
	addGroupCtrl.addGroup = addGroup;
	addGroupCtrl.getAllGroups = getAllGroups;
	addGroupCtrl.getNotMemberGroups = getNotMemberGroups;
	addGroupCtrl.loadGroups = loadGroups;

	// params
	addGroupCtrl.user = user;

	// fields
	addGroupCtrl.groupsSelected = null;
	addGroupCtrl.groups = [];
	addGroupCtrl.oGroups = [];
	addGroupCtrl.enabled = true;

	addGroupCtrl.loadGroups();

	function lookupGroups() {

		return addGroupCtrl.oGroups;
	}

	function loadGroups() {

		addGroupCtrl.loadingGroupsProgress = 30;
		addGroupCtrl.getAllGroups(1, 10);
	}

	function cancel() {

		$uibModalInstance.dismiss('Cancel');
	}

	function addGroup() {

		addGroupCtrl.enabled = false;
		var requests = [];
		angular.forEach(addGroupCtrl.groupsSelected, function(groupToAdd) {
			requests.push(scimFactory.addUserToGroup(groupToAdd.id,
					addGroupCtrl.user));
		});

		$q.all(requests).then(function(response) {
			console.log("Added ", addGroupCtrl.groupsSelected);
			$uibModalInstance.close(response);
			addGroupCtrl.enabled = true;
		}, function(error) {
			console.error(error);
			$scope.operationResult = Utils.buildErrorOperationResult(error);
			addGroupCtrl.enabled = true;
		});
	}
	
	function getAllGroups(startIndex, count) {

		scimFactory
			.getGroups(startIndex, count)
				.then(function(response) {

					angular.forEach(response.data.Resources, function(group) {
						addGroupCtrl.groups.push(group);
					});
					addGroupCtrl.groups = $filter('orderBy')(addGroupCtrl.groups, "displayName", false);

					if (response.data.totalResults > (response.data.startIndex + response.data.itemsPerPage)) {

						addGroupCtrl.loadingGroupsProgress = Math.floor((startIndex + count) * 100 / response.data.totalResults);
						addGroupCtrl.getAllGroups(startIndex + count, count);

					} else {

						addGroupCtrl.loadingGroupsProgress = 100;
						addGroupCtrl.oGroups = addGroupCtrl.getNotMemberGroups();
					}
				}, function(error) {

					console.error(error);
					$scope.operationResult = Utils.buildErrorOperationResult(error);
				});
	}

	function getNotMemberGroups() {
	
		return addGroupCtrl.groups.filter(function(group) {
			for ( var i in addGroupCtrl.user.groups) {
				if (group.id === addGroupCtrl.user.groups[i].value) {
					return false;
				}
			}
			return true;
		});
	}

}