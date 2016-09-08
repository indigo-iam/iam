'use strict';

angular.module('dashboardApp').controller('AddUserGroupController',
		AddUserGroupController);

AddUserGroupController.$inject = [ '$scope', '$state', '$q',
		'$uibModalInstance', '$sanitize', 'scimFactory', 'user', 'oGroups' ];

function AddUserGroupController($scope, $state, $q, $uibModalInstance,
		$sanitize, scimFactory, user, oGroups) {

	var addGroupCtrl = this;

	// methods
	addGroupCtrl.cancel = cancel;
	addGroupCtrl.lookupGroups = lookupGroups;
	addGroupCtrl.addGroup = addGroup;

	// params
	addGroupCtrl.user = user;
	console.log(addGroupCtrl.user);

	// fields
	addGroupCtrl.groupsSelected = null;
	addGroupCtrl.oGroups = oGroups;
	addGroupCtrl.disabled = false;

	$scope.oGroups = oGroups;
	$scope.selected = {}

	function lookupGroups() {

		return addGroupCtrl.oGroups;
	}

	function cancel() {

		$uibModalInstance.close();
	}

	function addGroup() {

		console.log(addGroupCtrl.groupsSelected);
		console.log(addGroupCtrl.user);
		var requests = [];
		angular.forEach(addGroupCtrl.groupsSelected, function(groupToAdd) {
			requests.push(scimFactory.addUserToGroup(groupToAdd.id,
					addGroupCtrl.user.id));
		});

		$q.all(requests).then(function(response) {
			console.log("Added ", addGroupCtrl.groupsSelected);
			addGroupCtrl.cancel();
		}, function(error) {
			console.error(error);
			addGroupCtrl.cancel();
			$state.go("error", {
				"error" : error
			});
		});
	}
	;

}