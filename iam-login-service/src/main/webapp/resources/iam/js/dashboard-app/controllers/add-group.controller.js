'use strict';

angular.module('dashboardApp').controller('AddGroupController',
		AddGroupController);

AddGroupController.$inject = [ '$scope', '$rootScope', '$uibModalInstance', 'Utils',
		'scimFactory' ];

function AddGroupController($scope, $rootScope, $uibModalInstance, Utils, scimFactory) {
	
	var addGroupCtrl = this;

	addGroupCtrl.group = {};
	addGroupCtrl.addGroup = addGroup;
	addGroupCtrl.resetGroup = resetGroup;
	addGroupCtrl.cancel = cancel;

	function resetGroup() {

		addGroupCtrl.group.displayName = "";
		addGroupCtrl.enabled = true;

	}

	addGroupCtrl.resetGroup();

	function addGroup() {

		addGroupCtrl.enabled = false;

		addGroupCtrl.group.schemas = [];
		addGroupCtrl.group.schemas[0] = "urn:ietf:params:scim:schemas:core:2.0:Group";

		console.info(addGroupCtrl.group);

		scimFactory.createGroup(addGroupCtrl.group).then(function(response) {
			$rootScope.loggedUser.totGroups = $rootScope.loggedUser.totGroups + 1;
			$uibModalInstance.close(response.data);
			addGroupCtrl.enabled = true;
		}, function(error) {
			console.error('Error creating group', error);
			$scope.operationResult = Utils.buildErrorOperationResult(error);
			addGroupCtrl.enabled = true;
		});
	}

	function cancel() {
		$uibModalInstance.dismiss("cancel");
	}
}