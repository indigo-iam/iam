'use strict';

angular.module('dashboardApp').controller('EditGroupController', EditGroupController);

EditGroupController.$inject = ['$scope', '$uibModalInstance', 'Utils', 'scimFactory', '$location', 'group'];

function EditGroupController($scope, $uibModalInstance, Utils, scimFactory, $location, group) {

	$scope.groupToEdit = group;
	alert(group.displayName);
	
	$scope.groupId = group.id;
	$scope.group = {
			displayName: group.displayName,
			schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"]
	};
	$scope.saveGroup = saveGroup;

	function saveGroup() {
		
		$scope.patchOp = {
			
			schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
			operations: [{
				op: "replace",
				path: $scope.groupToEdit.meta.location,
				
			}]
		}
		
		console.info("Saving: ", $scope.group);
		
		
		
		scimFactory
			.patchGroup($scope.groupId, $scope.group)
				.then(
					function(response) {
						$uibModalInstance.close(response.data);
					},
					function(error) {
						console.error('Error creating group: ', error);
					}
				);
	};
	
	function cancel() {
		$uibModalInstance.dismiss("cancel");
	}
}