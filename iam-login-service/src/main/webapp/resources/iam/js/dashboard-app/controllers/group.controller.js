'use strict';

angular.module('dashboardApp').controller('GroupController', GroupController);

GroupController.$inject = [ '$rootScope', '$state', '$filter', 'scimFactory', '$uibModal', 'ModalService', 'Utils' ];

function GroupController($rootScope, $state, $filter, scimFactory, $uibModal, ModalService, Utils) {

	var group = this;

	group.loadGroup = loadGroup;

	group.id = $state.params.id;
	group.data = [];

	group.loadGroup();

	function loadGroup() {

		$rootScope.pageLoadingProgress = 30;
		group.loadingModal = $uibModal
		.open({
			animation: false,
			templateUrl : '/resources/iam/template/dashboard/loading-modal.html'
		});

		group.loadingModal.opened.then(function() {
			scimFactory.getGroup(group.id).then(
					function(response) {

						group.data = response.data;
						group.data.members = $filter('orderBy')(group.data.members, "display", false);
						$rootScope.pageLoadingProgress = 100;
						group.loadingModal.dismiss("Dismiss");

					}, function(error) {

						$rootScope.pageLoadingProgress = 100;
						$scope.operationResult = Utils.buildErrorOperationResult(error);
						group.loadingModal.dismiss("Dismiss");

					});
		});
	}

	group.removeMemberFromList = removeMemberFromList;

	function removeMemberFromList(user) {

		var i = group.data.members.indexOf(user);
		group.data.members.splice(i, 1);
	}

	group.deleteMember = deleteMember;

	function deleteMember(user) {

		var modalOptions = {
				closeButtonText: 'Cancel',
				actionButtonText: 'Remove membership',
				headerText: 'Remove «' + user.display + "» from «" + group.data.displayName + "»",
				bodyText: `Are you sure you want to remove '${user.display}' from '${group.data.displayName}'?`	
			};
				
			ModalService.showModal({}, modalOptions).then(
				function (){
					scimFactory.removeUserFromGroup(group.id, user.value, user.$ref,
							user.display)
						.then(function(response) {
							console.log("Deleted: ", user.display);
							group.removeMemberFromList(user);
							$scope.operationResult = Utils.buildSuccessOperationResult("User " + user.display + " membership has been removed successfully");
						}, function(error) {
							$scope.operationResult = Utils.buildErrorOperationResult(error);
						});
				});
	}
}