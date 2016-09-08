'use strict';

angular.module('dashboardApp').controller('GroupsController', GroupsController);

GroupsController.$inject = [ '$scope', '$location', '$uibModal', '$state',
		'$filter', 'filterFilter', 'scimFactory' ];

function GroupsController($scope, $location, $uibModal, $state, $filter,
		filterFilter, scimFactory) {

	var gc = this;

	// group data
	gc.groups = [];

	// create empty search model (object) to trigger $watch on update
	gc.search = {};

	// pagination controls
	gc.currentPage = 1;
	gc.totalItems = gc.groups.length;
	gc.entryLimit = 10; // items per page

	// functions
	gc.getAllGroups = getAllGroups;
	gc.getGroups = getGroups;
	gc.resetFilters = resetFilters;
	gc.updateNoOfPages = updateNoOfPages;
	gc.updateTotalItems = updateTotalItems;

	// add group
	gc.clickToOpen = clickToOpen;

	// delete group
	gc.deleteGroup = deleteGroup;
	gc.removeGroupFromList = removeGroupFromList;

	// Controller actions:
	gc.resetFilters()
	gc.getAllGroups(); // eval gc.groups

	function updateTotalItems() {

		gc.totalItems = gc.groups.length;
	}

	function updateNoOfPages() {

		gc.noOfPages = Math.ceil(gc.totalItems / gc.entryLimit);
	}

	function resetFilters() {
		// needs to be a function or it won't trigger a $watch
		gc.search = {};
	}
	;

	// $watch search to update pagination
	$scope.$watch('gc.search', function(newVal, oldVal) {
		gc.filtered = filterFilter(gc.groups, newVal);
		gc.updateTotalItems();
		gc.updateNoOfPages();
		gc.currentPage = 1;
	}, true);

	function getAllGroups() {

		gc.groups = [];
		gc.getGroups(1, gc.entryLimit);
	}

	function getGroups(startIndex, count) {

		scimFactory
				.getGroups(startIndex, count)
				.then(
						function(response) {
							angular.forEach(response.data.Resources, function(
									group) {
								gc.groups.push(group);
							});
							gc.groups = $filter('orderBy')(gc.groups,
									"displayName", false);
							gc.updateTotalItems();
							gc.updateNoOfPages();
							if (response.data.totalResults > (response.data.startIndex + response.data.itemsPerPage)) {
								gc.getGroups(startIndex + count, count);
							}
						}, function(error) {
							$state.go("error", {
								"error" : error
							});
						});
	}

	function clickToOpen() {
		var modalInstance = $uibModal.open({
			templateUrl : '/resources/iam/template/dashboard/groups/newgroup.html',
			controller : 'AddGroupController'
		});
		modalInstance.result.then(function(createdGroup) {
			console.info(createdGroup);
			gc.groups.push(createdGroup);
			gc.groups = $filter('orderBy')(gc.groups, "displayName", false);
			gc.updateTotalItems();
			gc.updateNoOfPages();
		}, function() {
			console.info('Modal dismissed at: ', new Date());
		});
	}
	;

	function removeGroupFromList(group) {

		var i = gc.groups.indexOf(group);
		gc.groups.splice(i, 1);

		gc.filtered = filterFilter(gc.groups, gc.search);
		gc.updateTotalItems();
		gc.updateNoOfPages();
	}

	function deleteGroup(group) {
		scimFactory.deleteGroup(group.id).then(function(response) {
			gc.removeGroupFromList(group);
		}, function(errorResponse) {
			alert('Error deleting group: ', errorResponse.data.detail);
			console.error('Error deleting group: ', errorResponse.data.detail);
		});
	}
	;
}