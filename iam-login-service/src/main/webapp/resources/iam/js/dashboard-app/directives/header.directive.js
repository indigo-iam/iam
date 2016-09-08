angular.module('dashboardApp').directive('header', function() {
	return {
		restrict : 'E',
		templateUrl : '/resources/iam/template/dashboard/header.html',
		compile : function(tElement, tAttrs, transclude) {
			$.AdminLTE.pushMenu($(tElement).find('.sidebar-toggle'));
		}
	};
});