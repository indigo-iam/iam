angular.module('dashboardApp').directive('sidebar', function() {
	return {
		restrict : 'C',
		compile : function(tElement, tAttrs, transclude) {
			// Enable sidebar tree view controls
			$.AdminLTE.tree(tElement);
		}
	};
});