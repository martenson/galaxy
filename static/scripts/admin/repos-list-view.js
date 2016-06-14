define(["libs/toastr","admin/repos-row-view","admin/repos-model","mvc/ui/ui-select","utils/utils"],function(a,b,c,d,e){var f=Backbone.View.extend({el:"#center",rowViews:{},defaults:{view:"all",section_filter:null,sort_by:"date",sort_order:"asc"},events:{"click #select-all-checkboxes":"selectAll","click th > a":"sortClicked"},list_sections:[],initialize:function(a){this.options=_.defaults(this.options||{},a,this.defaults),this.collection=new c.Repos,this.listenTo(this.collection,"sync",this.renderAll),this.collection.switchComparator(this.options.sort_by),this.render(),this.fetchRepos(),this.adjustMenu()},render:function(a){this.options=_.extend(this.options,a);var b=this.templateRepoList();return this.$el.html(b({section_filter:this.options.section_filter})),this.fetchSections(),$("#center").css("overflow","auto"),this.$el.find("[data-toggle]").tooltip(),this},fetchRepos:function(){this.collection.fetch({success:function(){},error:function(){}})},repaint:function(a){return this.options=_.extend(this.options,a),this.removeAllRows(),this.clearFilter(),this.adjustMenu(),this.renderAll(),this},adjustMenu:function(a){this.options=_.extend(this.options,a),this.$el.find("li").removeClass("active"),$(".tab_"+this.options.view).addClass("active"),"uninstalled"===this.options.view?$("#admin_section_select").hide():$("#admin_section_select").show()},renderAll:function(a){this.options=_.extend(this.options,a),this.collection.switchComparator(this.options.sort_by),this.collection.sort();var b="desc"===this.options.sort_order?this.collection.models.reverse():this.collection.models,c=this;_.each(b,function(a){c.renderOne(a)})},renderOne:function(a){var c=null,d=!1,e="uninstalled"===a.get("status").toLowerCase()||"deactivated"===a.get("status").toLowerCase(),f="undefined"!=typeof a.get("sections")&&a.get("sections").indexOf(this.options.section_filter)>=0;d="uninstalled"===this.options.view&&e,d=d||("all"===this.options.view||this.options.view===a.get("type"))&&!e,d=d&&(!this.options.section_filter||f),d&&(this.rowViews[a.get("id")]?(c=this.rowViews[a.get("id")].render(),this.$el.find("[data-toggle]").tooltip()):(c=new b.AdminReposRowView({repo:a}),this.rowViews[a.get("id")]=c,this.$el.find("[data-toggle]").tooltip()),this.$el.find("#repos_list_body").append(c.el))},removeOne:function(){},removeAllRows:function(){var a=this;this.$el.find(".repo-row").each(function(){var b=$(this).data("id");a.rowViews[b].remove()})},selectAll:function(a){var b=a.target.checked;that=this,$(":checkbox","#repos_list_body").each(function(){this.checked=b,view_id=$(this.parentElement.parentElement).data("id"),b?that.rowViews[view_id].turnDark():that.rowViews[view_id].turnLight()})},sortClicked:function(a){a.preventDefault(),this.adjustHeading(a),this.removeAllRows(),this.renderAll()},adjustHeading:function(a){var b=$(a.target).attr("class").split("-")[2];b===this.options.sort_by&&(this.options.sort_order="asc"===this.options.sort_order?"desc":"asc"),this.options.sort_by=b,console.log(this.options.sort_by),this.$el.find('span[class^="sort-icon"]').hide().removeClass("fa-sort-asc").removeClass("fa-sort-desc"),this.$el.find(".sort-icon-"+b).addClass("fa-sort-"+this.options.sort_order).show()},fetchSections:function(){var a=this;e.get({url:Galaxy.root+"api/toolpanel",success:function(b){a.list_sections=[],a.list_sections.push({id:"",text:""});for(key in b)a.list_sections.push({id:b[key].id,text:b[key].name});a._renderSelectBox()},cache:!0})},_renderSelectBox:function(){var a=this;this.select_section=new d.View({css:"admin-section-select",data:a.list_sections,container:a.$el.find("#admin_section_select"),placeholder:"Section Filter",allowClear:!0}),this.$el.find("#admin_section_select").on("select2-selecting",function(b){Galaxy.adminapp.admin_router.navigate("repos/v/"+a.options.view+"/f/"+b.val,{trigger:!0})}).on("select2-removed",function(){Galaxy.adminapp.admin_router.navigate("repos/v/"+a.options.view,{trigger:!0})})},clearFilter:function(){this.select_section&&this.select_section.clear()},templateRepoList:function(){return _.template(['<div class="repos_container">','<div class="repos_toolbar">',"<span><strong>REPOSITORIES</strong></span>",'<button data-toggle="tooltip" data-placement="top" title="Uninstall selected repositories" class="btn btn-default primary-button toolbar-item" type="button">',"Uninstall","</button>",'<button data-toggle="tooltip" data-placement="top" title="Update selected repositories" class="btn btn-default primary-button toolbar-item" type="button">',"Update","</button>",'<span id="admin_section_select" class="admin-section-select toolbar-item" />','<ul class="nav nav-tabs repos-nav">','<li role="presentation" class="tab_all">','<a href="#repos/v/all">All</a>',"</li>",'<li role="presentation" class="tab_tools"><a href="#repos/v/tools">With Tools</a></li>','<li role="presentation" class="tab_packages"><a href="#repos/v/packages">Packages</a></li>','<li role="presentation" class="tab_uninstalled"><a href="#repos/v/uninstalled">Uninstalled or Deactivated</a></li>',"</ul>","</div>",'<div id="repositories_list">','<div class="repos_container table-responsive">','<table class="grid table table-condensed">',"<thead>",'<th style="text-align: center; width: 20px; " title="Check to select all repositories">','<input id="select-all-checkboxes" style="margin: 0;" type="checkbox">',"</th>","<th>",'<a class="sort-repos-name" data-toggle="tooltip" data-placement="top" title="sort alphabetically" href="#">',"Name","</a>",'<span class="sort-icon-name fa fa-sort-asc" style="display: none;"/>',"</th>",'<th style="width:10%;">','<a class="sort-repos-owner" data-toggle="tooltip" data-placement="top" title="sort alphabetically" href="#">',"Owner","</a>",'<span class="sort-icon-owner fa fa-sort-asc" style="display: none;"/>',"</th>",'<th class="centercell" style="width:10%;">','<a class="sort-repos-installation" data-toggle="tooltip" data-placement="top" title="sort by installation state" href="#">',"Installation","</a>",'<span class="sort-icon-installation fa fa-sort-asc" style="display: none;"/>',"</th>",'<th class="centercell" style="width:10%;">','<a class="sort-repos-version" data-toggle="tooltip" data-placement="top" title="sort by version state" href="#">',"Version","</a>",'<span class="sort-icon-version fa fa-sort-asc" style="display: none;"/>',"</th>",'<th style="width:10%;">','<a class="sort-repos-date" data-toggle="tooltip" data-placement="top" title="sort by date" href="#">',"Date Installed","</a>",'<span class="sort-icon-date fa fa-sort-asc"/>',"</th>","</thead>",'<tbody id="repos_list_body">',"</tbody>","</table>","</div>","</div>","</div>"].join(""))}});return{AdminReposListView:f}});
//# sourceMappingURL=../../maps/admin/repos-list-view.js.map