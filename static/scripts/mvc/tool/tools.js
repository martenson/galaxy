define(["libs/underscore","viz/trackster/util","mvc/dataset/data","mvc/tool/tool-form"],function(a,b,c){"use strict";var d={hidden:!1,show:function(){this.set("hidden",!1)},hide:function(){this.set("hidden",!0)},toggle:function(){this.set("hidden",!this.get("hidden"))},is_visible:function(){return!this.attributes.hidden}},e=Backbone.Model.extend({defaults:{name:null,label:null,type:null,value:null,html:null,num_samples:5},initialize:function(){this.attributes.html=unescape(this.attributes.html)},copy:function(){return new e(this.toJSON())},set_value:function(a){this.set("value",a||"")}}),f=Backbone.Collection.extend({model:e}),g=e.extend({}),h=e.extend({set_value:function(a){this.set("value",parseInt(a,10))},get_samples:function(){return d3.scale.linear().domain([this.get("min"),this.get("max")]).ticks(this.get("num_samples"))}}),i=h.extend({set_value:function(a){this.set("value",parseFloat(a))}}),j=e.extend({get_samples:function(){return a.map(this.get("options"),function(a){return a[0]})}});e.subModelTypes={integer:h,"float":i,data:g,select:j};var k=Backbone.Model.extend({defaults:{id:null,name:null,description:null,target:null,inputs:[],outputs:[]},urlRoot:Galaxy.root+"api/tools",initialize:function(b){this.set("inputs",new f(a.map(b.inputs,function(a){var b=e.subModelTypes[a.type]||e;return new b(a)})))},toJSON:function(){var a=Backbone.Model.prototype.toJSON.call(this);return a.inputs=this.get("inputs").map(function(a){return a.toJSON()}),a},remove_inputs:function(a){var b=this,c=b.get("inputs").filter(function(b){return-1!==a.indexOf(b.get("type"))});b.get("inputs").remove(c)},copy:function(a){var b=new k(this.toJSON());if(a){var c=new Backbone.Collection;b.get("inputs").each(function(a){a.get_samples()&&c.push(a)}),b.set("inputs",c)}return b},apply_search_results:function(b){return-1!==a.indexOf(b,this.attributes.id)?this.show():this.hide(),this.is_visible()},set_input_value:function(a,b){this.get("inputs").find(function(b){return b.get("name")===a}).set("value",b)},set_input_values:function(b){var c=this;a.each(a.keys(b),function(a){c.set_input_value(a,b[a])})},run:function(){return this._run()},rerun:function(a,b){return this._run({action:"rerun",target_dataset_id:a.id,regions:b})},get_inputs_dict:function(){var a={};return this.get("inputs").each(function(b){a[b.get("name")]=b.get("value")}),a},_run:function(d){var e=a.extend({tool_id:this.id,inputs:this.get_inputs_dict()},d),f=$.Deferred(),g=new b.ServerStateDeferred({ajax_settings:{url:this.urlRoot,data:JSON.stringify(e),dataType:"json",contentType:"application/json",type:"POST"},interval:2e3,success_fn:function(a){return"pending"!==a}});return $.when(g.go()).then(function(a){f.resolve(new c.DatasetCollection(a))}),f}});a.extend(k.prototype,d);var l=(Backbone.View.extend({}),Backbone.Collection.extend({model:k})),m=Backbone.Model.extend(d),n=Backbone.Model.extend({defaults:{elems:[],open:!1},clear_search_results:function(){a.each(this.attributes.elems,function(a){a.show()}),this.show(),this.set("open",!1)},apply_search_results:function(b){var c,d=!0;a.each(this.attributes.elems,function(a){a instanceof m?(c=a,c.hide()):a instanceof k&&a.apply_search_results(b)&&(d=!1,c&&c.show())}),d?this.hide():(this.show(),this.set("open",!0))}});a.extend(n.prototype,d);var o=Backbone.Model.extend({defaults:{search_hint_string:"search tools",min_chars_for_search:3,clear_btn_url:"",visible:!0,query:"",results:null,clear_key:27},urlRoot:Galaxy.root+"api/tools",initialize:function(){this.on("change:query",this.do_search)},do_search:function(){var a=this.attributes.query;if(a.length<this.attributes.min_chars_for_search)return void this.set("results",null);var b=a;this.timer&&clearTimeout(this.timer),$("#search-clear-btn").hide(),$("#search-spinner").show();var c=this;this.timer=setTimeout(function(){"undefined"!=typeof ga&&ga("send","pageview",Galaxy.root+"?q="+b),$.get(c.urlRoot,{q:b},function(a){c.set("results",a),$("#search-spinner").hide(),$("#search-clear-btn").show()},"json")},400)},clear_search:function(){this.set("query",""),this.set("results",null)}});a.extend(o.prototype,d);var p=Backbone.Model.extend({initialize:function(a){this.attributes.tool_search=a.tool_search,this.attributes.tool_search.on("change:results",this.apply_search_results,this),this.attributes.tools=a.tools,this.attributes.layout=new Backbone.Collection(this.parse(a.layout))},parse:function(b){var c=this,d=function(b){var e=b.model_class;if(e.indexOf("Tool")===e.length-4)return c.attributes.tools.get(b.id);if("ToolSection"===e){var f=a.map(b.elems,d);return b.elems=f,new n(b)}return"ToolSectionLabel"===e?new m(b):void 0};return a.map(b,d)},clear_search_results:function(){this.get("layout").each(function(a){a instanceof n?a.clear_search_results():a.show()})},apply_search_results:function(){var a=this.get("tool_search").get("results");if(null===a)return void this.clear_search_results();var b=null;this.get("layout").each(function(c){c instanceof m?(b=c,b.hide()):c instanceof k?c.apply_search_results(a)&&b&&b.show():(b=null,c.apply_search_results(a))})}}),q=Backbone.View.extend({initialize:function(){this.model.on("change:hidden",this.update_visible,this),this.update_visible()},update_visible:function(){this.model.attributes.hidden?this.$el.hide():this.$el.show()}}),r=q.extend({tagName:"div",render:function(){var a=$("<div/>");a.append(x.tool_link(this.model.toJSON()));var b=this.model.get("form_style",null);if("upload1"===this.model.id)a.find("a").on("click",function(a){a.preventDefault(),Galaxy.upload.show()});else if("regular"===b){var c=this;a.find("a").on("click",function(a){a.preventDefault(),Galaxy.router.push("/",{tool_id:c.model.id,version:c.model.get("version")})})}return this.$el.append(a),this}}),s=q.extend({tagName:"div",className:"toolPanelLabel",render:function(){return this.$el.append($("<span/>").text(this.model.attributes.text)),this}}),t=q.extend({tagName:"div",className:"toolSectionWrapper",initialize:function(){q.prototype.initialize.call(this),this.model.on("change:open",this.update_open,this)},render:function(){this.$el.append(x.panel_section(this.model.toJSON()));var b=this.$el.find(".toolSectionBody");return a.each(this.model.attributes.elems,function(a){if(a instanceof k){var c=new r({model:a,className:"toolTitle"});c.render(),b.append(c.$el)}else if(a instanceof m){var d=new s({model:a});d.render(),b.append(d.$el)}}),this},events:{"click .toolSectionTitle > a":"toggle"},toggle:function(){this.model.set("open",!this.model.attributes.open)},update_open:function(){this.model.attributes.open?this.$el.children(".toolSectionBody").slideDown("fast"):this.$el.children(".toolSectionBody").slideUp("fast")}}),u=Backbone.View.extend({tagName:"div",id:"tool-search",className:"bar",events:{click:"focus_and_select","keyup :input":"query_changed","change :input":"query_changed","click #search-clear-btn":"clear"},render:function(){return this.$el.append(x.tool_search(this.model.toJSON())),this.model.is_visible()||this.$el.hide(),$("#messagebox").is(":visible")&&this.$el.css("top","95px"),this.$el.find("[title]").tooltip(),this},focus_and_select:function(){this.$el.find(":input").focus().select()},clear:function(){return this.model.clear_search(),this.$el.find(":input").val(""),this.focus_and_select(),!1},query_changed:function(a){return this.model.attributes.clear_key&&this.model.attributes.clear_key===a.which?(this.clear(),!1):void this.model.set("query",this.$el.find(":input").val())}}),v=Backbone.View.extend({tagName:"div",className:"toolMenu",initialize:function(){this.model.get("tool_search").on("change:results",this.handle_search_results,this)},render:function(){var a=this,b=new u({model:this.model.get("tool_search")});return b.render(),a.$el.append(b.$el),this.model.get("layout").each(function(b){if(b instanceof n){var c=new t({model:b});c.render(),a.$el.append(c.$el)}else if(b instanceof k){var d=new r({model:b,className:"toolTitleNoSection"});d.render(),a.$el.append(d.$el)}else if(b instanceof m){var e=new s({model:b});e.render(),a.$el.append(e.$el)}}),a.$el.find("a.tool-link").click(function(b){var c=$(this).attr("class").split(/\s+/)[0],d=a.model.get("tools").get(c);a.trigger("tool_link_click",b,d)}),this},handle_search_results:function(){var a=this.model.get("tool_search").get("results");a&&0===a.length?$("#search-no-results").show():$("#search-no-results").hide()}}),w=Backbone.View.extend({className:"toolForm",render:function(){this.$el.children().remove(),this.$el.append(x.tool_form(this.model.toJSON()))}}),x=(Backbone.View.extend({className:"toolMenuAndView",initialize:function(){this.tool_panel_view=new v({collection:this.collection}),this.tool_form_view=new w},render:function(){this.tool_panel_view.render(),this.tool_panel_view.$el.css("float","left"),this.$el.append(this.tool_panel_view.$el),this.tool_form_view.$el.hide(),this.$el.append(this.tool_form_view.$el);var a=this;this.tool_panel_view.on("tool_link_click",function(b,c){b.preventDefault(),a.show_tool(c)})},show_tool:function(a){var b=this;a.fetch().done(function(){b.tool_form_view.model=a,b.tool_form_view.render(),b.tool_form_view.$el.show(),$("#left").width("650px")})}}),{tool_search:a.template(['<input id="tool-search-query" class="search-query parent-width" name="query" ','placeholder="<%- search_hint_string %>" autocomplete="off" type="text" />','<a id="search-clear-btn" title="clear search (esc)"> </a>','<span id="search-spinner" class="search-spinner fa fa-spinner fa-spin"></span>'].join("")),panel_section:a.template(['<div class="toolSectionTitle" id="title_<%- id %>">','<a href="javascript:void(0)"><span><%- name %></span></a>',"</div>",'<div id="<%- id %>" class="toolSectionBody" style="display: none;">','<div class="toolSectionBg"></div>',"<div>"].join("")),tool_link:a.template(['<a class="<%- id %> tool-link" href="<%= link %>" target="<%- target %>" minsizehint="<%- min_width %>">','<span class="labels">',"<% _.each( labels, function( label ){ %>",'<span class="label label-default label-<%- label %>">',"<%- label %>","</span>","<% }); %>","</span>",'<span class="tool-old-link">',"<%- name %>","</span>"," <%- description %>","</a>"].join("")),tool_form:a.template(['<div class="toolFormTitle"><%- tool.name %> (version <%- tool.version %>)</div>','<div class="toolFormBody">',"<% _.each( tool.inputs, function( input ){ %>",'<div class="form-row">','<label for="<%- input.name %>"><%- input.label %>:</label>','<div class="form-row-input">',"<%= input.html %>","</div>",'<div class="toolParamHelp" style="clear: both;">',"<%- input.help %>","</div>",'<div style="clear: both;"></div>',"</div>","<% }); %>","</div>",'<div class="form-row form-actions">','<input type="submit" class="btn btn-primary" name="runtool_btn" value="Execute" />',"</div>",'<div class="toolHelp">','<div class="toolHelpBody"><% tool.help %></div>',"</div>"].join(""),{variable:"tool"})});return{ToolParameter:e,IntegerToolParameter:h,SelectToolParameter:j,Tool:k,ToolCollection:l,ToolSearch:o,ToolPanel:p,ToolPanelView:v,ToolFormView:w}});
//# sourceMappingURL=../../../maps/mvc/tool/tools.js.map