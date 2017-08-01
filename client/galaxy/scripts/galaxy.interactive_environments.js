/**
 * Internal function to remove content from the main area and add the notebook.
 * Not idempotent
 */
function append_notebook(url){
    clear_main_area();
    $('#main').append('<iframe frameBorder="0" seamless="seamless" style="width: 100%; height: 100%; overflow:hidden;" scrolling="no" src="'+ url +'"></iframe>'
    );
}

function clear_main_area(){
    $('#spinner').remove();
    $('#main').children().remove();
}

function display_spinner(){
        $('#main').append('<img id="spinner" src="' + galaxy_root + 'static/style/largespinner.gif" style="position:absolute;margin:auto;top:0;left:0;right:0;bottom:0;">');
}

function not_ready(timeout, timeout_values, timeout_time_max, timeout_time_step) {
    if(timeout_values.count == 0){
        display_spinner();
        toastr.info(
            "Galaxy is launching a container in which to run this interactive environment. Please wait...",
            {'closeButton': true, 'tapToDismiss': false}
        );
    }
    timeout_values.count++;
    if(timeout_values.time < timeout_time_max){
        timeout_values.time += timeout_time_step;
    }
    console.log("Readiness request " + timeout_values.count + " sleeping " + timeout_values.time / 1000 + "s");
    window.setTimeout(timeout, timeout_values.time)
}

/**
 * Check a URL for a boolean true/false and call a callback when done.
 */
function load_when_ready(url, success_callback){
    var ajax_timeout = 500;
    var ajax_timeout_max = 10000;
    var ajax_timeout_step = 250;
    var timeout_values = { time: 1000, count: 0 };
    var timeout_time_max = 15000;
    var timeout_time_step = 1000;
    var timeout = function(){
        $.ajax({
            url: url,
            xhrFields: {
                withCredentials: true
            },
            type: "GET",
            timeout: ajax_timeout,
            dataType: "json",
            success: function(data){
                if(data == true){
                    console.log("Galaxy reports IE container ready, returning");
                    clear_main_area();
                    toastr.clear();
                    success_callback();
                }else if(data == false){
                    not_ready(timeout, timeout_values, timeout_time_max, timeout_time_step);
                }else{
                    clear_main_area();
                    toastr.clear();
                    toastr.error(
                        "Galaxy failed to launch a container in which to run this interactive environment, contact your administrator.",
                        "Error",
                        {'closeButton': true, 'tapToDismiss': false}
                    );
                }
            },
            error: function(jqXHR, textStatus, errorThrown){
                if(textStatus == "timeout"){
                    if(ajax_timeout < ajax_timeout_max){
                        ajax_timeout += ajax_timeout_step;
                    }
                    not_ready(timeout, timeout_values, timeout_time_max, timeout_time_step);
                }else{
                    clear_main_area();
                    toastr.clear();
                    toastr.error(
                        "Galaxy encountered an error while attempting to determine the readiness of this interactive environment, contact your administrator.",
                        "Error",
                        {'closeButton': true, 'tapToDismiss': false}
                    );
                }
            }
        });
    }
    window.setTimeout(timeout, timeout_values.time);
}



/**
 * Test availability of a URL, and call a callback when done.
 * http://stackoverflow.com/q/25390206/347368
 * @param {String} url: URL to test availability of. Must return a 200 (302->200 is OK).
 * @param {String} callback: function to call once successfully connected.
 *
 */
function test_ie_availability(url, success_callback){
    var request_count = 0;
    display_spinner();
    interval = setInterval(function(){
        $.ajax({
            url: url,
            xhrFields: {
                withCredentials: true
            },
            type: "GET",
            timeout: 500,
            success: function(){
                console.log("Connected to IE, returning");
                clearInterval(interval);
                success_callback();
            },
            error: function(jqxhr, status, error){
                request_count++;
                console.log("Availability request " + request_count);
                if(request_count > 30){
                    clearInterval(interval);
                    clear_main_area();
                    toastr.error(
                        "Could not connect to IE, contact your administrator",
                        "Error",
                        {'closeButton': true, 'timeOut': 20000, 'tapToDismiss': false}
                    );
                }
            }
        });
    }, 1000);
}
