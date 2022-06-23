var analyzer_results = {};
var file_byte_array = [];
var file_password = null;
var selected_file_component = 0;
var zip_file_extentions = ["docx", "docm", "pptx", "pptm", "xlsb", "xlsx", "xlsm", "zip"];

window.addEventListener('load', (event) => {
  document.getElementById('tab_summary').addEventListener('click', change_tab, false);
  document.getElementById('tab_text').addEventListener('click', change_tab, false);
  document.getElementById('summary_file_encrypted_password_img').addEventListener('click', decrypt_file, false);

  document.getElementById('open_file').addEventListener('change', read_file, false);
  document.getElementById('toolbar_open').addEventListener('click', function(){document.getElementById('open_file').click()}, false);
  document.getElementById('toolbar_save').addEventListener('click', save_selected, false);
});

/**
 * Handles the UX changes for when a user changes tabs.
 *
 * @param {Event}  e The event triggered from clicking the tab.
 */
function change_tab(e) {
  var tab_id = e.currentTarget.id;

  // Hide all tabs
  $("#tab_body_summary").hide();
  $("#tab_body_text").hide();

  $("#tab_summary").removeClass("tab_selected");
  $("#tab_text").removeClass("tab_selected");

  if (tab_id == "tab_summary") {
    $("#tab_body_summary").show();
    $("#tab_summary").addClass("tab_selected");
  } else if (tab_id == "tab_text") {
    $("#tab_body_text").show();
    $("#tab_text").addClass("tab_selected");
  }
}

/**
 * Decrypt file using provided password
 * @async
 *
 * @param {Event}  e The event triggered from clicking the decrypt file image.
 */
async function decrypt_file(e) {
  file_password = $("#summary_file_encrypted_password_txt").val();

  // If there is only one file, auto analyze that file
  if (analyzer_results.file_components.length == 1) {
    var component_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_byte_array, 0, file_password);
    var subfile_analyzer_results = await new Static_File_Analyzer(Array.from(component_bytes));
    display_file_summary(subfile_analyzer_results);
    select_file_component(null, 0);
  }
}

/**
 * Displays the provided file summary
 *
 * @param {object}  file_analyzer_results The results from the Static_File_Analyzer
 */
function display_file_summary(file_analyzer_results) {
  // Load summary info
  $("#summary_file_format").html(file_analyzer_results.file_format);
  $("#summary_file_type").html(file_analyzer_results.file_generic_type);
  $("#summary_file_format_ver").html(file_analyzer_results.file_format_ver);
  $("#summary_file_encrypted").html(file_analyzer_results.file_encrypted);

  if (file_analyzer_results.file_encrypted.toLowerCase() == "true" || file_analyzer_results.file_encrypted == true) {
    if (file_analyzer_results.file_format == "zip") {
      $("#summary_file_encrypted_password").css("display", "contents");
    } else {
      $("#summary_file_encrypted_password").css("display", "none");
      file_password = null;
    }
  } else {
    $("#summary_file_encrypted_password").css("display", "none");
    file_password = null;
  }

  $("#summary_detected_script").html(file_analyzer_results.scripts.script_type);
  $("#summary_metadata_title").html(file_analyzer_results.metadata.title);
  $("#summary_metadata_author").html(file_analyzer_results.metadata.author);
  $("#summary_metadata_description").html(file_analyzer_results.metadata.description);
  $("#summary_metadata_creation_application").html(file_analyzer_results.metadata.creation_application);
  $("#summary_metadata_creation_os").html(file_analyzer_results.metadata.creation_os);
  $("#summary_metadata_creation_date").html(file_analyzer_results.metadata.creation_date);
  $("#summary_metadata_last_modified_date").html(file_analyzer_results.metadata.last_modified_date);
  $("#summary_metadata_last_saved_location").html(file_analyzer_results.metadata.last_saved_location);

  $("#script_code").val(file_analyzer_results.scripts.extracted_script);
  $("#extracted_iocs").val(file_analyzer_results.iocs.join("\n"));
  $("#analytic_findings").val(file_analyzer_results.analytic_findings.join("\n"));
}

/**
 * Returns the content of a given byte array (file) as a string.
 * This function will attempt to make a Unicode safe conversion of the byte array,
 * but will return an ASCII representation if that fails.
 *
 * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of a file.
 * @return {String}     The string value of the file.
 */
function get_file_text(byte_array) {
  var file_text = file_text = Static_File_Analyzer.get_string_from_array(byte_array);

  if (file_text === null)
    file_text = Static_File_Analyzer.get_ascii(byte_array);

  return file_text;
}

/**
 * Event triggered when the user opens a file.
 *
 * @param {Event}  e The event triggered from opening a new file.
 */
function read_file(e) {
  var file = e.target.files[0];
  file_byte_array = [];

  if (!file) {
    return;
  } else {
    // Clear out file tree
    $("#file_tree").html("");
    $("#file_components_list").html("");

    // Clear password field.
    $("#summary_file_encrypted_password_txt").val("");

    // Disable save toolbar item
    $("#toolbar_save_svg").css("fill", "#999");
    $("#toolbar_save_caption").css("color", "#999");

    // Add new file info.
    $("#file_tree").append("<li id='top_level_file' class='file_tree_item_selected'>" + file.name + "</li>");
    $("#top_level_file").append("<ul class='nested_item' id='file_components_list'></ul>");
    document.getElementById("top_level_file").addEventListener('click', select_top_level_file, false);
  }

  var reader = new FileReader();
  reader.readAsArrayBuffer(file);

  reader.onload = async function(e) {
    if (e.target.readyState == FileReader.DONE) {
      var contents = e.target.result;
      var array_buffer = e.target.result,
          array = new Uint8Array(array_buffer);

      for (var i = 0; i < array.length; i++) {
          file_byte_array.push(array[i]);
      }

      analyzer_results = await new Static_File_Analyzer(file_byte_array);

      // Populate file tree.
      for (var i = 0; i < analyzer_results.file_components.length; i++) {
        var new_name = analyzer_results.file_components[i].name;
        var new_id = "component_" + i;
        var new_item = "<li id='" + new_id + "'>" + new_name + "</li>";

        $("#file_components_list").append(new_item);
        document.getElementById(new_id).addEventListener('click', select_file_component, false);
      }

      // Load summary info
      display_file_summary(analyzer_results);

      $("#file_text").val(get_file_text(array));
    }
  };
}

/**
 * Handles the UX click for the toolbar save selected button.
 * @async
 * @param {Event}  e The event triggered from clicking the tab.
 */
async function save_selected(e) {
  if (analyzer_results.file_components[selected_file_component].type == "zip") {
    var file_name = analyzer_results.file_components[selected_file_component].name;
    var component_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_byte_array, selected_file_component, file_password);
    var base64_encoded = Static_File_Analyzer.base64_encode_array(component_bytes);

    var hidden_element = document.createElement('a');
    hidden_element.href = 'data:application/octet-stream;base64,' + base64_encoded;
    hidden_element.target = '_blank';
    hidden_element.download = file_name;

    document.body.appendChild(hidden_element);
    hidden_element.click();
    document.body.removeChild(hidden_element);
  } else {
    // Code for other componets
  }
}

/**
 * Event triggered when the user clicks a file component from the file tree.
 * @async
 * @param {Event}   e The event triggered from the user click.
 * @param {integer} component_index Optional value to select ty component index.
 */
async function select_file_component(e, component_index=null) {
  if (e !== null) {
    var component_id = e.currentTarget.id;
    var component_index = parseInt(component_id.split("_")[1]);
    selected_file_component = component_index;
  }

  if (component_index !== null) {
    // Change UI to show selected component
    $("#top_level_file").removeClass("file_tree_item_selected");

    for (var i = 0; i < analyzer_results.file_components.length; i++) {
      var new_id = "#component_" + i;
      $(new_id).removeClass("file_tree_item_selected");
    }

    $("#component_" + component_index).addClass("file_tree_item_selected");

    if (analyzer_results.file_components[component_index].type == "zip") {
      file_password = ($("#summary_file_encrypted_password_txt").val().length > 0) ? $("#summary_file_encrypted_password_txt").val() : null;
      var component_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_byte_array, component_index, file_password);
      $("#file_text").val(get_file_text(component_bytes));

      // Enable save toolbar item
      $("#toolbar_save_svg").css("fill", "#000");
      $("#toolbar_save_caption").css("color", "#000");
    } else {
      // Code for other componets

      // Disable save toolbar item
      $("#toolbar_save_svg").css("fill", "#999");
      $("#toolbar_save_caption").css("color", "#999");
    }
  }

  if (e !== null) e.stopPropagation();
}

/**
 * Event triggered when the user clicks the top level file in the file tree.
 * @async
 * @param {Event}  e The event triggered from the user click.
 */
async function select_top_level_file(e) {
  $("#top_level_file").addClass("file_tree_item_selected");

  for (var i = 0; i < analyzer_results.file_components.length; i++) {
    var new_id = "#component_" + i;
    $(new_id).removeClass("file_tree_item_selected");
  }

  $("#file_text").val(get_file_text(file_byte_array));
}
