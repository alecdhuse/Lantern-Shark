var analyzer_results = {};
var file_byte_array = [];
var file_password = null;
var selected_file_component = 0;
var selected_file_component_id = "top_level_file";
var zip_file_extentions = ["docx", "docm", "pptx", "pptm", "xlsb", "xlsx", "xlsm", "zip"];

window.addEventListener('load', (event) => {
  document.getElementById('tab_summary').addEventListener('click', change_tab, false);
  document.getElementById('tab_text').addEventListener('click', change_tab, false);
  document.getElementById('tab_parsed').addEventListener('click', change_tab, false);
  document.getElementById('summary_file_encrypted_password_img').addEventListener('click', decrypt_file, false);
  document.getElementById('summary_file_encrypted_password_force_img').addEventListener('click', brute_force_zip, false);
  document.getElementById('summary_file_encrypted_password_txt').addEventListener('keydown', password_field_keydown, false);

  document.getElementById('open_file').addEventListener('change', read_file, false);
  document.getElementById('toolbar_open').addEventListener('click', function(){document.getElementById('open_file').click()}, false);
  document.getElementById('toolbar_save').addEventListener('click', save_selected_file, false);
});

/**
 * Attempts to brute force a ZIP file's password.

 * @param {Event}  e The event triggered from clicking the brute force image.
 * @return {void}
 */
async function brute_force_zip(e) {
  if (window.zip) {
    var base_password;
    var component_bytes;
    var component_index = analyzer_results.file_components.length - 1;
    var first_try_passwords = ['infected','abc123','abc321','malware','virus','decreto','mise'];

    // Try a list of common passwords first.
    for (var i=0; i<first_try_passwords.length; i++) {
      file_password = first_try_passwords[i];

      try {
        component_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_byte_array, component_index, file_password);
        if (component_bytes.length == analyzer_results.file_components[component_index].uncompressed_size) {
          // Password found!
          $("#summary_file_encrypted_password_txt").val(file_password);
          decrypt_file(e);
          return;
        }
      } catch (err) {
        if (err.message != "Invalid pasword") break;
      }
    }

    // Next try all combinations of numbers up to length 5.
    for (var i=0; i<99999; i++) {
      base_password = i.toString(10);

      for (var i2=1; i2<6; i2++) {
        var lead_zero = new Array(i2).join("0");
        file_password = lead_zero + base_password;

        try {
          component_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_byte_array, component_index, file_password);

          if (component_bytes.length == analyzer_results.file_components[component_index].uncompressed_size) {
            // Password found!
            $("#summary_file_encrypted_password_txt").val(file_password);
            decrypt_file(e);
            return;
          }
        } catch (err) {
          if (err.message != "Invalid pasword") break;
        }
      }
    }

    // Next try alpha numetic values.
    for (var i=0; i<9999999999; i++) {
      base_password = i.toString(36);

      for (var i2=1; i2<8; i2++) {
        var lead_zero = new Array(i2).join("0");
        file_password = lead_zero + base_password;

        try {
          component_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_byte_array, component_index, file_password);

          if (component_bytes.length == analyzer_results.file_components[component_index].uncompressed_size) {
            // Password found!
            $("#summary_file_encrypted_password_txt").val(file_password);
            decrypt_file(e);
            return;
          }
        } catch (err) {
          if (err.message != "Invalid pasword") break;
        }
      }
    }


  } else {
    throw "Zip decompression library not found. Please include zip-full.js from https://github.com/gildas-lormeau/zip.js";
  }
}

/**
 * Handles the UX changes for when a user changes tabs.
 *
 * @param {Event}  e The event triggered from clicking the tab.
 * @return {void}
 */
function change_tab(e) {
  var tab_id = e.currentTarget.id;

  // Hide all tabs
  $("#tab_body_summary").hide();
  $("#tab_body_text").hide();
  $("#tab_parsed_file").hide();

  $("#tab_summary").removeClass("tab_selected");
  $("#tab_text").removeClass("tab_selected");
  $("#tab_parsed").removeClass("tab_selected");

  if (tab_id == "tab_summary") {
    $("#tab_body_summary").show();
    $("#tab_summary").addClass("tab_selected");
  } else if (tab_id == "tab_text") {
    $("#tab_body_text").show();
    $("#tab_text").addClass("tab_selected");
  } else if (tab_id == "tab_parsed" || tab_id == "additional_metadata_div") {
    $("#tab_parsed_file").show();
    $("#tab_parsed").addClass("tab_selected");
  }
}

/**
 * Decrypt file using provided password
 * @async
 *
 * @param {Event}  e The event triggered from clicking the decrypt file image.
 * @return {void}
 */
async function decrypt_file(e) {
  file_password = $("#summary_file_encrypted_password_txt").val();

  let static_analyzer = new Static_File_Analyzer();
  analyzer_results = await static_analyzer.analyze(file_byte_array, "", file_password);

  if (analyzer_results.file_password == "unknown") {
    // wrong password
    $("#summary_file_encrypted_password_txt").addClass("field_invalid");
  } else {
    // correct password
    $("#summary_file_encrypted_password_txt").addClass("field_valid");

    try {
      for (var i=0; i<analyzer_results.file_components.length; i++) {
        if (analyzer_results.file_components[i].directory == false) {
          // Analyze the first file that is not a directory.
          var subfile_analyzer_results = await static_analyzer.analyze(analyzer_results.file_components[i].file_bytes);

          display_file_summary(subfile_analyzer_results);
          select_file_component(null, i);

          if (subfile_analyzer_results.file_components.length > 0) {
            // Display sub components in list
            display_sub_components(subfile_analyzer_results, selected_file_component_id);
          }

          if (selected_file_component_id == "top_level_file") {
            selected_file_component_id = "component_" + i;
          } else {
            selected_file_component_id = selected_file_component_id + "_" + i;
          }

          break;
        }
      }
    } catch (err) {
      // Wrong password
      console.log("File decrypt error: " + err)
    }
  }

}

/**
 * Displays the provided file summary
 *
 * @param {object}  file_analyzer_results The results from the Static_File_Analyzer
 * @return {void}
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

      if (file_analyzer_results.file_password !== "unknown") {
        $("#summary_file_encrypted_password_txt").val(file_analyzer_results.file_password);
      }
    } else {
      $("#summary_file_encrypted_password").css("display", "none");
      file_password = null;
    }
  } else {
    $("#summary_file_encrypted_password").css("display", "none");
    file_password = null;
  }

  $("#summary_metadata_title").html(escape_string(file_analyzer_results.metadata.title));
  $("#summary_metadata_author").html(escape_string(file_analyzer_results.metadata.author));
  $("#summary_metadata_description").html(escape_string(file_analyzer_results.metadata.description));
  $("#summary_metadata_creation_application").html(escape_string(file_analyzer_results.metadata.creation_application));
  $("#summary_metadata_creation_os").html(escape_string(file_analyzer_results.metadata.creation_os));
  $("#summary_metadata_creation_date").html(escape_string(file_analyzer_results.metadata.creation_date));
  $("#summary_metadata_last_modified_date").html(escape_string(file_analyzer_results.metadata.last_modified_date));
  $("#summary_metadata_last_saved_location").html(escape_string(file_analyzer_results.metadata.last_saved_location));
  $("#summary_metadata_sha256").html(escape_string(file_analyzer_results.file_hashes.sha256));

  if (file_analyzer_results.metadata.additional_metadata.type != "none") {
    let metadata_html = "<div id='additional_metadata_div' class='faux_link'>" + file_analyzer_results.metadata.additional_metadata.type + "</div>";
    $("#summary_metadata_additional").html(metadata_html);

    document.getElementById("additional_metadata_div").addEventListener('click', change_tab, false);
  } else {
    $("#summary_metadata_additional").html("None");
  }

  $("#extracted_iocs").val(file_analyzer_results.iocs.join("\n"));
  $("#analytic_findings").val(file_analyzer_results.analytic_findings.join("\n"));

  // Add all extracted scripts
  if (file_analyzer_results.scripts.extracted_scripts.length > 0) {
    let combined_scripts = "";
    let combined_script_types = "";
    for (let i=0; i<file_analyzer_results.scripts.extracted_scripts.length; i++) {
      combined_scripts += file_analyzer_results.scripts.extracted_scripts[i].script_text + "\n\n";

      if (!combined_script_types.includes(file_analyzer_results.scripts.extracted_scripts[i].script_type)) {
        if (i > 0) {
          combined_script_types += ", ", file_analyzer_results.scripts.extracted_scripts[i].script_type;
        } else {
          combined_script_types += file_analyzer_results.scripts.extracted_scripts[i].script_type;
        }
      }
    }
    $("#script_code").val(combined_scripts);
    $("#summary_detected_script").html(escape_string(combined_script_types));
  } else {
    $("#summary_detected_script").html("None");
    $("#summary_detected_script").html("");
  }

}

/**
 * Returns the content of a given byte array (file) as a string.
 * This function will attempt to make a Unicode safe conversion of the byte array,
 * but will return an ASCII representation if that fails.
 *
 * @param {boolean}  to_enable True or False to enable the save file toolbar button.
 * @return {void}
 */
function enable_save_file_toolbar_button(to_enable) {
  if (to_enable == true) {
    $("#toolbar_save_svg").css("fill", "#000");
    $("#toolbar_save_caption").css("color", "#000");
  } else {
    $("#toolbar_save_svg").css("fill", "#999");
    $("#toolbar_save_caption").css("color", "#999");
  }
}

/**
 * Returns a string that is HTML escaped.
 *
 * @param {String}  input_string The string to escape.
 * @return {String} The escaped stirng.
 */
function escape_string(input_string) {
  let return_string = input_string;

  return_string = return_string.replaceAll("&", "&amp;");
  return_string = return_string.replaceAll("<", "&lt;");
  return_string = return_string.replaceAll(">", "&gt;");

  return return_string;
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
 * Removes the styling from the file password input or decrypts file if key is enter.

 * @param {Event}  e The event triggered this function
 */
function password_field_keydown(e) {
  if (e.key == "Enter") {
    decrypt_file(e);
  } else {
    $("#summary_file_encrypted_password_txt").removeClass("field_invalid");
    $("#summary_file_encrypted_password_txt").removeClass("field_valid");
  }
}

/**
 * Event triggered when the user opens a file.
 *
 * @param {Event}  e The event triggered from opening a new file.
 * @return {void}
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
    $("#summary_file_encrypted_password_txt").removeClass("field_invalid");
    $("#summary_file_encrypted_password_txt").removeClass("field_valid");

    // Disable save toolbar item
    $("#toolbar_save_svg").css("fill", "#999");
    $("#toolbar_save_caption").css("color", "#999");

    // Add new file info.
    $("#file_tree").append("<li id='top_level_file' class='file_tree_item_selected'>" + file.name + "</li>");
    //$("#top_level_file").append("<ul class='nested_item' id='file_components_list'></ul>");
    document.getElementById("top_level_file").addEventListener('click', select_top_level_file, false);
  }

  var reader = new FileReader();
  reader.readAsArrayBuffer(file);

  reader.onload = async function(e) {
    if (e.target.readyState == FileReader.DONE) {
      var contents = e.target.result;
      var array_buffer = e.target.result,
          array = new Uint8Array(array_buffer);

      let file_byte_array = Array.from(array);

      let static_analyzer = new Static_File_Analyzer();
      analyzer_results = await static_analyzer.analyze(file_byte_array);

      await display_sub_components(analyzer_results, "top_level_file");

      // If the file is a type of file archive or disk image and it contains a single file.
      // Auto open to that one file.
      if ((analyzer_results.file_generic_type == "File Archive" || analyzer_results.file_generic_type == "Disk Image" ) && analyzer_results.file_components.length == 1) {
        // Load subfile summary info
        select_file_component(null, 0);
      } else {
        // Load main file summary info
        display_file_summary(analyzer_results);
      }

      $("#file_text").val(get_file_text(array));
      $("#parsed_file_text").val(analyzer_results.parsed);
    }
  };
}

async function display_sub_components(analyzer_results, parent_element_id) {
  for (var i = 0; i < analyzer_results.file_components.length; i++) {
    var child_element_id;
    var component_name = analyzer_results.file_components[i].name;

    if (parent_element_id == "top_level_file") {
      child_element_id = "component_" + i;
    } else {
      child_element_id = parent_element_id + "_" + i;
    }

    var layer = child_element_id.substring(child_element_id.indexOf("_"));
    var sub_list_id = "file_components_list" + layer;
    var new_item = "<li class='file_tree_item_not_selected' id='" + child_element_id + "'>" + component_name + "</li>";

    $("#"+parent_element_id).append("<ul class='nested_item' id='" + sub_list_id + "'></ul>");
    $("#"+sub_list_id).append(new_item);

    document.getElementById(child_element_id).addEventListener('click', select_file_component, false);

    if (analyzer_results.file_components[i].directory == false) {
      if (analyzer_results.file_components[i].hasOwnProperty("file_bytes")) {
        let static_analyzer = new Static_File_Analyzer();
        var subfile_analyzer_results = await static_analyzer.analyze(Array.from(analyzer_results.file_components[i].file_bytes));

        if (subfile_analyzer_results.file_components.length > 0) {
          await display_sub_components(subfile_analyzer_results, child_element_id);
        }
      }
    }
  }
}

/**
 * Handles the UX click for the toolbar save selected button.
 * @async
 * @param {Event}  e The event triggered from clicking the tab.
 * @return {void}
 */
async function save_selected_file(e) {
  var base64_encoded;
  var component_bytes = [];

  let component_info = selected_file_component_id.split("_").slice(1);
  let select_analyzer_results = analyzer_results;
  var selected_file_component;

  for (let i=0; i<component_info.length; i++) {
    let c_component_index = parseInt(component_info[i]);
    selected_file_component = select_analyzer_results.file_components[c_component_index];

    if (i+1 < component_info.length) {
      let static_analyzer = new Static_File_Analyzer();
      select_analyzer_results = await static_analyzer.analyze(selected_file_component.file_bytes);
    } else {
      // Don't analyze file if it's the last one.
      break;
    }
  }

  var file_name = selected_file_component.name;
  file_password = $("#summary_file_encrypted_password_txt").val();
  component_bytes = selected_file_component.file_bytes;

  if (component_bytes !== null && component_bytes !== undefined) {
    base64_encoded = Static_File_Analyzer.base64_encode_array(component_bytes);
    var hidden_element = document.createElement('a');
    hidden_element.href = 'data:application/octet-stream;base64,' + base64_encoded;
    hidden_element.target = '_blank';
    hidden_element.download = file_name;

    document.body.appendChild(hidden_element);
    hidden_element.click();
    document.body.removeChild(hidden_element);
  }
}

/**
 * Event triggered when the user clicks a file component from the file tree.
 * @async
 * @param {Event}   e The event triggered from the user click.
 * @param {integer} component_index Optional value to select ty component index.
 * @return {void}
 */
async function select_file_component(e, component_index=null) {
  var select_analyzer_results = analyzer_results;
  var component_info = [];
  var selected_file_component;

  try {
    if (e !== null) {
      var component_id = e.currentTarget.id;
      selected_file_component_id = component_id;
      component_info = component_id.split("_").slice(1);
    } else {
      component_info = [component_index];
    }

    for (let i=0; i<component_info.length; i++) {
      let c_component_index = parseInt(component_info[i]);
      selected_file_component = select_analyzer_results.file_components[c_component_index];

      let static_analyzer = new Static_File_Analyzer();
      select_analyzer_results = await static_analyzer.analyze(selected_file_component.file_bytes);
    }

    // Remove all selected classes
    $("#top_level_file").removeClass("file_tree_item_selected");
    $("#top_level_file").find("*").removeClass("file_tree_item_selected");
    $("#top_level_file").find("*").addClass("file_tree_item_not_selected");

    // Remove all selected classes
    $("#top_level_file").removeClass("file_tree_item_selected");
    $("#top_level_file").find("*").removeClass("file_tree_item_selected");
    $("#top_level_file").find("*").addClass("file_tree_item_not_selected");

    // Change UI to show selected component
    var to_select = "#component_" + component_info.join("_");
    $(to_select).removeClass("file_tree_item_not_selected");
    $(to_select).addClass("file_tree_item_selected");

    if (selected_file_component.directory == true) {
      // This is a directory
      $("#summary_file_format").html("Directory");
      $("#summary_file_type").html("Directory");
      $("#summary_file_format_ver").html("unknown");
      $("#summary_file_encrypted").html("False");
      $("#summary_detected_script").html("None");
      $("#summary_metadata_title").html("unknown");
      $("#summary_metadata_author").html("unknown");
      $("#summary_metadata_description").html("unknown");
      $("#summary_metadata_creation_application").html("unknown");
      $("#summary_metadata_creation_os").html("unknown");
      $("#summary_metadata_creation_date").html("unknown");
      $("#summary_metadata_last_modified_date").html("unknown");
      $("#summary_metadata_last_saved_location").html("unknown");
      $("#script_code").val("");
      $("#extracted_iocs").val("");
      $("#analytic_findings").val("");
    } else {
      $("#file_text").val(get_file_text(selected_file_component.file_bytes));
      $("#parsed_file_text").val(select_analyzer_results.parsed);

      display_file_summary(select_analyzer_results);

      if (selected_file_component.hasOwnProperty("file_bytes") && selected_file_component.file_bytes.length > 0) {
        // Enable save toolbar item
        enable_save_file_toolbar_button(true);
      } else {
        // Disable save toolbar item
        enable_save_file_toolbar_button(false);
      }

    }
  } catch (err) {
    console.log("Error parsing file component: " + err);
  }

  if (e !== null) e.stopPropagation();
}

/**
 * Event triggered when the user clicks the top level file in the file tree.
 * @async
 * @param {Event}  e The event triggered from the user click.
 * @return {void}
 */
async function select_top_level_file(e) {
  $("#top_level_file").addClass("file_tree_item_selected");

  for (var i = 0; i < analyzer_results.file_components.length; i++) {
    var new_id = "#component_" + i;
    $(new_id).removeClass("file_tree_item_selected");
  }

  display_file_summary(analyzer_results);
  $("#file_text").val(get_file_text(file_byte_array));
  $("#parsed_file_text").val(analyzer_results.parsed);
}
