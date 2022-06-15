/*
 Copyright (c) 2022 Alec Dhuse. All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in
 the documentation and/or other materials provided with the distribution.

 3. The names of the authors may not be used to endorse or promote products
 derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
 INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
 INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
class Static_File_Analyzer {
  /**
   * Created the default object structure for the output of this class.
   *
   * @param {Uint8Array} file_bytes Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param {String}     file_text  [Optional] The text version of the file, it can be provided to save compute time, otherwise it will be generated in this constructor.
   * @return {object}    An object with analyzed file results. See get_default_file_json for the format.
   */
  constructor(file_bytes, file_text="") {
    this.BIG_ENDIAN = "BIG_ENDIAN";
    this.LITTLE_ENDIAN = "LITTLE_ENDIAN";
    this.XML_DOMAINS = ["openoffice.org","purl.org","schemas.microsoft.com","schemas.openxmlformats.org","w3.org"];

    var file_info = this.get_default_file_json();

    if (this.array_equals(file_bytes.slice(7,14), [42,42,65,67,69,42,42])) {
      file_info = this.analyze_ace(file_bytes);
    } else if (this.array_equals(file_bytes.slice(0,2), [77,90])) {
      file_info = this.analyze_exe(file_bytes);
    } else if (this.array_equals(file_bytes.slice(0,2), [31,139])) {
      file_info = this.analyze_gz(file_bytes);
    } else if (this.array_equals(file_bytes.slice(32769,32774), [67,68,48,48,49])) {
      file_info = this.analyze_iso9660(file_bytes);
    } else if (this.array_equals(file_bytes.slice(6,10), [74,70,73,70])) {
      file_info = this.analyze_jpeg(file_bytes);
    } else if (this.array_equals(file_bytes.slice(0,6), [82,97,114,33,26,7])) {
      file_info = this.analyze_rar(file_bytes);
    } else if (this.array_equals(file_bytes.slice(0,4), [0x7b,0x5c,0x72,0x74])) {
      file_info = this.analyze_rtf(file_bytes);
    } else if (this.array_equals(file_bytes.slice(0,4), [37,80,68,70])) {
      if (file_text == "") file_text = Static_File_Analyzer.get_ascii(file_bytes);
      file_info = this.analyze_pdf(file_bytes, file_text);
    } else if (this.array_equals(file_bytes.slice(0,4), [137,80,78,71])) {
      if (file_text == "") file_text = Static_File_Analyzer.get_ascii(file_bytes);
      file_info = this.analyze_png(file_bytes, file_text);
    } else if (this.array_equals(file_bytes.slice(0,8), [208,207,17,224,161,177,26,225])) {
      file_info = this.analyze_xls(file_bytes);
    } else if (this.array_equals(file_bytes.slice(0,5), [60,63,120,109,108])) {
      file_info = this.analyze_xml(file_bytes);
    } else if (this.array_equals(file_bytes.slice(0,4), [80,75,3,4])) {
      file_info = this.analyze_zip(file_bytes);
    } else {
      // Probably a text or mark up/down language
      if (file_text == "") file_text = Static_File_Analyzer.get_ascii(file_bytes);
    }

    return file_info;
  }

  /**
   * Extracts meta data and other information from ACE archive files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_ace(file_bytes) {
    var ace_os_list  = ["MS-DOS", "OS/2", "Windows", "Unix", "MAC-OS", "Windows NT", "Primos", "APPLE GS", "ATARI", "VAX VMS", "AMIGA", "NEXT"];
    var file_info = this.get_default_file_json();

    file_info.file_format = "ace";
    file_info.file_generic_type = "File Archive";
    file_info.file_creation_os = ((file_bytes[16] < 12) ? ace_os_list[file_bytes[16]] : file_bytes[16]);
    file_info.file_format_ver = file_bytes[15];
    file_info.metadata.creation_date = this.get_msdos_timestamp(file_bytes.slice(18, 22));

    var av_string_size = file_bytes[30];
    var header_byte2 = file_bytes[37];
    var header_bits2 = ("00000000" + (header_byte2).toString(2)).slice(-8).split("");

    if (header_bits2[6] == 1) {
      file_info.file_encrypted = "true";
      file_info.file_encryption_type = "Blowfish 160";
    } else {
      file_info.file_encrypted = "false";
      file_info.file_encryption_type = "none";
    }

    return file_info;
  }

  /**
   * Uses an aray of regex rules to find potentialy malicious code in a given script.
   * The output of this cunvtion is an array of string in the format:
   * [INFO,SUSPICIOUS,MALICIOUS] - Description of the finding.
   *
   * @param {String}  script_text Script text to analyze for malicious code.
   * @return {Array}  A string array with rule names for potentialy malicious code.
   */
  analyze_embedded_script(script_text) {
    var findings = [];
    var iocs = [];

    var rules = [
      {
        name:  "SUSPICIOUS - VBA Macro Calls Shell Command",
        regex: /Shell\(\s*[^\,\)]+\s*(?:,\s*[a-zA-Z]+\s*)?\)/gmi
      },
      {
        name:  "SUSPICIOUS - Certutil Used to Download a File",
        regex: /certutil\.exe\s+-urlcache\s+-split\s+-f\s+/gmi
      },
      {
        name:  "SUSPICIOUS - Mshta Command Used to Load Internet Hosted Resource",
        regex: /mshta\s+[a-zA-Z]+\:\/\//gmi
      }
    ];

    for (var r=0; r < rules.length; r++) {
      if (rules[r].regex.test(script_text)) {
        findings.push(rules[r].name);
      }
    }

    // Check for IoCs
    var ioc_search_base = [script_text, script_text.split("").reverse().join("")];

    for (var sbi=0; sbi<ioc_search_base.length; sbi++) {
      var url_regex = /((?:https?\:\/\/|\\\\)[^\s\)\"\'\,]+)/gmi;
      var url_match = url_regex.exec(ioc_search_base[sbi]);
      while (url_match !== null) {
        if (sbi == 1) {
          findings.push("SUSPICIOUS - IoC Found in Reversed String");
        }

        // Check for hex IP
        var hex_ip_match = /(?:\/|\\)(0x[0-9a-f]+)\//gmi.exec(url_match[1]);
        if (hex_ip_match !== null) {
          findings.push("SUSPICIOUS - Hex Obfuscated IP Address");

          try {
            var str_ip = Static_File_Analyzer.get_ip_from_hex(hex_ip_match[1]);
            iocs.push(url_match[1].replace(hex_ip_match[1], str_ip));
          } catch(err) {
            iocs.push(url_match[1]);
          }
        } else {
          iocs.push(url_match[1]);
        }

        url_match = url_regex.exec(ioc_search_base[sbi]);
      }
    }

    return {
      'findings': findings,
      'iocs':     iocs
    };
  }

  /**
   * Extracts IoCs and suspicious and malicious indicators from Excel 4.0 macros.
   *
   * @param {object} file_info The file_info object for the current
   * @param {object} sheets    The object containing all sheets in the spreadsheet.
   * @param {String} macro_string The string containing the macto to analyze
   * @return {object}  file_info with added result info.
   */
  analyze_excel_macro(file_info, sheets, macro_string) {
    var macro_functions = macro_string.split("=");
    var new_finding;

    for (var i=0; i<macro_functions.length; i++) {
      if (macro_functions[i].trim() != "") {
        new_finding = "";
        file_info.scripts.extracted_script += "=" + macro_functions[i] + "\n";

        if (/CALL\(/gm.test(macro_functions[i])) {
          file_info.scripts.script_type = "Excel 4.0 Macro";
          new_finding = "SUSPICIOUS - Use of CALL function";
        } else if (/EXEC\(/gm.test(macro_functions[i])) {
          file_info.scripts.script_type = "Excel 4.0 Macro";
          new_finding = "SUSPICIOUS - Use of EXEC function";
        }

        if (new_finding != "" && !file_info.analytic_findings.includes(new_finding)) {
          file_info.analytic_findings.push(new_finding);
        }
      }
    }

    var cms_regex = /cmd\s+(?:\/\w\s+)?([a-z0-9]+)\s+[^\s\)]+/gmi;
    var cmd_match = cms_regex.exec(macro_string);
    while (cmd_match !== null) {
      if (/((?:https?\:\/\/|\\\\)[^\s\)]+)/gmi.test(cmd_match[0])) {
        if (cmd_match[1] == "mshta") {
          new_finding = "SUSPICIOUS - Mshta Command Used to Load Internet Hosted Resource";
          if (!file_info.analytic_findings.includes(new_finding)) {
            file_info.analytic_findings.push(new_finding);
          }
        }
      }

      cmd_match = cms_regex.exec(macro_string);
    }

    file_info = this.search_for_iocs(macro_string, file_info);

    return file_info;
  }

  /**
   * Extracts meta data and other information from .exe executable files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_exe(file_bytes) {
    var file_info = this.get_default_file_json();

    file_info.file_format = "exe";
    file_info.file_generic_type = "Executable";

    // Header offset starts at 3C / 60
    var header_offset = this.get_two_byte_int(file_bytes.slice(60,62), this.LITTLE_ENDIAN);

    // Get compile time
    var compile_time_offset = header_offset + 8;
    var compile_timestamp_int = this.get_four_byte_int(file_bytes.slice(compile_time_offset,compile_time_offset+4), this.LITTLE_ENDIAN);
    var compile_timestamp = new Date(compile_timestamp_int*1000);
    file_info.metadata.creation_date = compile_timestamp.toISOString().slice(0, 19).replace("T", " ");;

    return file_info;
  }

  /**
   * Extracts meta data and other information from gz archive files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_gz(file_bytes) {
    var file_info = this.get_default_file_json();

    file_info.file_format = "gz";
    file_info.file_generic_type = "File Archive";

    // This format does not support encryption
    file_info.file_encrypted = "false";
    file_info.file_encryption_type = "none";

    return file_info;
  }

  /**
   * Extracts meta data and other information from .iso image files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_iso9660(file_bytes, file_text="") {
    var file_info = this.get_default_file_json();

    file_info.file_format = "iso";
    file_info.file_generic_type = "File Archive";

    // Check for El Torito format
    if (this.array_equals(file_bytes.slice(34821,34832), [49,1,69,76,32,84,79,82,73,84,79])) {
      file_info.file_format_ver = "El Torito V1";

      // This format does not support encryption
      file_info.file_encrypted = "false";
      file_info.file_encryption_type = "none";
    } else {
      // If the file text is not given, generate it from the bytes
      if (file_text.length == 0) {
        file_text = Static_File_Analyzer.get_ascii(file_bytes);
      }

      var domain_identifier_suffix_start = file_text.indexOf("*OSTA UDF Compliant");
      if (domain_identifier_suffix_start > 0) {
        var udf_version_bytes = file_bytes.slice(domain_identifier_suffix_start + 23, domain_identifier_suffix_start + 25);
        var udf_version_str = udf_version_bytes[0].toString();

        if (udf_version_bytes[1] < 10) {
          udf_version_str += ".0" +  udf_version_bytes[1].toString();
        }  else {
          if (udf_version_bytes[1].toString().length = 2) {
            udf_version_str += "." + udf_version_bytes[1].toString();
          } else {
            udf_version_str += "." + udf_version_bytes[1].toString() + "0";
          }
        }


        file_info.file_format_ver = "Universal Disk Format V" + udf_version_str;
      }
    }

    // Cheack creation application
    if (this.array_equals(file_bytes.slice(33342,33349), [73,77,71,66,85,82,78])) {
      var app_version = Static_File_Analyzer.get_ascii(file_bytes.slice(33350,33359)).trim();
      file_info.metadata.creation_application = "ImgBurn " + app_version;
      file_info.metadata.creation_os = "Windows"; // ImgBurn is Windows Only
    }

    return file_info;
  }

  /**
   * Extracts meta data and other information from JPEG image files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_jpeg(file_bytes) {
    var file_info = this.get_default_file_json();

    file_info.file_format = "jpeg";
    file_info.file_generic_type = "Image";
    file_info.file_encrypted = "false";
    file_info.file_encryption_type = "none";

    var jfif_ver_bytes = file_bytes.slice(11,13);
    var jfif_ver_str = jfif_ver_bytes[0].toString();

    if (jfif_ver_bytes[1] < 10) {
      jfif_ver_str += ".0" +  jfif_ver_bytes[1].toString();
    }  else {
      if (jfif_ver_bytes[1].toString().length = 2) {
        jfif_ver_str += "." + jfif_ver_bytes[1].toString();
      } else {
        jfif_ver_str += "." + jfif_ver_bytes[1].toString() + "0";
      }
    }

    file_info.file_format_ver = "JFIF Version " + jfif_ver_str;

    return file_info;
  }

  /**
   * Extracts meta data and other information from PDF files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_pdf(file_bytes, file_text) {
    var file_info = this.get_default_file_json();

    file_info.file_format = "pdf";
    file_info.file_generic_type = "Document";

    var pdf_version_str = Static_File_Analyzer.get_ascii(file_bytes.slice(5,16));
    file_info.file_format_ver = (pdf_version_str.indexOf("%") > 0) ? pdf_version_str.split("%")[0].trim() : pdf_version_str.split("\n")[0].trim();

    // If the file text is not given, generate it from the bytes
    if (file_text.length == 0) {
      file_text = Static_File_Analyzer.get_ascii(file_bytes);
    }

    // Identify Objects and Streams
    var metadata_objs = ["/author", "/creationdate", "/creator", "/moddate", "/producer", "/title"];
    var metadata_obj_found = false;
    var objects_regex = /\d+\s+\d+\s+obj\s+\<\<\s*([^\>]*)\>\>\s*(endobj|stream|trailer|\>\>)/gmi;
    var objects_matches = objects_regex.exec(file_text);

    while (objects_matches != null) {
      if (objects_matches[2] == "endobj" || objects_matches[2] == "trailer") {
        if (metadata_objs.some(v => objects_matches[1].toLowerCase().includes(v))) {
          // Found an object with metadata.
          metadata_obj_found = true;
          var metadata_regex = /\/(Author|CreationDate|Creator|ModDate|Producer|Subject|Title)([^\/\n\r]+)/gmi;
          var metadata_matches = metadata_regex.exec(objects_matches[1]);

          while (metadata_matches != null) {
            var meta_value = metadata_matches[2].trim();
            if (meta_value.substring(0,1) == "(" && meta_value.slice(-1) == ")" ) {
              meta_value = meta_value.slice(1,-1);
            }

            if (metadata_matches[1].toLowerCase() == "author") {
              file_info.metadata.author = meta_value;
            } else if (metadata_matches[1].toLowerCase() == "creationdate") {
              var date_parts = /[Dd]\:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/gm.exec(meta_value);
              if (date_parts != null) {
                  file_info.metadata.creation_date = date_parts[1] + "-" + date_parts[2] + "-" + date_parts[3] + " " + date_parts[4] + ":" + date_parts[5] + ":" + date_parts[6];
              }
            } else if (metadata_matches[1].toLowerCase() == "creator") {
              if (file_info.metadata.author == "unknown") {
                file_info.metadata.author = meta_value.replaceAll("\\(", "(").replaceAll("\\)", ")");
              }
            } else if (metadata_matches[1].toLowerCase() == "moddate") {
              var date_parts = /[Dd]\:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/gm.exec(meta_value);
              if (date_parts != null) {
                  file_info.metadata.last_modified_date = date_parts[1] + "-" + date_parts[2] + "-" + date_parts[3] + " " + date_parts[4] + ":" + date_parts[5] + ":" + date_parts[6];
              }
            } else if (metadata_matches[1].toLowerCase() == "producer") {
              var creation_os_match = meta_value.match(/(\w+\s+\w+\s+\d+\.\d+\.\d+\s+(?:Build\s[0-9-a-zA-Z]+)?)/gm);
              if (creation_os_match != null) {
                file_info.metadata.creation_os = creation_os_match[0];
                file_info.metadata.creation_application = meta_value.split("/")[0].trim();
              } else {
                file_info.metadata.creation_application = meta_value;
              }
            } else if (metadata_matches[1].toLowerCase() == "subject") {
              file_info.metadata.description = meta_value;
            } else if (metadata_matches[1].toLowerCase() == "title") {
              file_info.metadata.title = meta_value;
            }

            metadata_matches = metadata_regex.exec(objects_matches[1]);
          }
        }
      } else if (objects_matches[2] == "stream") {
        var start_index = objects_matches.index + objects_matches[0].length;
        var end_index = file_text.indexOf("endstream", start_index);
        var stream_text = file_text.substring(start_index, end_index);

        // Check for CVE-2019-7089 Ref: https://insert-script.blogspot.com/2019/01/adobe-reader-pdf-callback-via-xslt.html
        var cve_match = stream_text.match(/\<\?\s*xml\-stylesheet\s*([^\>]+)\?\>/gmi);
        if (cve_match !== null) {
          var href_unc_match = /href\s*\=\s*[\"\'](\\\\[^\'\"]+)[\"\']/gmi.exec(cve_match[0]);
          if (href_unc_match !== null) {
            file_info.analytic_findings.push("MALICIOUS - CVE-2019-7089 Exploit Found");
            file_info.iocs.push(href_unc_match[1]);
          }
        }
      } else if (objects_matches[2] == ">>") {
        // Nested OBJ
        // Check for CVE-2018-4993 Ref: https://github.com/deepzec/Bad-Pdf/blob/master/badpdf.py
        var cve_match = /\/AA\s*\<\<\s*\/O\s*\<\<\s*\/F\s*\(\s*((?:\\{2,4}|https?\:\/\/)(?:[a-zA-Z0-9]+[\.\:]?)+\\*\s*)\s*\)\s*\/D\s*[^\n\r]+\s+\/S\s*\/GoToE/gmi.exec(objects_matches[1]);
        if (cve_match !== null) {
          file_info.analytic_findings.push("MALICIOUS - CVE-2018-4993 Exploit Found");
          file_info.iocs.push(cve_match[1]);
        }
      }

      // TODO push streams to file_components
      //file_info.file_components.push({});
      objects_matches = objects_regex.exec(file_text);
    }

    // Look for embedded scripts
    var script_regex = /\/(S|JavaScript|JS)\s*\(/gmi;
    var script_matches = script_regex.exec(file_text);

    while (script_matches != null) {
      var script_start = script_matches.index + script_matches[0].length;
      var script_end = file_text.indexOf(">>", script_start);
      var script_text = file_text.substring(script_start, script_end).trim();
      var script_type = "unknown";

      if (script_text.slice(-1) == ")") {
        script_text = script_text.slice(0,-1);
      }

      file_info.scripts.extracted_script += script_text + "\n\n";

      if (script_matches[1].toLowerCase() == "js" || script_matches[1].toLowerCase() == "javascript") {
        file_info.scripts.script_type = "JavaScript";
      }

      script_matches = script_regex.exec(file_text);
    }

    if (metadata_obj_found == false) {
      // Backup method to extract meta data, this need refining.

      // RDF Meta data
      file_info.metadata.creation_application = this.get_xml_tag_content(file_text, "xmp:CreatorTool", 0);
      if (file_info.metadata.creation_application == "unknown") {
        file_info.metadata.creation_application = this.get_xml_tag_content(file_text, "pdf:Producer", 0);
      }

      file_info.metadata.creation_date = this.get_xml_tag_content(file_text, "xmp:CreateDate", 0);
      file_info.metadata.last_modified_date = this.get_xml_tag_content(file_text, "xmp:ModifyDate", 0);
      file_info.metadata.author = this.get_xml_tag_content(file_text, "dc:creator", 0);
      file_info.metadata.author = file_info.metadata.author.replace(/\<\/?\w+\:?\w+\>/gm, "").trim(); //Remove XML tags from author string

      // Meta data tags
      var tag_matches = /\<\<\s*\/(?:[Cc]reator|[Cc]reationDate|[Pp]roducer|[Mm]od[Dd]ate)/gm.exec(file_text);

      if (tag_matches != null) {
        var meta_tag_start = tag_matches.index;
        var meta_tag_end = file_text.indexOf(">>", meta_tag_start);
        var meta_tag_text = file_text.substring(meta_tag_start, meta_tag_end+2);

        var producer_tag_start = meta_tag_text.indexOf("/Producer");
        var producer_tag_end = meta_tag_text.indexOf("/", producer_tag_start+9);
        if (producer_tag_end < 0) producer_tag_end = meta_tag_text.indexOf(">>", producer_tag_start);
        var producer_tag_text = meta_tag_text.substring(producer_tag_start+9, producer_tag_end);
        producer_tag_text = producer_tag_text.replace(/(?:\\\(|\\\))/gm, "").trim();

        var creation_os_match = producer_tag_text.match(/(\w+\s+\w+\s+\d+\.\d+\.\d+\s+(?:Build\s[0-9-a-zA-Z]+)?)/gm);
        if (creation_os_match != null) {
          file_info.metadata.creation_os = creation_os_match[0];
          file_info.metadata.creation_application = producer_tag_text.split("/")[0].trim();
        }

        var creator_tag_matches = /\/[Cc]reator(.+)\n?\/(?:[Pp]roducer|[Cc]reation[Dd]ate|[Mm]odDate|\>\>)/gm.exec(meta_tag_text);
        if (creator_tag_matches != null) {
          file_info.metadata.author = creator_tag_matches[1].trim();

          // Check to see if any other tags were included
           var extra_tag_matches = /\/(?:[Pp]roducer|[Cc]reation[Dd]ate|[Mm]od[Dd]ate)/gm.exec(file_info.metadata.author);
           if (extra_tag_matches != null) {
             file_info.metadata.author = file_info.metadata.author.substring(0,extra_tag_matches.index);
           }
        } else {
          var creator_tag_start = meta_tag_text.indexOf("/Creator");
          var creator_tag_end = meta_tag_text.indexOf("/", creator_tag_start+8);
          if (creator_tag_end < 0) creator_tag_end = meta_tag_text.indexOf(">>", creator_tag_start);
          var creator_tag_text = meta_tag_text.substring(creator_tag_start+8, creator_tag_end);
          file_info.metadata.author = creator_tag_text.trim();
        }

        file_info.metadata.author = file_info.metadata.author.replaceAll(/\\\(/gm, "(");
        file_info.metadata.author = file_info.metadata.author.replaceAll(/\\\)/gm, ")");

        var creation_date_tag_start = meta_tag_text.indexOf("/CreationDate");
        var creation_date_tag_end = meta_tag_text.indexOf("/", creation_date_tag_start+13);
        if (creation_date_tag_end < 0) creation_date_tag_end = meta_tag_text.indexOf(">>", creation_date_tag_start);
        var creation_date_tag_text = meta_tag_text.substring(creation_date_tag_start+13, creation_date_tag_end);
        var date_parts = /\([Dd]\:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/gm.exec(creation_date_tag_text);

        if (date_parts != null) {
            file_info.metadata.creation_date = date_parts[1] + "-" + date_parts[2] + "-" + date_parts[3] + " " + date_parts[4] + ":" + date_parts[5] + ":" + date_parts[6];
        }

        if (file_info.metadata.creation_os != "unknown") {
          var os_start = file_info.metadata.creation_application.indexOf(file_info.metadata.creation_os);
          file_info.metadata.creation_application = file_info.metadata.creation_application.substring(os_start + file_info.metadata.creation_os.length).trim();
          file_info.metadata.creation_application = file_info.metadata.creation_application.replace(/\)$/gm, "");
        }
      }
    }

    // Extract more meta data from what we have already collected.
    if (file_info.metadata.creation_application.indexOf("Macintosh") > 0 || file_info.metadata.author.indexOf("Macintosh") > 0 ) {
      file_info.metadata.creation_os = "macOS";
    }

    return file_info;
  }

  /**
   * Extracts meta data and other information from PNG image files.
   *
   * @see http://www.libpng.org/pub/png/spec/1.2/PNG-Chunks.html
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_png(file_bytes, file_text) {
    var file_info = this.get_default_file_json();

    file_info.file_format = "png";
    file_info.file_generic_type = "Image";
    file_info.file_encrypted = "false";
    file_info.file_encryption_type = "none";

    // get tEXt chunks
    var search_index = 8;
    while (search_index > 0) {
      search_index = file_text.indexOf("tEXt", search_index);
      if (search_index > 0) {
        var chunk_length_bytes = file_bytes.slice(search_index-4,search_index);
        var chunk_length_int = this.get_four_byte_int(chunk_length_bytes);
        var content_bytes = file_bytes.slice(search_index+4, search_index+chunk_length_int+4);
        var chunk_text = file_text.substring(search_index+4,(search_index+chunk_length_int+4));
        var split_index = content_bytes.indexOf(0);

        var chunk_keyword = chunk_text.substring(0,split_index).trim();
        var chunk_text_val = chunk_text.substring(split_index+1).trim();

        if (chunk_keyword.toLowerCase() == "author") {
          file_info.metadata.author = chunk_text_val;
        } else if (chunk_keyword.toLowerCase() == "comment") {
          // not implemented
          var comment = chunk_text_val;
        } else if (chunk_keyword.toLowerCase() == "copyright") {
          // not implemented
          var copyright = chunk_text_val;
        } else if (chunk_keyword.toLowerCase() == "creation time") {
          file_info.metadata.creation_date = chunk_text_val;
        } else if (chunk_keyword.toLowerCase() == "description") {
          file_info.description = chunk_text_val;
        } else if (chunk_keyword.toLowerCase() == "disclaimer") {
          // not implemented
          var disclaimer = chunk_text_val;
        } else if (chunk_keyword.toLowerCase() == "software") {
          file_info.metadata.creation_application = chunk_text_val;
        } else if (chunk_keyword.toLowerCase() == "source") {
          file_info.metadata.creation_os = chunk_text_val;
        } else if (chunk_keyword.toLowerCase() == "title") {
          file_info.metadata.title = chunk_text_val;
        } else if (chunk_keyword.toLowerCase() == "warning") {
          // not implemented
          var warning = chunk_text_val;
        }

        search_index = file_text.indexOf("tEXt", search_index+chunk_length_int);
      } else {
        break;
      }
    }

    return file_info;
  }

  /**
   * Extracts meta data and other information from RAR archive files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_rar(file_bytes) {
    var file_info = this.get_default_file_json();

    file_info.file_format = "rar";
    file_info.file_generic_type = "File Archive";

    // Format version
    if (file_bytes[6] == 1) {
      file_info.file_format_ver = "5+";
    } else {
      file_info.file_format_ver = "1.5 to 4.0";
    }

    // OS the file was created in //currently wrong bits
    if (file_bytes[24] == 0) {
      file_info.metadata.creation_os = "Windows";
    } else if (file_bytes[24] == 1) {
      file_info.metadata.creation_os = "Unix";
    }

    return file_info;
  }

  /**
   * Extracts meta data and other information from RTF document files.
   *
   * @see http://www.snake.net/software/RTF/RTF-Spec-1.7.pdf
   * @see https://www.mandiant.com/resources/how-rtf-malware-evad
   * @see https://blog.talosintelligence.com/2017/03/how-malformed-rtf-defeats-security.html
   * @see https://www.decalage.info/rtf_tricks
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_rtf(file_bytes, file_text) {
    // Get ASCII and Unicode translation of bytes.
    var file_text_unicode = Static_File_Analyzer.get_string_from_array(file_bytes);
    var file_text_ascii = Static_File_Analyzer.get_ascii(file_bytes);

    var file_info = this.get_default_file_json();

    file_info.file_format = "rtf";
    file_info.file_generic_type = "Document";
    file_info.file_encrypted = "false";
    file_info.file_encryption_type = "none";

    if (file_text_unicode != file_text_ascii) {
      file_info.analytic_findings.push("SUSPICIOUS - Non-ASCII characters detected");
    }

    // Read RTF header
    var header_match = /\\(rt[a-zA-Z]*)([0-9]+)/gmi.exec(file_text_ascii);
    if (header_match !== null) {
      if (header_match[1] != "rtf") {
        // Malformed header
        file_info.analytic_findings.push("SUSPICIOUS - Malformed RTF header: " + header_match[1]);
      }

      if (header_match[2] != "1") {
        // Invalid RTF version
        file_info.analytic_findings.push("SUSPICIOUS - Invalid RTF Version: " + header_match[2]);
      } else {
        file_info.file_format_ver = "1";
      }
    }

    // Look for metadata
    var doc_title_match = /\{\s*\\title\s+([^\}]+)/gmi.exec(file_text_ascii);
    file_info.metadata.title = (doc_title_match !== null) ? doc_title_match[1] : "none";

    var doc_subject_match = /\{\s*\\subject\s+([^\}]+)/gmi.exec(file_text_ascii);
    file_info.metadata.description = (doc_subject_match !== null) ? doc_subject_match[1] : "none";

    var doc_author_match = /\{\s*\\author\s+([^\}]+)/gmi.exec(file_text_ascii);
    file_info.metadata.author = (doc_author_match !== null) ? doc_author_match[1] : "none";

    var doc_operator_match = /\{\s*\\operator\s+([^\}]+)/gmi.exec(file_text_ascii);
    var doc_operator = (doc_operator_match !== null) ? doc_operator_match[1] : "none";
    file_info.metadata.author = (doc_operator != file_info.metadata.author) ? (file_info.metadata.author + " and " + doc_operator) : file_info.metadata.author;

    var doc_creation_match = /\{\s*\\creatim\s*(?:\\yr([0-9]{2,4})\s*)?(?:\\mo([0-9]{1,2})\s*)?(?:\\dy([0-9]{1,2})\s*)?(?:\\hr([0-9]{1,2})\s*)?(?:\\min([0-9]{1,2}))?/gmi.exec(file_text_ascii);
    if (doc_creation_match !== null) {
      var create_year  = (doc_creation_match[1] !== null) ? doc_creation_match[1] : "0000";
      var create_month = (doc_creation_match[2] !== null) ? doc_creation_match[2] : "00";
      var create_day   = (doc_creation_match[3] !== null) ? doc_creation_match[3] : "00";
      var create_hour  = (doc_creation_match[4] !== null) ? doc_creation_match[4] : "00";
      var create_min   = (doc_creation_match[5] !== null) ? doc_creation_match[5] : "00";

      create_month = (create_month.length == 1) ? "0" + create_month : create_month;
      create_day   = (create_day.length == 1) ? "0" + create_day : create_day;
      create_hour  = (create_hour.length == 1) ? "0" + create_hour : create_hour;
      create_min   = (create_min.length == 1) ? "0" + create_min : create_min;

      file_info.metadata.creation_date = create_year + "-" + create_month + "-" + create_day + " " + create_hour + ":" + create_min + ":00";
    }

    var doc_modified_match = /\{\s*\\revtim\s*(?:\\yr([0-9]{2,4})\s*)?(?:\\mo([0-9]{1,2})\s*)?(?:\\dy([0-9]{1,2})\s*)?(?:\\hr([0-9]{1,2})\s*)?(?:\\min([0-9]{1,2}))?/gmi.exec(file_text_ascii);
    if (doc_modified_match !== null) {
      var mod_year  = (doc_modified_match[1] !== null) ? doc_modified_match[1] : "0000";
      var mod_month = (doc_modified_match[2] !== null) ? doc_modified_match[2] : "00";
      var mod_day   = (doc_modified_match[3] !== null) ? doc_modified_match[3] : "00";
      var mod_hour  = (doc_modified_match[4] !== null) ? doc_modified_match[4] : "00";
      var mod_min   = (doc_modified_match[5] !== null) ? doc_modified_match[5] : "00";

      mod_month = (mod_month.length == 1) ? "0" + mod_month : mod_month;
      mod_day   = (mod_day.length == 1) ? "0" + mod_day : mod_day;
      mod_hour  = (mod_hour.length == 1) ? "0" + mod_hour : mod_hour;
      mod_min   = (mod_min.length == 1) ? "0" + mod_min : mod_min;

      file_info.metadata.last_modified_date = mod_year + "-" + mod_month + "-" + mod_day + " " + mod_hour + ":" + mod_min + ":00";
    }

    var doc_creation_app_match = /\\xml[0-9a-z]*\s*https?\:\/\/schemas\.microsoft\.com\/office\/word\//gmi.exec(file_text_ascii);
    if (doc_creation_app_match !== null) {
      file_info.metadata.creation_application = "Microsoft Word";
    }

    // Look for Hex data
    var hex_data_regex = /(\\[a-zA-Z0-9]+)?[\s\r\n\-]([a-fA-F0-9]+[\s\r\n]*)+[\s\}\\]/gm;
    var hex_data_match = hex_data_regex.exec(file_text_ascii);

    while (hex_data_match != null) {
      var hex_data = hex_data_match[0].replace(/[^0-9A-Fa-f]/g, '');

      // Microsoft Word allows an extra hex digit, which if present it ignores.
      if (hex_data.length & 1) {
        // Odd hex length trim hex data.
        hex_data = hex_data.slice(0,-1);
      }

      // Convert to array
      var hex_bytes = Array(hex_data.length/2);
      hex_bytes[0] = Number("0x" + hex_data.substring(0,2));

      for (var bi=2; bi<hex_data.length; bi+=2) {
        hex_bytes[bi/2] = Number("0x" + hex_data.substring(bi,bi+2));
      }

      // Do basic checks to see if the hex data is an OLE Object.
      var format_id = [Number("0x" + hex_data.substring(4,6)), Number("0x" + hex_data.substring(6,8))];

      var test_ascii = Static_File_Analyzer.get_ascii(hex_bytes.slice(0, (hex_bytes.length < 256) ? hex_bytes.length : 256));
      if (/equation[^\d]+3/gmi.test(test_ascii)) {
        file_info.analytic_findings.push("MALICIOUS - CVE-2017-11882 Exploit Found");
      }

      hex_data_match = hex_data_regex.exec(file_text_ascii);
    }

    return file_info;
  }

  /**
   * Extracts IoCs and suspicious and malicious indicators from VBA code.
   *
   * @param {String} vba_code VBA code in string format.
   * @param  {{{'type': String, 'doc_obj': Obj}} document_obj Document object
   * @return {JSON}  Object with findings
   */
  analyze_vba(file_info, document_obj) {
    var vba_code = file_info.scripts.extracted_script;

    // All document types
    var doc_property_regex = /(?:([^\s\n\r]+)\s*\=\s*)?ActiveWorkbook\.BuiltinDocumentProperties\s*\(\s*([^\)]+)\s*\)/gmi;
    var doc_property_match = doc_property_regex.exec(vba_code);

    while (doc_property_match !== null) {
      var property_name = "";
      var property_val = "";

      if (doc_property_match[2].startsWith("\"")) {
        // Literal value
        property_name = doc_property_match[2].slice(1,-1);
      } else {
        // Varable value
      }

      if (property_name.toLowerCase() == "author") {
        property_val = document_obj.document_properties.author;
      } else if (property_name.toLowerCase() == "comments") {
        property_val = document_obj.document_properties.comments;
      } else if (property_name.toLowerCase() == "keywords") {
        property_val = document_obj.document_properties.keywords;
      } else if (property_name.toLowerCase() == "subject") {
        property_val = document_obj.document_properties.subject;
      } else if (property_name.toLowerCase() == "title") {
        property_val = document_obj.document_properties.title;
      }

      var comment_insert_loc = vba_code.indexOf("\n", doc_property_match.index+doc_property_match[0].length);
      var comment = (doc_property_match[1] !== null && doc_property_match[1] !== undefined) ? doc_property_match[1] + " = " : "";
      comment = "'🦈 " + comment + property_val + "\n";
      file_info.scripts.extracted_script = file_info.scripts.extracted_script.substring(0,comment_insert_loc) + comment + file_info.scripts.extracted_script.substring(comment_insert_loc);
      vba_code = file_info.scripts.extracted_script;

      doc_property_match = doc_property_regex.exec(vba_code);
    }

    if (document_obj.type.toLowerCase() == "spreadsheet") {
      var cell_range_regex = /(?:([^\s]+)\s*\=\s*)ActiveWorkbook\.Worksheets\s*\(([^\)]+)\)\.Range\s*\(([^\)]+)\)/gmi;
      var cell_range_match = cell_range_regex.exec(vba_code);
      var sheet_name;
      var range_val;

      while (cell_range_match !== null) {
        if (cell_range_match[2].startsWith("\"")) {
          // Literal value
          sheet_name = cell_range_match[2].slice(1,-1);
        } else {
          // Varable value
        }

        if (cell_range_match[3].startsWith("\"")) {
          // Literal value
          range_val = cell_range_match[3].slice(1,-1);
        } else {
          // Varable value
        }

        var range_match = /([a-zA-Z]+)([0-9]+)\:([a-zA-Z]+)([0-9]+)/gm.exec(range_val);
        if (range_match !== null && (range_match[1] == range_match[3] || range_match[2] == range_match[4])) {
          // Single dimension array
          document_obj.varables[cell_range_match[1]] = [];
          var return_array = [];
          var cell_ref;
          var cell_value;

          if (range_match[2] == range_match[4]) {
            // Change columns
            var current_col = range_match[1];
            cell_ref = current_col + range_match[2];
            cell_value = (document_obj.sheets[sheet_name].data.hasOwnProperty(cell_ref)) ? document_obj.sheets[sheet_name].data[cell_ref].value : "";
            return_array.push(cell_value);
            document_obj.varables[cell_range_match[1]].push((document_obj.sheets[sheet_name].data.hasOwnProperty(cell_ref)) ? document_obj.sheets[sheet_name].data[cell_ref] : "");

            while (current_col != range_match[3]) {
              current_col = this.increment_xls_column(current_col);
              cell_ref = current_col + range_match[2];
              cell_value = (document_obj.sheets[sheet_name].data.hasOwnProperty(cell_ref)) ? document_obj.sheets[sheet_name].data[cell_ref].value : "";
              return_array.push(cell_value);
              document_obj.varables[cell_range_match[1]].push((document_obj.sheets[sheet_name].data.hasOwnProperty(cell_ref)) ? document_obj.sheets[sheet_name].data[cell_ref] : "");
            }
          } else {
            // Change rows
            for (var i=parseInt(range_match[2]); i<=parseInt(range_match[4]); i++) {
              cell_ref = range_match[1] + i;
              cell_value = (document_obj.sheets[sheet_name].data.hasOwnProperty(cell_ref)) ? document_obj.sheets[sheet_name].data[cell_ref].value : "";
              return_array.push(cell_value);
              document_obj.varables[cell_range_match[1]].push((document_obj.sheets[sheet_name].data.hasOwnProperty(cell_ref)) ? document_obj.sheets[sheet_name].data[cell_ref] : "");
            }
          }

          var comment_insert_loc = vba_code.indexOf("\n", cell_range_match.index+cell_range_match[0].length);
          var comment = (cell_range_match[1] !== null && cell_range_match[1] !== undefined) ? cell_range_match[1] + " = " : "";
          comment = "'🦈 " + comment + JSON.stringify(return_array) + "\n";
          file_info.scripts.extracted_script = file_info.scripts.extracted_script.substring(0,comment_insert_loc) + comment + file_info.scripts.extracted_script.substring(comment_insert_loc);
          vba_code = file_info.scripts.extracted_script;
        }

        cell_range_match = cell_range_regex.exec(cell_range_regex);
      }

      var creat_object_regex = /CreateObject\s*\(\s*([^\s]+)\s*\)/gmi;
      var create_object_match = creat_object_regex.exec(vba_code);

      while (create_object_match !== null) {
        var new_object_type;

        if (create_object_match[1].startsWith("\"")) {
          // Literal value
          new_object_type = create_object_match[1].slice(1,-1);
        } else {
          // String value
          new_object_type = create_object_match[1].split(".");

          if (document_obj.varables.hasOwnProperty(new_object_type[0])) {
            var varable_obj = document_obj.varables[new_object_type[0]];

            if (new_object_type.length > 1) {
              var item_index_match = /Item\s*\((\d+)\s*\)/gmi.exec(new_object_type[1]);
              if (item_index_match !== null) {
                varable_obj = varable_obj[item_index_match[1]-1];
              }

              if (new_object_type.length > 2) {
                if (new_object_type[2].toLowerCase() == "value" && varable_obj.hasOwnProperty("value")) {
                  new_object_type = varable_obj.value;
                }
              } else {
                new_object_type = varable_obj;
              }
            } else {
              new_object_type = varable_obj[0];
            }
          }
        }

        var suspicious_objects = ["ADODB.Stream","MSXML2.ServerXMLHTTP.6.0","Msxml2.XMLHTTP.6.0"];
        if (suspicious_objects.includes(new_object_type)) {
          var new_finding = "SUSPICIOUS - Creation of " + new_object_type + " VBA Object Type";
          if (!file_info.analytic_findings.includes(new_finding)) {
            file_info.analytic_findings.push(new_finding);
          }
        }

        create_object_match = creat_object_regex.exec(vba_code);
      }

      var shell_regex = /Shell\s*\(\s*([^\)]+)\s*\)/gmi;
      var shell_match = shell_regex.exec(vba_code);
      var shell_command;

      while (shell_match !== null) {
        var new_finding = "SUSPICIOUS - VBA Macro Calls Shell Command";
        if (!file_info.analytic_findings.includes(new_finding)) {
          file_info.analytic_findings.push(new_finding);
        }

        if (shell_match[1].startsWith("\"")) {
          // Literal value
          shell_command = shell_match[1].slice(1,-1);
        } else {
          // Varable value, find definition.
          var shell_var_regex  = new RegExp("\\.saveToFile\\s+" + shell_match[1], "gm");
          var shell_var_match = shell_var_regex.exec(vba_code);

          if (shell_var_match !== null) {
            var new_finding = "SUSPICIOUS - Shell Execution of a Downloaded File";
            if (!file_info.analytic_findings.includes(new_finding)) {
              file_info.analytic_findings.push(new_finding);
            }
          }
        }

        // multiple vars, resolve their values
        var comp_var_regex = /(\"[^\"]+\"|[\w\d]+)\s*([\+\-\*\\\%\^\&])?/gm;
        var comp_var_match = comp_var_regex.exec(shell_match[1]);
        var comp_result = "";

        while (comp_var_match !== null) {
          // Get varable value
          var shell_var_regex  = new RegExp(comp_var_match[1] + "\\s*\\=\\s*(\\\"?[^\\n\\r\\\"]+\\\"?)", "gm");
          var shell_var_match = shell_var_regex.exec(vba_code);

          if (shell_var_match !== null) {
            if (shell_var_match[1].startsWith("\"")) {
              // Literal value
              comp_result += shell_var_match[1].slice(1,-1);
            }

          }

          comp_var_match = comp_var_regex.exec(shell_match[1]);
        }

        if (comp_result.length > 0) {
          var comment_insert_loc = vba_code.indexOf("\n", shell_match.index);
          comment = "'🦈 Shell(\"" + comp_result + "\")\n";
          file_info.scripts.extracted_script = file_info.scripts.extracted_script.substring(0,comment_insert_loc) + comment + file_info.scripts.extracted_script.substring(comment_insert_loc);
        }

        shell_match = shell_regex.exec(vba_code);
      }
    }

    var analyzed_results = this.analyze_embedded_script(file_info.scripts.extracted_script);

    for (var f=0; f<analyzed_results.findings.length; f++) {
      if (!file_info.analytic_findings.includes(analyzed_results.findings[f])) {
        file_info.analytic_findings.push(analyzed_results.findings[f]);
      }
    }

    for (var f=0; f<analyzed_results.iocs.length; f++) {
      if (!file_info.iocs.includes(analyzed_results.iocs[f])) {
        file_info.iocs.push(analyzed_results.iocs[f]);
      }
    }

  }

  /**
   * Extracts meta data and other information from Excel Binary File Format (.xls) files.
   *
   * @see https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/cd03cb5f-ca02-4934-a391-bb674cb8aa06
   * @see https://www.loc.gov/preservation/digital/formats/fdd/fdd000510.shtml
   * @see https://blog.reversinglabs.com/blog/excel-4.0-macros
   * @see http://www.openoffice.org/sc/compdocfileformat.pdf
   * @see https://inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files
   * @see https://docs.microsoft.com/en-us/previous-versions/office/developer/office-2010/gg615597(v=office.14)
   * @see https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/43684742-8fcd-4fcd-92df-157d8d7241f9
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_xls(file_bytes) {
    var file_info = this.get_default_file_json();

    file_info.file_format = "xls";
    file_info.file_generic_type = "Spreadsheet";

    // Variables to load spreadsheet into mem.
    var sheet_index_list = []; // Indexed list of sheet names.
    var spreadsheet_sheet_names = {};
    var string_constants = Array();
    var spreadsheet_defined_vars = {};
    var spreadsheet_var_names = [];
    var downloaded_files = [];
    var document_properties = {};

    var document_obj = {
      'type': "spreadsheet",
      'document_properties': document_properties,
      'sheets': spreadsheet_sheet_names,
      'current_sheet_name': "",
      'current_cell': "",
      'varables': spreadsheet_defined_vars,
      'recalc_objs': []
    };

    var cmb_obj = this.parse_compound_file_binary(file_bytes);

    for (var c=0; c<cmb_obj.entries.length; c++) {
      if (cmb_obj.entries[c].entry_name.toLowerCase() != "root entry") {
        file_info.file_components.push({
          'name': cmb_obj.entries[c].entry_name,
          'type': "cfb"
        });
      }

      if (cmb_obj.entries[c].entry_name.toLowerCase() == "summaryinformation") {
        document_properties = cmb_obj.entries[c].entry_properties;
        var creation_os = "unknown";

        if (document_properties.hasOwnProperty("os")) {
          creation_os = document_properties.os + " " + (document_properties.hasOwnProperty("os_version") ? document_properties.os_version : "");
        }

        file_info.metadata.author = (document_properties.hasOwnProperty("author")) ? document_properties.author : "unknown";
        file_info.metadata.creation_application = (document_properties.hasOwnProperty("creating_application")) ? document_properties.creating_application : "unknown";
        file_info.metadata.creation_os = creation_os;
        file_info.metadata.creation_date = (document_properties.hasOwnProperty("create_date")) ? document_properties.create_date : "0000-00-00 00:00:00";
        file_info.metadata.description = (document_properties.hasOwnProperty("subject")) ? document_properties.subject : "unknown";
        file_info.metadata.last_modified_date = (document_properties.hasOwnProperty("last_saved")) ? document_properties.last_saved : "0000-00-00 00:00:00";
        file_info.metadata.title = (document_properties.hasOwnProperty("title")) ? document_properties.title : "unknown";
      } else if (cmb_obj.entries[c].entry_name.toLowerCase() == "worddocument") {
        file_info.file_format = "doc";
        file_info.file_generic_type = "Document";
      } else if (cmb_obj.entries[c].entry_name.toLowerCase() == "workbook") {
        file_info.file_format = "xls";
        file_info.file_generic_type = "Spreadsheet";
      }
    }

    var current_byte = 0;

    file_info.file_format_ver = cmb_obj.format_version_major;
    var byte_order = cmb_obj.byte_order; // Byte order LITTLE_ENDIAN or BIG_ENDIAN
    var sector_size = cmb_obj.sector_size; // Size in bytes

    var number_of_directory_sectors = this.get_four_byte_int(file_bytes.slice(40,44), byte_order);
    var number_of_sectors = this.get_four_byte_int(file_bytes.slice(44,48), byte_order);
    var sec_id_1 = this.get_four_byte_int(file_bytes.slice(48,52), byte_order);
    var min_stream_size = this.get_four_byte_int(file_bytes.slice(56,60), byte_order);
    var short_sec_id_1 = this.get_four_byte_int(file_bytes.slice(60,64), byte_order);
    var number_of_short_sectors = this.get_four_byte_int(file_bytes.slice(64,68), byte_order);
    var master_sector_id_1 = this.get_four_byte_int(file_bytes.slice(68,72), byte_order);
    var number_of_master_sectors = this.get_four_byte_int(file_bytes.slice(72,76), byte_order);

    var sec_1_pos = 512 + (sec_id_1 * sector_size); // Should be Root Entry
    var workbook_pos = sec_1_pos + 128;
    var summary_info_pos = workbook_pos + 128;
    var doc_summary_info_pos = summary_info_pos + 128;

    if (this.array_equals(file_bytes.slice(workbook_pos, workbook_pos+13),[0x45,0x00,0x6E,0x00,0x63,0x00,0x72,0x00,0x79,0x00,0x70,0x00,0x74])) {
      file_info.file_encrypted = "true";
    } else {
      file_info.file_encrypted = "false";
    }

    // Find BOF - Beginning of file record
    for (var i=sector_size; i<file_bytes.length; i++) {
      if (file_bytes[i] == 0x09 && file_bytes[i+1] == 0x08) {
        // Found Beginning of file record.
        current_byte = i;
        break;
      }
    }

    if (file_bytes[current_byte] == 0x09) {
      // Beginning of file record found.

      // BIFF 5 and 7 has a length of 8 bytes. For BIFF 8, the length of the BOF record can be either 8 or 16 bytes.
      var biff_record_length = this.get_two_byte_int(file_bytes.slice(current_byte+2,current_byte+4), byte_order);

      // Byte value of 5 representing BIFF 5/7 and 6 representing BIFF 8.
      var biff_version = file_bytes[current_byte+5];
      var xlm_val = file_bytes.slice(current_byte+6,current_byte+8);

      if (this.array_equals(xlm_val, [40,0])) {
        // Excel 4.0 macro sheet
        file_info.scripts.script_type = "Excel 4.0 Macro";
      }

      current_byte += 8;

      var rup_build = this.get_two_byte_int(file_bytes.slice(current_byte,current_byte+=2), byte_order);
      var rup_year = this.get_two_byte_int(file_bytes.slice(current_byte,current_byte+=2), byte_order);

      // Other meta data we are skipping for now.
      // See: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/91ebafbe-ccc0-41a4-839d-15bbec175b9f
      current_byte += 8;

      // stream_start is the offset within the whole file for lbPlyPos / sheet stream_pos.
      var stream_start = current_byte;

      // Find boundsheets
      for (var i=current_byte; i<file_bytes.length; i++) {
        if (file_bytes[i] == 133 && file_bytes[i+1] == 0 && file_bytes[i+3] == 0 && file_bytes[i+2] > 0 && file_bytes[i+2] < 137) {
          // Found boundsheet
          var boundsheet_length = file_bytes[i+2];
          var stream_pos = this.get_four_byte_int(file_bytes.slice(i+4,i+8), byte_order);

          // 0 - visible, 1 - hidden, 2 - very hidden.
          var sheet_state_val = file_bytes[i+8];

          // Some malicious Excel files will have unused bits set that are part of this byte.
          sheet_state_val = this.get_int_from_bin(this.get_binary_array([sheet_state_val]).slice(-2));
          var sheet_state = (sheet_state_val == 1) ? "hidden" : ((sheet_state_val == 1) ? "very hidden": "visible");

          // 0 - Worksheet or dialog sheet, 1 - Macro sheet, 2 - Chart sheet, 6 - VBA module
          var sheet_type = file_bytes[i+8];
          var sheet_name = Static_File_Analyzer.get_string_from_array(file_bytes.slice(i+12, i+boundsheet_length+4));

          spreadsheet_sheet_names[sheet_name] = {
            'name': sheet_name,
            'state': sheet_state,
            'sheet_type': sheet_type,
            'file_pos': stream_pos + stream_start,
            'data': {}
          };

          i += boundsheet_length+3;
        }
      }

      // Sort list by byte position.
      sheet_index_list = Object.entries(spreadsheet_sheet_names);
      sheet_index_list = sheet_index_list.sort((a, b) => a[1].file_pos - b[1].file_pos);

      for (var si=0; si<sheet_index_list.length; si++) {
        sheet_index_list[si] = sheet_index_list[si][0];
      }

      // Find SST - string constants - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/b6231b92-d32e-4626-badd-c3310a672bab
      for (var i=current_byte; i<file_bytes.length; i++) {
        if (file_bytes[i] == 0xFC && file_bytes[i+1] == 0x00) {
          var sst_record_size = this.get_two_byte_int(file_bytes.slice(i+2,i+4), byte_order);

          if (sst_record_size > 0) {
            var cst_total = this.get_four_byte_int(file_bytes.slice(i+4,i+8), byte_order);
            var cst_unique = this.get_four_byte_int(file_bytes.slice(i+8,i+12), byte_order);

            if (cst_unique > cst_total) continue;

            var rgb_bytes = file_bytes.slice(i+12, i+sst_record_size+4);
            var current_unique_offset = 0;

            if (rgb_bytes.length > 0) {
              // See https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/173d9f51-e5d3-43da-8de2-be7f22e119b9
              for (var u=0; u < cst_unique; u++) {
                var char_count = this.get_two_byte_int(rgb_bytes.slice(current_unique_offset, current_unique_offset+2), byte_order);
                var char_prop_bits = this.get_bin_from_int(rgb_bytes[current_unique_offset+2]).reverse();
                var double_byte_chars = (char_prop_bits[0] == 1) ? true : false;
                var rgb_len = (double_byte_chars) ? char_count * 2 : char_count;
                var phonetic_string = (char_prop_bits[2] == 1) ? true : false;
                var rich_string = (char_prop_bits[3] == 1) ? true : false;
                var reserved2 = this.get_int_from_bin(char_prop_bits.slice(4,8));

                //if (reserved2 != 0) break;

                var varable_offset = 3;
                var c_run;
                var cb_ext_rst;

                if (rich_string) {
                  c_run = this.get_two_byte_int(rgb_bytes.slice(current_unique_offset, current_unique_offset+2), byte_order);
                  varable_offset += 2;
                }

                if (phonetic_string) {
                  cb_ext_rst = this.get_four_byte_int(rgb_bytes.slice(current_unique_offset+varable_offset, current_unique_offset+varable_offset+2), byte_order);
                  varable_offset += 2;
                }

                var rgb_text_bytes = rgb_bytes.slice(current_unique_offset+varable_offset, rgb_len+current_unique_offset+varable_offset).filter(i => i !== 0);
                var rgb = Static_File_Analyzer.get_string_from_array(rgb_text_bytes);
                rgb = (rgb !== null) ? rgb : Static_File_Analyzer.get_ascii(rgb_text_bytes);
                current_unique_offset += rgb_len + varable_offset;

                if (rich_string) {
                  var rg_run_bytes = rgb_bytes.slice(current_unique_offset, current_unique_offset+c_run+1);
                  current_unique_offset += +c_run;
                }

                if (phonetic_string) {
                  var ext_rst_bytes = rgb_bytes.slice(current_unique_offset, current_unique_offset+cb_ext_rst+1);
                  current_unique_offset += cb_ext_rst;
                }

                if (current_unique_offset > rgb_bytes.length) break;

                if (rgb !== null && rgb.length > 0) {
                  file_info = this.search_for_iocs(rgb, file_info);
                  string_constants.push(rgb);
                }

              }
            }

          }
        }
      }

      // Find Lbl (defined name) records - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/d148e898-4504-4841-a793-ee85f3ea9eef
      for (var i=current_byte; i<file_bytes.length; i++) {
        if (file_bytes[i] == 0x18 && file_bytes[i+1] == 0x00) {
          var record_size = this.get_two_byte_int(file_bytes.slice(i+2,i+4), byte_order);
          var prop_bits = this.get_bin_from_int(file_bytes[4]).concat(this.get_bin_from_int(file_bytes[5]));
          var is_hidden = (prop_bits[0] == 1) ? true : false;
          var is_function = (prop_bits[1] == 1) ? true : false;
          var is_vba_macro = (prop_bits[2] == 1) ? true : false;
          var is_macro = (prop_bits[3] == 1) ? true : false;
          var is_function_calc = (prop_bits[4] == 1) ? true : false;
          var is_built_in = (prop_bits[5] == 1) ? true : false;
          var function_category = this.get_int_from_bin(prop_bits.slice(6,12));

          // function_category must be less than 32, if it's not this is not an Lbl record
          if (function_category >= 32) continue;
          if (prop_bits[12] != 0) continue;

          var published_name = (prop_bits[13] == 1) ? true : false;
          var is_workbook_param  = (prop_bits[14] == 1) ? true : false;

          var shortcut_key = file_bytes[i+6];
          var name_char_count = file_bytes[i+7];
          var rgce = this.get_two_byte_int(file_bytes.slice(i+8,i+10), byte_order);
          var reserved3 = this.get_two_byte_int(file_bytes.slice(i+10,i+12), byte_order);
          if (reserved3 != 0) continue;

          var itab = this.get_two_byte_int(file_bytes.slice(i+12,i+14), byte_order);
          var reserved4 = file_bytes[i+14];
          var reserved5 = file_bytes[i+15];
          var reserved6 = file_bytes[i+16];
          var reserved7 = file_bytes[i+17];

          var byte_option_bits = this.get_bin_from_int(file_bytes[i+18]);
          var double_byte_chars = (byte_option_bits[0] == 1) ? true : false;
          var string_end;

          if (double_byte_chars) {
            // Characters are two bytes each.
            string_end = i+19 + (name_char_count * 2);
          } else {
            // Characters are one byte each.
            string_end = i+19 + name_char_count;
          }

          var string_val = Static_File_Analyzer.get_string_from_array(file_bytes.slice(i+19, string_end));

          if (string_val !== null && string_val.length > 0) {
            spreadsheet_var_names.push({
              'name': string_val
            });
          }
        }
      }

      document_obj = {
        'type': "spreadsheet",
        'document_properties': document_properties,
        'sheets': spreadsheet_sheet_names,
        'sheet_index_list': sheet_index_list,
        'sheet_indexes': Array(sheet_index_list.length),
        'current_sheet_name': Object.entries(spreadsheet_sheet_names)[0],
        'current_cell': "",
        'defined_names': spreadsheet_var_names,
        'varables': spreadsheet_defined_vars,
        'recalc_objs': document_obj.recalc_objs
      };

      var cell_records = this.read_dbcell_records(file_bytes, document_obj, byte_order);

      // Parse the String and Number cells first.
      for (var i=0; i<cell_records.length; i++) {
        var cell_data_obj;

        if (cell_records[i].record_type == "LabelSst") {
          cell_data_obj = this.parse_xls_label_set_record(cell_records[i], string_constants, byte_order);
          document_obj.sheets[cell_data_obj.sheet_name].data[cell_data_obj.cell_name] = cell_data_obj.cell_data;
          console.log(cell_data_obj.sheet_name + " " + cell_data_obj.cell_name + " - " + cell_data_obj.cell_data.value);
        } else if (cell_records[i].record_type == "RK") {
          cell_data_obj = this.parse_xls_rk_record(cell_records[i], byte_order);
          document_obj.sheets[cell_data_obj.sheet_name].data[cell_data_obj.cell_name] = cell_data_obj.cell_data;
          console.log(cell_data_obj.sheet_name + " " + cell_data_obj.cell_name + " - " + cell_data_obj.cell_data.value);
        } else if (cell_records[i].record_type == "String") {
          // Do nothing
          continue;
        }
      }

      // Parse the remaining cells
      var cell_data_obj;
      for (var i=0; i<cell_records.length; i++) {
        //break; // TEMP
        if (cell_records[i].record_type == "String") {
          // String value of a formula.
          var string_size = this.get_two_byte_int(cell_records[i].record_bytes.slice(0, 2), byte_order);
          var byte_option_bits = this.get_bin_from_int(cell_records[i].record_bytes[2]);
          var double_byte_chars = (byte_option_bits[0] == 1) ? true : false;
          var string_end = (double_byte_chars) ? 3 + (string_size * 2) : 3 + string_size;
          var string_val = Static_File_Analyzer.get_string_from_array(cell_records[i].record_bytes.slice(3, string_end));

          // DEBUG
          if (cell_data_obj.cell_data.value != string_val) {
            console.log(cell_data_obj.sheet_name + " " + cell_data_obj.cell_name + " Cell precalc missmatch - calc: " + cell_data_obj.cell_data.value + " precalc: " + string_val);

            cell_data_obj.cell_data.value = string_val;
            cell_data_obj.cell_recalc = false;

            var full_cell_name = cell_data_obj.sheet_name + "!" + cell_data_obj.cell_name;
            var recalc_index = document_obj.recalc_objs.indexOf(full_cell_name);

            if (recalc_index >= 0) {
              document_obj.recalc_objs.splice(recalc_index, 1);
            }

            document_obj.sheets[cell_data_obj.sheet_name].data[cell_data_obj.cell_name] = cell_data_obj.cell_data;
          }
        } else if (cell_records[i].record_type == "Formula") {
          cell_data_obj = this.parse_xls_formula_record(cell_records[i], document_obj, file_info, byte_order);

          if (cell_data_obj.cell_recalc == false) {
            document_obj.sheets[cell_data_obj.sheet_name].data[cell_data_obj.cell_name] = cell_data_obj.cell_data;
            console.log(cell_data_obj.sheet_name + " " + cell_data_obj.cell_name + " - " + cell_data_obj.cell_data.formula + " - "+ cell_data_obj.cell_data.value);
          }

        }
      }

      console.log("~~Recalc cells") // DEBUG
      var last_recalc_len = document_obj.recalc_objs.length;
      // Re-parse cells needing recalculation.
      while (document_obj.recalc_objs.length > 0) {
        var cell_data_obj;
        var recalc_objects = document_obj.recalc_objs.slice();
        document_obj.recalc_objs = [];
        for (var ro=0; ro<recalc_objects.length; ro++) {
          //break; // temp
          var recalc_cell_name = recalc_objects[ro];

          for (var i=0; i<cell_records.length; i++) {
            var full_cell_name = cell_records[i].sheet_name + "!" + cell_records[i].cell_name;
            if (recalc_cell_name == full_cell_name) {
              if (cell_records[i].record_type == "Formula") {
                cell_data_obj = this.parse_xls_formula_record(cell_records[i], document_obj, file_info, byte_order);
                document_obj.sheets[cell_data_obj.sheet_name].data[cell_data_obj.cell_name] = cell_data_obj.cell_data;

                if (cell_data_obj.cell_recalc == false) {
                  console.log(cell_data_obj.cell_name + " - " + cell_data_obj.cell_data.formula + " - "+ cell_data_obj.cell_data.value);
                } else {
                  var debug45=54;
                }

              }
            }
          }
        }

        if (document_obj.recalc_objs.length == last_recalc_len) {
          break;
        }
      }

      // Read sheet indexes
      // See https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/67c20922-0427-4c2d-96cc-2267d3f09e8c
      // The Index record specifies row information and the file locations for all DBCell records corresponding to each row block in the sheet
      for (const [key, value] of Object.entries(spreadsheet_sheet_names)) {
        var index_start = value.file_pos;

        if (file_bytes[index_start] == 0x0b && file_bytes[index_start+1] == 0x02) {
          var index_record_size = this.get_two_byte_int(file_bytes.slice(index_start+2,index_start+4), byte_order);

          //Skip over reserved 4 bytes
          var reserved_bytes = file_bytes.slice(index_start+4,index_start+8);

          // The first row that has at least one cell with data in current sheet; zero-based index.
          var rw_mic = this.get_four_byte_int(file_bytes.slice(index_start+8,index_start+12), byte_order);

          // The last row that has at least one cell with data in the sheet, MUST be 0 if there are no rows with data.
          var rw_mac = this.get_four_byte_int(file_bytes.slice(index_start+12,index_start+16), byte_order);

          // Specifies the file position of the DefColWidth record, but we don't use this.
          var ib_xf = this.get_four_byte_int(file_bytes.slice(index_start+16,index_start+20), byte_order);

          if (rw_mac > 0) {
            // Read bytes for DBCell file pointers.
            var rgib_rw_bytes = file_bytes.slice(index_start+20,index_start+4+index_record_size);

            if (rgib_rw_bytes.length > 0) {
              // These bytes are an array of FilePointers giving the file position of each referenced DBCell record as specified in [MS-OSHARED] section 2.2.1.5.
              for (var ai=0; ai<rgib_rw_bytes.length;) {
                var file_pointer = this.get_four_byte_int(rgib_rw_bytes.slice(ai,ai+4), byte_order);
                //console.log(file_pointer); // debug

                var first_row_record = this.get_four_byte_int(file_bytes.slice(file_pointer, file_pointer+4), byte_order);
                var first_row_pos = file_pointer + first_row_record;

                var row_block_count = ((rw_mac - rw_mic) % 32 == 0) ? Math.ceil((rw_mac - rw_mic) / 32) : Math.ceil((rw_mac - rw_mic) / 32 + 1);

                // I don't know where the maximum number comes from yet.
                // Open office says it is the number of ROW records in this Row Block
                //The MS doc says it has to be less than 32.
                for (var b=0; b<=row_block_count;) {
                  // Specifies the file offset in bytes to the first record that specifies a CELL in each row that is a part of this row block.
                  var rgdb = this.get_two_byte_int(file_bytes.slice(file_pointer+(b*2)+4, file_pointer+(b*2)+6), byte_order);
                  var row_start = first_row_pos + rgdb;


                  b+=2;
                  //console.log(rgdb); // debug
                }

                ai+=4;
              }
            }
          } else {
            // There are no DBCell records for this sheet.
          }

        }
      }

      // Hack to find VBA code. TODO proppery index file to get VBA
      for (var i=current_byte; i<file_bytes.length; i++) {
        if (file_bytes[i] == 0x01 && file_bytes[i+3] == 0x00 && file_bytes[i+4] == 0x41 && file_bytes[i+5] == 0x74 && file_bytes[i+6] == 0x74) {
          var compressed_header = [file_bytes[i+2], file_bytes[i+1]]; // Little Endian
          var header_bit_array = this.get_binary_array(Uint8Array.from(compressed_header));
          var compressed_chunk_byte_size = this.get_int_from_bin(header_bit_array.slice(4, 16), this.BIG_ENDIAN) + 5;

          var vba_compressed_bytes = file_bytes.slice(i,i+compressed_chunk_byte_size);
          var vba_bytes = this.decompress_vba(vba_compressed_bytes);
          var vba_code = Static_File_Analyzer.get_ascii(vba_bytes);
          vba_code = this.pretty_print_vba(vba_code);

          var sub_match = /\n[a-z\s]?(?:Sub|Function)[^\(]+\([^\)]*\)/gmi.exec(vba_code);

          if (sub_match != null) {
            file_info.scripts.script_type = "VBA Macro";
            vba_code = vba_code.substring(sub_match.index).trim();
            file_info.scripts.extracted_script += vba_code + "\n\n";

            document_obj = {
              'type': "spreadsheet",
              'document_properties': document_properties,
              'sheets': spreadsheet_sheet_names,
              'current_sheet_name': "",
              'current_cell': "",
              'varables': spreadsheet_defined_vars,
              'recalc_objs': document_obj.recalc_objs
            };

            var vba_results = this.analyze_vba(file_info, document_obj);
          }
        }
      }
    } else {
      // File format error.
      console.log("No BOF record found.");
    }

    return file_info;
  }

  /**
   * Extracts meta data and other information from XML files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_xml(file_bytes) {
    var file_info = this.get_default_file_json();

    file_info.file_format = "xml";
    file_info.file_generic_type = "Document";

    return file_info;
  }

  /**
   * Extracts meta data and other information from multiple file formats that use the PKZip format.
   * This includes OOXML Document files that usualy have extetions like .docx, .xlmx, etc.
   *
   * @see https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
   * @see http://officeopenxml.com/anatomyofOOXML.php
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  async analyze_zip(file_bytes) {
    var zip_os_list  = ["MS-DOS", "Amiga", "OpenVMS", "UNIX", "VM/CMS", "Atari ST", "OS/2 H.P.F.S.", "Macintosh", "Z-System", "CP/M", "Windows NTFS", "MVS", "VSE", "Acorn Risc", "VFAT", "alternate MVS", "BeOS", "Tandem", "OS/400", "OS X (Darwin)"];
    var file_info = this.get_default_file_json();

    file_info.file_format = "zip";
    file_info.file_generic_type = "File Archive";

    // For OOXML Documents
    var has_content_types_xml = false;
    var has_rels_dir = false;

    var archive_files = [];
    var current_file_start = 0;

    while (this.array_equals(file_bytes.slice(current_file_start,current_file_start+4), [80,75,3,4])) {
      var file_entry = {};

      file_entry.extract_version = file_bytes.slice(current_file_start+4,current_file_start+6);
      file_entry.extract_version_properties = this.get_zip_extract_version_properties(file_entry.extract_version);

      if (file_info.file_encryption_type == "unknown" || file_info.file_encryption_type == "none") {
        file_info.file_encryption_type = file_entry.extract_version_properties.file_encryption_type;
        file_info.file_encrypted = "true";
      }

      file_entry.general_purpose_flag_bytes = file_bytes.slice(current_file_start+6,current_file_start+8);
      // For the general purpose flag, if the first bit (little endien ) is 1, file is encrypted.
      file_entry.general_purpose_flag_bits = ("00000000" + (file_entry.general_purpose_flag_bytes[0]).toString(2)).slice(-8).split("").reverse();
      if (file_entry.general_purpose_flag_bits[0] == 1  && file_bytes[current_file_start+7] == 0) {
        file_info.file_encrypted = "true";
        file_entry.file_encrypted = "true";

        if (file_info.file_encryption_type == "unknown") {
          if (file_bytes[current_file_start+8] == 99) {
            file_info.file_encryption_type = "AES";
            file_entry.file_encryption_type = "AES";
          }
        }
      } else {
        file_info.file_encrypted = "false";
        file_info.file_encryption_type = "none";
        file_entry.file_encrypted = "false";
        file_entry.file_encryption_type = "none";
      }

      file_entry.compression_method_bytes = file_bytes.slice(current_file_start+8,current_file_start+10);
      file_entry.compression_method_bits_1 = ("00000000" + (file_entry.compression_method_bytes[0]).toString(2)).slice(-8).split("").reverse();
      file_entry.compression_method_bits_2 = ("00000000" + (file_entry.compression_method_bytes[1]).toString(2)).slice(-8).split("").reverse();

      file_entry.file_mod_date = this.get_msdos_timestamp(file_bytes.slice(current_file_start+10,current_file_start+14));
      file_entry.crc32 = file_bytes.slice(current_file_start+14,current_file_start+18);
      file_entry.compressed_size = this.get_four_byte_int(file_bytes.slice(current_file_start+18,current_file_start+22), this.LITTLE_ENDIAN);
      file_entry.uncompressed_size = this.get_four_byte_int(file_bytes.slice(current_file_start+22,current_file_start+26), this.LITTLE_ENDIAN);
      file_entry.file_name_length = this.get_two_byte_int(file_bytes.slice(current_file_start+26,current_file_start+28), this.LITTLE_ENDIAN);
      file_entry.extra_field_length = this.get_two_byte_int(file_bytes.slice(current_file_start+28,current_file_start+30), this.LITTLE_ENDIAN);

      file_entry.file_name = Static_File_Analyzer.get_ascii(file_bytes.slice(current_file_start+30,current_file_start+30+file_entry.file_name_length));
      file_entry.extra_field_start = current_file_start + 30 + file_entry.file_name_length;
      file_entry.extra_field = file_bytes.slice(file_entry.extra_field_start, file_entry.extra_field_start + file_entry.extra_field_length);

      file_entry.file_data_start = file_entry.extra_field_start + file_entry.extra_field_length;
      file_entry.file_data = file_bytes.slice(file_entry.file_data_start, file_entry.file_data_start + file_entry.compressed_size);
      file_entry.file_data_ascii = Static_File_Analyzer.get_ascii(file_entry.file_data);
      current_file_start = file_entry.file_data_start + file_entry.compressed_size;

      if (file_entry.file_name.toLowerCase() == "[content_types].xml") {
        has_content_types_xml = true;
      }

      if (file_entry.file_name.toLowerCase().substring(0, 6) == "_rels/") {
        has_rels_dir = true;
      }

      archive_files.push(file_entry);
      file_info.file_components.push({
        'name': file_entry.file_name,
        'type': "zip"
      });
    }

    // Check if this file is really an OOXML Document / Office document
    // Ref: http://officeopenxml.com/anatomyofOOXML.php
    if (has_content_types_xml == true && has_rels_dir == true) {
      var spreadsheet_auto_open = false;
      var spreadsheet_auto_open_name = "";
      var spreadsheet_defined_names = {};
      var spreadsheet_sheet_names = {}; // Spreadsheet names index
      var spreadsheet_sheet_relations = {};
      var string_constants = [];
      var xml_text;

      for (var i = 0; i < archive_files.length; i++) {
        if (archive_files[i].file_name.toLowerCase().indexOf(".xml") > -1) {
          xml_text = Static_File_Analyzer.get_string_from_array(await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i));

          // Look for suspicious XML schema targets
          var xml_target_regex = /Target\s*\=\s*[\"\'](mhtml\:[^\"\']+)/gmi;
          var xml_target_match = xml_target_regex.exec(xml_text);

          while (xml_target_match !== null) {
            file_info.analytic_findings.push("SUSPICIOUS - Unusual XML Schema Target: " + xml_target_match[1]);
            file_info = this.search_for_iocs(xml_target_match[1], file_info);
            xml_target_match = xml_target_regex.exec(xml_text);
          }

          // Look for suspicious XML domains
          var xml_type_regex = /[^\:\w]Type\s*\=\s*[\"\']([a-zA-Z]+\:\/?\/?([^\/\>\<\"\']+)\/[^\"\']+)/gmi;
          var xml_type_match = xml_type_regex.exec(xml_text);

          while (xml_type_match !== null) {
            if (!this.XML_DOMAINS.includes(xml_type_match[2])) {
              file_info.analytic_findings.push("SUSPICIOUS - Unusual XML Schema Domain: " + xml_type_match[2]);
              console.log(xml_text); // DEBUG
            }

            xml_type_match = xml_type_regex.exec(xml_text);
          }
        } else if (/embeddings\/oleObject[0-9]+\.bin/gmi.test(archive_files[i].file_name)) {
          // embedded OLE objects
          var arc_file_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i);
          var cmb_obj = this.parse_compound_file_binary(arc_file_bytes);
          var root_guid = cmb_obj.entries[0].enrty_guid;

          for (var ci=1; ci<cmb_obj.entries.length; ci++) {
            if (root_guid == "0002CE02-0000-0000-C000-000000000046") {
              // Microsoft Equation 3.0 object
              // See https://malcat.fr/blog/exploit-steganography-and-delphi-unpacking-dbatloader/
              if (cmb_obj.entries[ci].entry_bytes[11] == 8) {
                // Font record, look for null terminator
                var found_null = false;
                for (var fr=14; fr<45; fr++) {
                  // Check if there is a null terminator withing 40 characters of the font name.
                  if (cmb_obj.entries[ci].entry_bytes[fr] == 0) {
                    found_null = true;
                    break;
                  }
                }

                if (found_null == false) {
                  // CVE-2017-11882 Exploit
                  file_info.analytic_findings.push("MALICIOUS - CVE-2017-11882 Exploit Found");
                }
              }
            }
          }
        }

        if (archive_files[i].file_name.toLowerCase().substring(0, 5) == "ppt/") {
          file_info.file_format = "pptx";
          file_info.file_generic_type = "Presentation";
        } else if (archive_files[i].file_name.toLowerCase().substring(0, 5) == "word/") {
          file_info.file_format = "docx";
          file_info.file_generic_type = "Document";
        } else if (archive_files[i].file_name.toLowerCase().substring(0, 3) == "xl/") {
          file_info.file_format = (file_info.file_format != "xlsm" && file_info.file_format != "xlsb") ? "xlsx" : file_info.file_format;
          file_info.file_generic_type = "Spreadsheet";

          if (archive_files[i].file_name.toLowerCase() == "xl/sharedstrings.bin") {
            var xl_file_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i);
            var current_byte = 0;
            var current_record_info;
            var current_record_bytes;

            while (current_byte < xl_file_bytes.length) {
              current_record_info = this.get_biff12_record_info(xl_file_bytes.slice(current_byte,current_byte+6));
              current_byte += current_record_info.offset;
              current_record_bytes = xl_file_bytes.slice(current_byte, current_byte+current_record_info.record_size);
              current_byte += current_record_bytes.length;

              // See: https://interoperability.blob.core.windows.net/files/MS-XLSB/%5BMS-XLSB%5D.pdf - PAGE 204
              if (current_record_info.record_number == 19) {
                // BrtSSTItem
                var option_bits = this.get_bin_from_int(current_record_bytes[0]);
                var current_byte2 = 1;

                var string_size = this.get_four_byte_int(current_record_bytes.slice(current_byte2, current_byte2+4), this.LITTLE_ENDIAN) * 2;
                var string_bytes = (current_record_bytes.slice(current_byte2+4, current_byte2+4+string_size));
                var string_text = Static_File_Analyzer.get_string_from_array(string_bytes.filter(i => i !== 0));
                current_byte2 = current_byte2 + 4 + string_size;

                string_constants.push(string_text);
                file_info = this.search_for_iocs(string_text, file_info);
              } else if (current_record_info.record_number == 159) {
                // BrtBeginSst
              } else if (current_record_info.record_number == 160) {
                // BrtEndSst
              } else {
                // DEBUG
                console.log("Unkown record number in sharedStrings.bin " + current_record_info.record_number);
              }
            }
          } else if (archive_files[i].file_name.toLowerCase() == "xl/sharedstrings.xml") {
            var sst_regex = /\<\s*t\s*\>([^\<]+)\<\s*\/t\s*\>/gmi;
            var sst_match = sst_regex.exec(xml_text);

            while (sst_match !== null) {
              string_constants.push(sst_match[1]);
              sst_match = sst_regex.exec(xml_text);
            }
          } else if (archive_files[i].file_name.toLowerCase() == "xl/workbook.xml") {
            // Look for more meta data
            var workbook_xml_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i);
            var workbook_xml = xml_text;

            // Look for last saved location
            var last_saved_loc_matches = /<[a-z0-9]+\:absPath[\sa-zA-Z0-9\:\=\"\'\/\.]+url\s*\=\s*[\"\']([^\"\']+)[\"\']/gmi.exec(workbook_xml);
            if (last_saved_loc_matches != null) {
              file_info.metadata.last_saved_location = last_saved_loc_matches[1];

              // We may be able to determin the creation OS if this path exists.
              if (/[a-zA-Z]\:[\\]+/gm.test(workbook_xml)) {
                // Path has format drive_letter:\ so this is probably windows
                file_info.metadata.creation_os = "Windows";
              }
            }

            if (workbook_xml.indexOf("schemas.microsoft.com/office/mac/excel/2008/main") > 0) {
              // Probably created on a mac
              // TODO: normalize os names
              file_info.metadata.creation_os = "macOS";
              file_info.metadata.creation_application = "Microsoft Excel";
            }

            if (workbook_xml.indexOf("schemas.microsoft.com/office/spreadsheetml") > 0) {
              file_info.metadata.creation_application = "Microsoft Excel";
            }

            // Get defined names
            var defined_names_regex = /\<definedName\s+name\s*\=\s*[\"\']([^\"\']+)[\"\']\s*\>([^\<]+)\</gmi;
            var defined_names_matches = defined_names_regex.exec(workbook_xml);

            while (defined_names_matches != null) {
              spreadsheet_defined_names[defined_names_matches[1]] = defined_names_matches[2];

              // Look for auto open macros, this is a case insensative varable starting with _xlnm.Auto_Open
              if (defined_names_matches[1].substring(0,15).toLowerCase() == "_xlnm.auto_open") {
                file_info.scripts.script_type = "Excel 4.0 Macro";
                file_info.file_format = "xlsm";
                file_info.analytic_findings.push("SUSPICIOUS - Auto Open Macro Found");

                spreadsheet_auto_open_name = defined_names_matches[1];
                spreadsheet_auto_open = true;
              }

              defined_names_matches = defined_names_regex.exec(workbook_xml);
            }

            // Index sheet names
            var sheet_regex = /\<sheet\s*name\s*\=\s*[\"\']([^\"\']+)[\"\']\s*sheetId\s*\=\s*[\'\"]([0-9]+)[\"\']\s*(?:state\s*\=\s*[\"\']([^\"\']+)[\"\']\s*)?r\:id\s*\=\s*[\"\']([a-zA-Z0-9]+)[\"\']/gmi;
            var sheet_matches = sheet_regex.exec(workbook_xml);

            while (sheet_matches != null) {
              spreadsheet_sheet_names[sheet_matches[1]] = {
                'name':  sheet_matches[1],
                'id':    sheet_matches[2],
                'state': ((sheet_matches[3] !== undefined) ? sheet_matches[3] : "visible"),
                'rid':   sheet_matches[4],
                'data':  {}
              };

              sheet_matches = sheet_regex.exec(workbook_xml);
            }

          } else if (archive_files[i].file_name.toLowerCase() == "xl/workbook.bin") {
            // Excel Binary Format
            file_info.file_format = "xlsb";

            var workbook_bin_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i);
            var current_byte = 0;
            var current_record_info;
            var current_record_bytes;

            while (current_byte < workbook_bin_bytes.length) {
              current_record_info = this.get_biff12_record_info(workbook_bin_bytes.slice(current_byte,current_byte+6));
              current_byte += current_record_info.offset;
              current_record_bytes = workbook_bin_bytes.slice(current_byte, current_byte+current_record_info.record_size);
              current_byte += current_record_bytes.length;

              // See: https://interoperability.blob.core.windows.net/files/MS-XLSB/%5BMS-XLSB%5D.pdf - PAGE 204
              if (current_record_info.record_number == 35) {
                // BrtFRTBegin
                var product_version = this.get_four_byte_int(current_record_bytes.slice(0,4), this.LITTLE_ENDIAN);
              } else if (current_record_info.record_number == 36) {
                // BrtFRTEnd
              } else if (current_record_info.record_number == 37) {
                // BrtACBegin
              } else if (current_record_info.record_number == 38) {
                // BrtACEnd
              } else if (current_record_info.record_number == 128) {
                // BrtFileVersion
              } else if (current_record_info.record_number == 131) {
                // BrtBeginBook
              } else if (current_record_info.record_number == 132) {
                // BrtEndBook
              } else if (current_record_info.record_number == 135) {
                // BrtBeginBookViews
              } else if (current_record_info.record_number == 136) {
                // BrtEndBookViews
              } else if (current_record_info.record_number == 143) {
                // BrtBeginBundleShs
              } else if (current_record_info.record_number == 144) {
                // BrtEndBundleShs
              } else if (current_record_info.record_number == 153) {
                // BrtWbProp
                // 4 bytes of bit properties
                // 4 bytes for dwThemeVersion
                var str_name = Static_File_Analyzer.get_string_from_array(current_record_bytes.slice(8));
              } else if (current_record_info.record_number == 155) {
                // BrtFileRecover
              } else if (current_record_info.record_number == 156) {
                // BrtBundleSh - Sheet information
                var sheet_state_val = this.get_four_byte_int(current_record_bytes.slice(0,4), this.LITTLE_ENDIAN);
                var sheet_state = (sheet_state_val == 1) ? "hidden" : ((sheet_state_val == 1) ? "very hidden": "visible");

                var sheet_id = this.get_four_byte_int(current_record_bytes.slice(4,8), this.LITTLE_ENDIAN);
                var sheet_type_size = this.get_four_byte_int(current_record_bytes.slice(8,12), this.LITTLE_ENDIAN) * 2;
                var sheet_type_bytes = (current_record_bytes.slice(12,12+sheet_type_size));
                var sheet_name_size = this.get_four_byte_int(current_record_bytes.slice(sheet_type_size+12,sheet_type_size+16), this.LITTLE_ENDIAN) * 2;
                var sheet_name_bytes = (current_record_bytes.slice(sheet_type_size+16,sheet_type_size+16+sheet_name_size));

                var sheet_type = Static_File_Analyzer.get_string_from_array(sheet_type_bytes.filter(i => i !== 0));
                var sheet_name = Static_File_Analyzer.get_string_from_array(sheet_name_bytes.filter(i => i !== 0));

                spreadsheet_sheet_names[sheet_name] = {
                  'name': sheet_name,
                  'state': sheet_state,
                  'sheet_id': sheet_id,
                  'rid': sheet_type,
                  'data': {}
                };
              } else if (current_record_info.record_number == 157) {
                // BrtCalcProp
              } else if (current_record_info.record_number == 158) {
                // BrtBookView
              } else if (current_record_info.record_number == 2071) {
                // BrtAbsPath15
                file_info.metadata.last_saved_location = Static_File_Analyzer.get_string_from_array(current_record_bytes.slice(2));
              } else if (current_record_info.record_number == 2091) {
                // BrtWorkBookPr15
              } else if (current_record_info.record_number == 3073) {
                // brtRevisionPtr
              }
            }
          } else if (archive_files[i].file_name.toLowerCase() == "xl/_rels/workbook.xml.rels" ||
                     archive_files[i].file_name.toLowerCase() == "xl/_rels/workbook.bin.rels") {

            // This will build the relationships for this spreadsheet. We can use this to find malicious code.
            if (archive_files[i].file_name.indexOf(".bin") > 0) {
              var workbook_xml_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i);
              xml_text = Static_File_Analyzer.get_string_from_array(workbook_xml_bytes);
            }

            var relationship_regex = /<\s*Relationship([^\>]+)\>/gmi;
            var relationship_matches = relationship_regex.exec(xml_text);

            while (relationship_matches != null) {
              var type_match = /Type\s*\=\s*[\"\']([^\"\']+)[\"\']/gmi.exec(relationship_matches[1]);
              var target_match = /Target\s*\=\s*[\"\']([^\"\']+)[\"\']/gmi.exec(relationship_matches[1]);
              var rid_match = /Id\s*\=\s*[\"\']([^\"\']+)[\"\']/gmi.exec(relationship_matches[1]);

              var type = (type_match !== null) ? type_match[1] : "";
              var target = (target_match !== null) ? target_match[1] : "";
              var rid = (rid_match !== null) ? rid_match[1] : "";

              if (type.toLowerCase().endsWith("vbaproject")) {
                if (target !== "vbaProject.bin") {
                  file_info.analytic_findings.push("SUSPICIOUS - Nonstandard VBA Project File Name: " + target);
                }

                file_info.scripts.script_type = "VBA Macro";
                var vba_file_index = -1;
                for (var fci=0; fci<file_info.file_components.length; fci++) {
                  if (file_info.file_components[fci].name.split("/")[1] == target) {
                    vba_file_index = fci;
                    break;
                  }
                }

                if (vba_file_index >= 0) {
                  var macro_data = await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, vba_file_index);
                  var vba_data = this.extract_vba(macro_data);

                  for (var s = 0; s < vba_data.attributes.length; s++) {
                    var sub_match = /\n[a-z\s]+Sub[^\(]+\([^\)]*\)/gmi.exec(vba_data.attributes[s]);

                    if (sub_match != null) {
                      var vba_code = vba_data.attributes[s].substring(sub_match.index).trim();
                      vba_code = this.pretty_print_vba(vba_code);
                      file_info.scripts.extracted_script += vba_code + "\n\n";
                    }
                  }
                }

              }

              if (rid != "") {
                spreadsheet_sheet_relations[rid] = {
                  'type':   type,
                  "target": target
                }
              }

              relationship_matches = relationship_regex.exec(xml_text);
            }

          }
        }

        if (/docProps\/core\.xml/gmi.test(archive_files[i].file_name)) {
          // Meta data file
          var meta_data_xml_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i);
          var meta_data_xml = Static_File_Analyzer.get_string_from_array(meta_data_xml_bytes);

          file_info.metadata.author = this.get_xml_tag_content(meta_data_xml, "dc:creator", 0);
          file_info.metadata.creation_date = this.get_xml_tag_content(meta_data_xml, "dcterms:created", 0);
          file_info.metadata.description = this.get_xml_tag_content(meta_data_xml, "dc:subject", 0);
          file_info.metadata.last_modified_date = this.get_xml_tag_content(meta_data_xml, "dcterms:modified", 0);
          file_info.metadata.title = this.get_xml_tag_content(meta_data_xml, "dc:title", 0);
        }
      }

      // If this is a spreadsheet, decode and look for malicious indicators
      if (file_info.file_format.substring(0,3) == "xls") {
        // Preload sheet target / file names into spreadsheet_sheet_names
        for (const [key, value] of Object.entries(spreadsheet_sheet_names)) {
          if (spreadsheet_sheet_relations[value.rid] !== null && spreadsheet_sheet_relations[value.rid] !== undefined) {
            spreadsheet_sheet_names[key].file_name = spreadsheet_sheet_relations[value.rid].target;
          }
        }

        // Index cell values and formaulas in all sheets
        for (var fi = 0; fi < archive_files.length; fi++) {
          for (const [key, value] of Object.entries(spreadsheet_sheet_names)) {
            if (archive_files[fi].file_name == "xl/" + value.file_name) {
              var sheet_file_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, fi);

              if (value.file_name.toLowerCase().slice(-3) == "bin") {
                // Binary Sheet file
                var current_byte = 0;
                var current_record_info;
                var current_record_bytes;
                var current_row = -1;

                while (current_byte < workbook_bin_bytes.length) {
                  current_record_info = this.get_biff12_record_info(sheet_file_bytes.slice(current_byte,current_byte+6));
                  current_byte += current_record_info.offset;
                  current_record_bytes = sheet_file_bytes.slice(current_byte, current_byte+current_record_info.record_size);
                  current_byte += current_record_bytes.length;

                  // See: https://interoperability.blob.core.windows.net/files/MS-XLSB/%5BMS-XLSB%5D.pdf - PAGE 204
                  if (current_record_info.record_number == 0) {
                    // BrtRowHdr
                    current_row = this.get_four_byte_int(current_record_bytes.slice(0,4), this.LITTLE_ENDIAN) + 1;
                  } else if (current_record_info.record_number == 1) {
                    // BrtCellBlank - Blank cell
                  } else if (current_record_info.record_number == 7) {
                    // BrtCellIsst - A cell record that contains a string.
                    var col = this.get_four_byte_int(current_record_bytes.slice(0,4), this.LITTLE_ENDIAN);
                    var sst_index = this.get_four_byte_int(current_record_bytes.slice(8,12), this.LITTLE_ENDIAN);
                    var cell_value = string_constants[sst_index];

                    if (current_row > -1) {
                      var cell_id = this.convert_xls_column(col) + current_row

                      spreadsheet_sheet_names[key]['data'][cell_id] = {
                        'formula': null,
                        'value': cell_value
                      }
                    }

                    var debug_t=0;
                  } else if (current_record_info.record_number == 37) {
                    // BrtACBegin
                  } else if (current_record_info.record_number == 38) {
                    // BrtACEnd
                  } else if (current_record_info.record_number == 60) {
                    // BrtColInfo
                  } else if (current_record_info.record_number == 129) {
                    // BrtBeginSheet
                  } else if (current_record_info.record_number == 133) {
                    // BrtBeginWsViews
                  } else if (current_record_info.record_number == 134) {
                    // BrtEndWsViews
                  } else if (current_record_info.record_number == 137) {
                    // BrtBeginWsView
                  } else if (current_record_info.record_number == 138) {
                    // BrtEndWsView
                  } else if (current_record_info.record_number == 145) {
                    // BrtBeginSheetData
                  } else if (current_record_info.record_number == 146) {
                    // BrtEndSheetData
                  } else if (current_record_info.record_number == 147) {
                    // BrtWsProp
                  } else if (current_record_info.record_number == 148) {
                    // BrtWsDim - specifies the used range of the sheet.
                  } else if (current_record_info.record_number == 152) {
                    // BrtSel
                    var pane = this.get_four_byte_int(current_record_bytes.slice(0,4), this.LITTLE_ENDIAN);
                    var row = this.get_four_byte_int(current_record_bytes.slice(4,8), this.LITTLE_ENDIAN);
                    var col = this.get_four_byte_int(current_record_bytes.slice(8,12), this.LITTLE_ENDIAN);
                    var rfx_index = this.get_four_byte_int(current_record_bytes.slice(12,16), this.LITTLE_ENDIAN);
                    var rfx_count = this.get_four_byte_int(current_record_bytes.slice(16,20), this.LITTLE_ENDIAN);
                    var rgrfx_bytes = current_record_bytes.slice(20,20+rfx_count);
                  } else if (current_record_info.record_number == 390) {
                    // BrtBeginColInfos
                  } else if (current_record_info.record_number == 391) {
                    // BrtEndColInfos
                  } else if (current_record_info.record_number == 476) {
                    // BrtMargins
                  } else if (current_record_info.record_number == 477) {
                    // BrtPrintOptions
                  } else if (current_record_info.record_number == 485) {
                    // BrtWsFmtInfo
                  } else if (current_record_info.record_number == 494) {
                    // BrtHLink - specifies a hyperlink that applies to a range of cells.
                    var row_start = this.get_four_byte_int(current_record_bytes.slice(0,4), this.LITTLE_ENDIAN);
                    var row_end = this.get_four_byte_int(current_record_bytes.slice(4,8), this.LITTLE_ENDIAN);
                    var col_start = this.get_four_byte_int(current_record_bytes.slice(8,12), this.LITTLE_ENDIAN);
                    var col_end = this.get_four_byte_int(current_record_bytes.slice(12,16), this.LITTLE_ENDIAN);

                    var rid_size = this.get_four_byte_int(current_record_bytes.slice(16,20), this.LITTLE_ENDIAN) * 2;
                    var rid_bytes = (current_record_bytes.slice(20, 20+rid_size));
                    var rid = Static_File_Analyzer.get_string_from_array(rid_bytes.filter(i => i !== 0));
                    var current_byte2 = 20+rid_size;

                    var location_size = this.get_four_byte_int(current_record_bytes.slice(current_byte2, current_byte2+4), this.LITTLE_ENDIAN) * 2;
                    var location_bytes = (current_record_bytes.slice(current_byte2+4, current_byte2+4+location_size));
                    var location = Static_File_Analyzer.get_string_from_array(location_bytes.filter(i => i !== 0));
                    current_byte2 = current_byte2 + 4 + location_size;

                    var tool_tip_size = this.get_four_byte_int(current_record_bytes.slice(current_byte2, current_byte2+4), this.LITTLE_ENDIAN) * 2;
                    var tool_tip_bytes = (current_record_bytes.slice(current_byte2+4, current_byte2+4+tool_tip_size));
                    var tool_tip = Static_File_Analyzer.get_string_from_array(tool_tip_bytes.filter(i => i !== 0));
                    current_byte2 = current_byte2 + 4 + tool_tip_size;

                    var display_size = this.get_four_byte_int(current_record_bytes.slice(current_byte2, current_byte2+4), this.LITTLE_ENDIAN) * 2;
                    var display_bytes = (current_record_bytes.slice(current_byte2+4, current_byte2+4+display_size));
                    var display = Static_File_Analyzer.get_string_from_array(display_bytes.filter(i => i !== 0));
                    current_byte2 = current_byte2 + 4 + display_size;

                  } else if (current_record_info.record_number == 535) {
                    // BrtSheetProtection
                  } else if (current_record_info.record_number == 1024) {
                    // BrtRwDescent
                  } else if (current_record_info.record_number == 1045) {
                    // BrtWsFmtInfoEx14
                  } else if (current_record_info.record_number == 3072) {
                    // Unknown
                  } else {
                    // DEBUG
                    console.log("Unknown record type: " + current_record_info.record_number);
                  }
                }

                var tt=0; // DEBUG
              } else {
                // XLM Sheet file
                var sheet_xml = Static_File_Analyzer.get_string_from_array(sheet_file_bytes);

                var c_tags_regex = /\<\s*c\s*r\s*\=\s*[\"\']([a-zA-Z0-9]+)[\"\'][^\>]+\>\s*(?:\<\s*f\s*\>([^\<]+)\<\/f\>\s*)?\<\s*v\s*(?:[^\>]*)?\>([^\<]+)\<\/v\>/gmi;
                var c_tags_matches = c_tags_regex.exec(sheet_xml);

                while (c_tags_matches != null) {
                  var cell_id = c_tags_matches[1];
                  var cell_value = c_tags_matches[3];

                  // Get cell type
                  var cell_type_match = /[tT]\s*\=\t*[\"\']([^\"\']+)[\"\']/gm.exec(c_tags_matches[0]);

                  if (cell_type_match !== null) {
                    if (cell_type_match[1].toLowerCase() == "b") {
                      // Boolean
                    } else if (cell_type_match[1].toLowerCase() == "e") {
                      // Error
                    } else if (cell_type_match[1].toLowerCase() == "n") {
                      // Number
                    } else if (cell_type_match[1].toLowerCase() == "s") {
                      // Shared String, lookup in shared strings
                      if (cell_value < string_constants.length) {
                        cell_value = string_constants[cell_value];
                      }
                    } else if (cell_type_match[1].toLowerCase() == "str") {
                      // Formula string
                    } else if (cell_type_match[1].toLowerCase() == "inlineStr") {
                      // Inline rich string
                    }
                  }

                  // Replace XML special key words
                  cell_value = cell_value.replaceAll(/\&lt\;/gmi, "<");
                  cell_value = cell_value.replaceAll(/\&gt\;/gmi, ">");
                  cell_value = cell_value.replaceAll(/\&amp\;/gmi, "&");

                  spreadsheet_sheet_names[key]['data'][cell_id] = {
                    'formula': c_tags_matches[2],
                    'value': cell_value
                  }

                  c_tags_matches = c_tags_regex.exec(sheet_xml);
                }

                break;
              }
            }
          }
        }

        if (spreadsheet_auto_open == true) {
          var auto_open_cell = spreadsheet_defined_names[spreadsheet_auto_open_name];
          var auto_open_sheet_obj = spreadsheet_sheet_names[auto_open_cell.split("!")[0]];

          /* Apparently the actual cell for auto open isn't important, we just
             need to execute all the formulas in the sheet part of auto open.
             We have already indexed that formulas, so let's execute them.
          */
          for (const [key, value] of Object.entries(auto_open_sheet_obj.data)) {
            var formula_output = this.calculate_cell_formula(value.formula, spreadsheet_sheet_names, auto_open_sheet_obj.name, file_info);
          }

        }

        var document_obj = {
          'type': "spreadsheet",
          'document_properties': {},
          'sheets': spreadsheet_sheet_names,
          'current_sheet_name': "",
          'current_cell': "",
          'varables': {}
        };

        var vba_results = this.analyze_vba(file_info, document_obj);
      }
    }

    var analyzed_results = this.analyze_embedded_script(file_info.scripts.extracted_script);

    for (var f=0; f<analyzed_results.findings.length; f++) {
      if (analyzed_results.findings.indexOf(analyzed_results.findings[f]) < 0) {
        file_info.analytic_findings.push(analyzed_results.findings[f]);
      }
    }

    for (var f=0; f<analyzed_results.iocs.length; f++) {
      if (file_info.iocs.indexOf(analyzed_results.iocs[f]) < 0) {
          file_info.iocs.push(analyzed_results.iocs[f]);
      }
    }

    return file_info;
  }

  /**
   * Converts a number in Roman Numerals to an arabic numerals integer.
   *
   * @param {String} roman_numeral A string representation of a Roman Numeral.
   * @return {int}   The integer value if the provided Roman Numeral.
   */
  static convert_roman_numeral_to_int(roman_numeral) {
    var roman = {'M':1000, 'D':500, 'C':100, 'L':50, 'X':10, 'V':5, 'I':1};
    var return_val = 0;

    roman_numeral = roman_numeral.toUpperCase();
    var roman_digits = roman_numeral.split("");
    var current_val, next_val;

    for (var i=0; i<roman_digits.length; i++) {
      if (i+1<roman_digits.length) {
        current_val = roman[roman_digits[i]];
        next_val = roman[roman_digits[i+1]];

        if (current_val < next_val) {
          return_val -= roman[roman_digits[i]];
        } else {
          return_val += roman[roman_digits[i]];
        }
      } else {
        return_val += roman[roman_digits[i]];
      }
    }

    return return_val;
  }

  /**
   * Converts a column index to a letter value.
   *
   * @param {int}     col_index An integer representing the column index.
   * @return {String} col_name  A String giving the letter or multiletter column name.
   */
  convert_xls_column(col_index) {
    var col_conversion = ["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"];
    var col_name = "";
    var c;
    var char_rem = col_index;

    if (col_index == 0) {
      return "A";
    }

    while (char_rem > 0) {
      c = ((char_rem) % 26);
      var t = String.fromCharCode(c+65);
      col_name = col_conversion[c] + col_name;

      char_rem = Math.floor((char_rem - c - 1) / 26);
    }

    return col_name;
  }


  /**
   * Decompress Visual Basic for Applicaitons (VBA) files within Microsoft OOXML Documents.
   *
   * @see https://www.wordarticles.com/Articles/Formats/StreamCompression.php
   *
   * @param {Uint8Array}  file_bytes               Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {array}      decompressed_file_bytes  Array with int values 0-255 representing the decompressed bytes of the given file.
   */
  decompress_vba(bytes) {
    var compressed_header;
    var compressed_data;
    var decompressed_buffer = [];
    var header_block_found = false;

    // Find block start
    for (var i=0; i<bytes.length; i++) {
      if (bytes[i] == 1) {
        // Compressed block start
        compressed_header = [bytes[i+2], bytes[i+1]]; // Little Endian
        compressed_data = bytes.slice(i+3, bytes.length);
        header_block_found = true;
        break;
      }
    }

    if (header_block_found == true) {
      // Get header data
      var header_bit_array = this.get_binary_array(Uint8Array.from(compressed_header));
      var compressed_chunk_byte_size = this.get_int_from_bin(header_bit_array.slice(4, 16), this.BIG_ENDIAN) + 3;
      var compressed_chunk_signature = this.get_int_from_bin(header_bit_array.slice(1, 4), this.BIG_ENDIAN);
      var compressed_chunk_flag = header_bit_array[0];
      var current_byte = 0;
      var compression_flags;

      // Resize array
      if (compressed_data.length-2 >= compressed_chunk_byte_size) {
        compressed_data = compressed_data.slice(0,compressed_chunk_byte_size-2);
      } else {
        // Error
      }

      // Token Sequences
      var debug = "";
      while (current_byte < compressed_data.length) {
        compression_flags = this.get_binary_array(Uint8Array.from([compressed_data[current_byte]])).reverse();
        current_byte++;

        for (var i=0; i<8; i++) {
          if (compression_flags[i] == 0) {
            // Non-compressed byte
            decompressed_buffer.push(compressed_data[current_byte]);
            current_byte++;
          } else {
            // copy token
            var copy_token_bytes = [compressed_data[current_byte+1], compressed_data[current_byte]];
            var copy_token_bits = this.get_binary_array(Uint8Array.from(copy_token_bytes));

            var number_of_bits = Math.ceil(Math.log2(decompressed_buffer.length));
            var number_of_offset_bits = (number_of_bits < 4) ? 4 : ((number_of_bits > 12) ? 12 : number_of_bits);

            var offset_bytes = this.get_int_from_bin(copy_token_bits.slice(0, number_of_offset_bits), this.BIG_ENDIAN) + 1;
            var byte_length = this.get_int_from_bin(copy_token_bits.slice(number_of_offset_bits), this.BIG_ENDIAN) + 3;
            current_byte += 2;

            // do the copy
            var offset_index = (decompressed_buffer.length) - offset_bytes;
            var end_index = offset_index + byte_length;
            var bytes_to_copy = decompressed_buffer.slice(offset_index, end_index);

            if (end_index > decompressed_buffer.length-1) {
              // source and target overlaps
              var length_diff = end_index - (decompressed_buffer.length);

              if (length_diff < bytes_to_copy.length) {
                // Overlap fits within the current copy buffer.
                bytes_to_copy.push(...bytes_to_copy.slice(0,length_diff));
              } else {
                // Overlap does not fit into current copy buffer
                var original_copy_bytes_len = bytes_to_copy.length;
                while (length_diff > 0) {
                  var overflow_bytes = bytes_to_copy.slice(0,length_diff);
                  bytes_to_copy.push(...overflow_bytes);
                  length_diff -= overflow_bytes.length;
                }
              }
            }

            decompressed_buffer.push(...bytes_to_copy);
          }
        }
      }

    } else {
      // Error, header block not found
    }

    // Remove null chars from the end of the array
    while (decompressed_buffer.at(-1) == 0 || decompressed_buffer.at(-1) === undefined || decompressed_buffer.at(-1) === null) {
      decompressed_buffer.pop();
    }

    return decompressed_buffer;
  }

  /**
   * Handles the calculation of Excell formulas and macros for a given sheet cell.
   *
   * @param {String}  cell_formula            The string value of a cell's formula.
   * @param {object}  spreadsheet_sheet_names This contains information on all the sheets within a spreadsheet.
   * @param {String}  active_sheet            The name of the active sheet withing the spreadsheet we are using.
   * @param {object}  file_info               The working file info object, passed so we can add analytic_findings and extracted_script code.
   * @return {String} The calculated output of a cell's formula.
   */
  calculate_cell_formula(cell_formula, spreadsheet_sheet_names, active_sheet, file_info) {
    var formula_output = "";

    var formula_regex = /\=?(?:null)?([a-zA-Z]+)\(([^\,\)]+\,?)([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?\)/gmi;
    var formula_matches = formula_regex.exec(cell_formula);

    while (formula_matches != null) {
      var formula_name = formula_matches[1];
      var formula_params = [];
      var param_index = 2;

      while (formula_matches[param_index] !== null && formula_matches[param_index] !== undefined) {
        if ((formula_matches[param_index].match(/\!/g) || []).length > 1) {
          //Multiple cell references
          if ((formula_matches[param_index].match(/(?:\&amp\;|&)/gmi) || []).length > 1) {
            // Concat
            var concat_result = "";
            var concat_parts = formula_matches[param_index].split("&amp;");
            concat_parts = (concat_parts.length > 1) ? concat_parts : concat_parts.split("&");

            for (var p=0; p<concat_parts.length; p++) {
              if (concat_parts[p].charAt(0) == "\"" && concat_parts[p].slice(-1) == "\"") {
                // String literal
                concat_result += concat_parts[p].slice(1,-1);
              } else {
                // Cell reference
                concat_result += this.get_ooxlm_cell_data(concat_parts[p], spreadsheet_sheet_names, active_sheet).value;
              }
            }

            // Look for nested string concat and do the concat.
            concat_result = concat_result.replaceAll(/(?:[\"\']\&amp\;[\"\']|\"?\&\"?)/gmi, "");
            formula_params[param_index] = concat_result;
          }
        } else {
          var cell_ref_obj = this.get_ooxlm_cell_data(formula_matches[param_index], spreadsheet_sheet_names, active_sheet);

          if (cell_ref_obj !== null && cell_ref_obj !== undefined) {
            if (cell_ref_obj.value !== null && cell_ref_obj.value !== undefined) {
              // Value is already calculated
              formula_params[param_index] = cell_ref_obj.value;
              formula_params[param_index] = formula_params[param_index].replaceAll(/[\"\']\&amp\;[\"\']/gmi, "");
            } else {
              // We will have to calculate this
              if (cell_ref_obj.formula !== null && cell_ref_obj.formula !== undefined) {
                formula_params[param_index] = this.calculate_cell_formula(cell_ref_obj.formula, spreadsheet_sheet_names, active_sheet);
              } else {
                // This cell will probably be used as a destination, just keep it null.
                formula_params[param_index] = null;
              }
            }
          } else {
            // Unknown cell
            formula_params[param_index] = "";
          }
        }

        param_index++;
      }

      this.execute_excel_formula(formula_name, formula_matches, formula_params, spreadsheet_sheet_names, active_sheet, file_info);

      formula_matches = formula_regex.exec(cell_formula);
    }

    return formula_output;
  }

  /**
   * Handles the execution of Excell formulas and macros.
   * Some formulas will not be executed or will be approximated.
   *
   * @param {String}  formula_name            The name of the formula we are going to execute.
   * @param {object}  formula_matches         A Javascript regex match object for the formula string.
   * @param {object}  formula_params          The computed parameters of the formula.
   * @param {object}  spreadsheet_sheet_names This contains information on all the sheets within a spreadsheet.
   * @param {String}  active_sheet            The name of the active sheet withing the spreadsheet we are using.
   * @param {object}  file_info               The working file info object, passed so we can add analytic_findings and extracted_script code.
   */
  execute_excel_formula(formula_name, formula_matches, formula_params, spreadsheet_sheet_names, active_sheet, file_info) {
    var macro_formula = formula_matches.input;

    if (formula_name.toUpperCase() == "ARABIC") {

    } else if (formula_name.toUpperCase() == "CALL") {
      if (!file_info.analytic_findings.includes("SUSPICIOUS - Use of CALL function")) {
        file_info.analytic_findings.push("SUSPICIOUS - Use of CALL function");
      }

      // Check for various cell references
      var dollar_sign_ref_regex = /(?:([a-zA-Z0-9]+)!)?\$([a-zA-Z]+)\$([0-9]+)/gmi;
      var dollar_sign_ref_match = dollar_sign_ref_regex.exec(macro_formula);
      var sheet_ref;

      while (dollar_sign_ref_match !== null) {
        if (dollar_sign_ref_match[1] !== null && dollar_sign_ref_match[1] !== undefined) {
          sheet_ref = dollar_sign_ref_match[1];
        } else {
          // No sheet ref, use acive sheet
          sheet_ref = active_sheet;
        }
        var cell_ref = dollar_sign_ref_match[2] + dollar_sign_ref_match[3];
        var cell_obj = spreadsheet_sheet_names[sheet_ref].data[cell_ref];
        var cell_val = "";

        if (cell_obj.value !== null) {
          cell_val = cell_obj.value;
        }

        macro_formula = macro_formula.replaceAll(dollar_sign_ref_match[0], cell_val);

        dollar_sign_ref_match = dollar_sign_ref_regex.exec(macro_formula);
      }

      file_info.scripts.extracted_script += macro_formula + "\n\n";
    } else if (formula_name.toUpperCase() == "CHAR") {
      //String.fromCharCode(stack_result)
    } else if (formula_name.toUpperCase() == "EXEC") {
      if (!file_info.analytic_findings.includes("SUSPICIOUS - Use of EXEC function")) {
        file_info.analytic_findings.push("SUSPICIOUS - Use of EXEC function");
      }

      file_info.scripts.extracted_script += formula_matches.input + "\n\n";
    } else if (formula_name.toUpperCase() == "FORMULA" || formula_name.toUpperCase() == "FILL") {
      /*  FORMULA(formula_text, reference)
          Formula_text - text, number, reference, or formula
          reference - Cell Reference
          Takes the value in formula_text and places it in the spreadsheet at the location defined by reference.

          FILL is often used in the same way as FORMULA.
      */
      var cell_name;
      var new_sheet_name;

      if (formula_matches[3].indexOf("!") > 0) {
        var cell_reference = formula_matches[3].split("!");
        new_sheet_name = cell_reference[0].replaceAll("'", "");
        new_sheet_name = new_sheet_name.replaceAll("\"", "");
        cell_name = cell_reference[1];
      } else {
        // No sheet ref, use acive sheet
        cell_name = formula_matches[3];
        new_sheet_name = active_sheet;
      }

      if (spreadsheet_sheet_names[new_sheet_name].data[cell_name] !== null && spreadsheet_sheet_names[new_sheet_name].data[cell_name] !== undefined) {
        spreadsheet_sheet_names[new_sheet_name].data[cell_name].value = formula_params[2];
      } else {
        // create new value
        spreadsheet_sheet_names[new_sheet_name].data[cell_name] = {
          'formula': null,
          'value': formula_params[2]
        }
      }

      if (/\=[a-zA-Z]+\s*\(/gmi.test(formula_params[2])) {
        var formula_regex = /\=?([a-zA-Z]+)\(([^\,\)]+\,?)([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?\)/gmi;
        var formula_matches = formula_regex.exec(formula_params[2]);

        if (formula_matches != null) {
          this.execute_excel_formula(formula_matches[1], formula_matches, [], spreadsheet_sheet_names, active_sheet, file_info);
        }
      }
    } else if (formula_name.toUpperCase() == "_XLFN.ARABIC") {

    } else {
      console.log(formula_name + " function has not been implemented yet.")
    }
  }

/**
 * Executes the XLS / Excel 4.0 calculation stack.
 *
 * @param {array}    stack The list of operations to execute.
 * @param {object}   workbook The document object containing sheets, variables, etc.
 * @return {boolean} The result of the execution / calculation.
 */
  execute_excel_stack(stack, workbook) {
  var c_index = 0;

    while (c_index < stack.length && c_index >= 0) {
      if (stack[c_index].type == "operator") {
        if (stack[c_index].value == "-") {
          var param1 = stack[c_index-2];
          var param2 = stack[c_index-1];
          var sub_result = 0;

          if (param1.type == "number" && param2.type == "number") {
            sub_result = param1.value - param2.value;
          } else if (param1.type == "string" && param2.type == "number") {
            sub_result = param2.value;
          } else if (param1.type == "number" && param2.type == "string") {
            sub_result = param1.value ;
          } else if (param1.type == "reference" || param2.type == "reference") {
            sub_result = param1.value + " - " + param2.value;
          }

          stack.splice(c_index-2, 3, {
            'value': sub_result,
            'type': "number"
          });
          c_index--;
        } else if (stack[c_index].value == "+") {
          var sub_result = stack[c_index-2].value + stack[c_index-1].value;
          stack.splice(c_index-2, 3, {
            'value': sub_result,
            'type': "number"
          });
          c_index--;
        } else if (stack[c_index].value == "*") {
          var sub_result = stack[c_index-2].value * stack[c_index-1].value;
          stack.splice(c_index-2, 3, {
            'value': sub_result,
            'type': "number"
          });
          c_index--;
        } else if (stack[c_index].value == "/") {
          var sub_result = stack[c_index-2].value / stack[c_index-1].value;
          stack.splice(c_index-2, 3, {
            'value': sub_result,
            'type': "number"
          });
          c_index--;
        } else if (stack[c_index].value == "^") {
          var sub_result = Math.pow(stack[c_index-2].value, stack[c_index-1].value);
          stack.splice(c_index-2, 3, {
            'value': sub_result,
            'type': "number"
          });
          c_index--;
        } else if (stack[c_index].value == "&") {
          // Concat
          if (c_index > 1) {
            var val1 = (stack[c_index-2] !== null && stack[c_index-2] !== undefined && stack[c_index-2].value !== null) ? stack[c_index-2].value : "";
            var val2 = (stack[c_index-1] !== null && stack[c_index-1] !== undefined && stack[c_index-1].value !== null) ? stack[c_index-1].value : "";
            var sub_result = String(val1) + String(val2);

            stack.splice(c_index-2, 3, {
              'value': sub_result,
              'type': "string"
            });
            c_index--;
          } else {
            // Wrong argument number, skip for now
            c_index++;
          }

        } else if (stack[c_index].value == "==") {
          // comparison
          if (c_index == 0) {
            // TODO: Implement this more fully. Currently we are just skipping it.
            stack.shift();
          } else {
            if (c_index > 1) {
              var sub_result = (String(stack[c_index-2].value) == String(stack[c_index-1].value));
            }

            c_index++;
          }
        } else if (stack[c_index].value == "!=") {
          // not comparison
          if (c_index == 0) {
            // TODO: Implement this more fully. Currently we are just skipping it.
            stack.shift();
          } else {
            if (c_index > 1) {
              var sub_result = (String(stack[c_index-2].value) != String(stack[c_index-1].value));
            }

            c_index++;
          }
        } else if (stack[c_index].value == "[]") {
          // TODO: Implement this more fully.
          if (stack[c_index-1].value.charAt(0) == "=") {
            var code_script = stack[c_index-1].value.replaceAll(/\\?[\"\']&\\?[\"\']/gm, "");
            file_info.scripts.extracted_script += code_script + "\n\n";

            if (code_script.substr(0,3).toUpperCase() == "=IF") {
              // TODO return the actual valuse
              stack.splice(c_index-1, 2, {'value': "true",'type': "string"});
            } else {
              // return true
              stack.splice(c_index-1, 2, {'value': "true",'type': "string"});
            }
          } else {

          }
       } else if (stack[c_index].value == "=") {
         // Assigment, this works the same way as SET.NAME but the stack order is different.
         if (c_index == 0) {
           if (stack.length >= 3) {
             var param1 = stack[c_index+1];
             var param2 = stack[c_index+2];
             var formula = "";

             param2 = (param2.length > 0) ? param2 : "\"\"";

             if (param1.type == "string" || param1.type == "reference") {
               workbook.varables[param1.value] = param2.value;
               formula = "SET.NAME(" + param1.value + ", " + param2.value + ")";
               stack.splice(c_index, 3, {
                 'value': formula ,
                 'type': "string"
               });

               if (c_index+1 < stack.length && stack[c_index+1].value == "_xlfn.SET.NAME") {
                 stack.splice(c_index+1, 1);
               }
               // TODO check for references in param2
             }
           }
         }

         c_index++;
       } else {
          console.log("Unknown Operator: " + stack[c_index].value);
          c_index++;
        }
      } else {
        if (stack[c_index].type == "string") {
          if (stack[c_index].value !== null && stack[c_index].value !== undefined) {
            try {
              if (String(stack[c_index].value).substring(0, 6).toLowerCase() == "_xlfn.") {
                // Execute an Excel function.
                var function_name = stack[c_index].value.substring(6);

                if (function_name == "ARABIC") {
                  var sub_result = Static_File_Analyzer.convert_roman_numeral_to_int(stack[c_index+1].value);
                  stack.splice(c_index, 2);
                  stack.unshift({
                    'value': sub_result,
                    'type': "number"
                  });
                  c_index++;
                } else if (function_name == "CHAR") {
                  if (c_index > 0) {
                    var sub_result = String.fromCharCode(stack[c_index-1].value);
                    stack.splice(c_index-1, 2, {
                      'value': sub_result,
                      'type': "number"
                    });
                  }
                  c_index++;
                } else if (function_name == "COUNT") {
                  c_index++;
                } else if (function_name == "COUNTA") {
                  // COUNTA - counts the number of cells that are not empty in a range. Two params start_cell, end_cell
                  c_index++;
                } else if (function_name == "EXEC") {
                  var param_count = stack[c_index].params;
                  var exec_cmd = "";

                  for (var rpi=c_index-param_count; rpi<c_index; rpi++) {
                    exec_cmd += stack[rpi].value + ",";
                  }
                  exec_cmd = exec_cmd.slice(0,-1);

                  // When executing a command ^ is a special, escape charater that will be ignored.
                  // It is often used to obfusticate cmd codes.
                  exec_cmd = exec_cmd.replaceAll("^", "");
                  var sub_result = "=EXEC(" + exec_cmd + ")"

                  stack.splice(0, c_index+1);
                  stack.unshift({
                    'value': sub_result,
                    'type': "string"
                  });

                  c_index++;
                } else if (function_name == "HALT") {
                  c_index++;
                } else if (function_name == "IF") {
                  var sub_result = false;
                  var formula = "=IF(";

                  if (stack[c_index-1].type == "operator") {
                    var op_param1 = stack[c_index-3];
                    var op_param2 = stack[c_index-2];

                    if (stack[c_index-1].value == "==") {
                      formula += op_param1.value + " == " + op_param2.value;
                      sub_result = (op_param1.value == op_param2);
                    } else if (stack[c_index-1].value == "!=") {
                      formula += op_param1.value + " != " + op_param2.value;
                      sub_result = (op_param1.value != op_param2);
                    } else if (stack[c_index-1].value == "<") {
                      formula += op_param1.value + " < " + op_param2.value;
                      sub_result = (op_param1.value < op_param2);
                    } else if (stack[c_index-1].value == ">") {
                      formula += op_param1.value + " > " + op_param2.value;
                      sub_result = (op_param1.value > op_param2);
                    }
                  } if (stack[c_index-1].type == "boolean") {
                    formula += stack[c_index-1].value;
                    sub_result = stack[c_index-1].value;
                  }
                  formula += ")";

                  stack.splice(0, c_index+1);
                  stack.unshift({
                    'value':   sub_result,
                    'type':    "boolean",
                    'formula': formula
                  });

                  c_index++;
                } else if (function_name == "ISNUMBER") {
                  c_index++;
                } else if (function_name == "REGISTER") {
                  var sub_result = "=REGISTER(";
                  var reg_params = stack.slice(0,c_index);

                  for (var rpi=0; rpi<reg_params.length; rpi++) {
                    sub_result += reg_params[rpi].value + ",";
                  }

                  sub_result = sub_result.slice(0,-1) + ")";
                  stack.splice(0, c_index+1);
                  stack.unshift({
                    'value':   sub_result,
                    'type':    "string",
                    'formula': sub_result
                  });
                  c_index++;
                } else if (function_name == "RETURN") {
                  var sub_result = "=RETURN(";
                  var reg_params = stack.slice(0,c_index);

                  for (var rpi=0; rpi<reg_params.length; rpi++) {
                    sub_result += reg_params[rpi].value + ",";
                  }

                  sub_result = sub_result.slice(0,-1) + ")";
                  stack.splice(0, c_index+1);
                  stack.unshift({
                    'value': sub_result,
                    'type': "string"
                  });
                  c_index++;
                } else if (function_name == "SET.NAME") {
                  var param1 = {'value': null, 'type': "string"};
                  var param2 = {'value': null, 'type': "string"};
                  var op_stack_length = 1;

                  if (stack[c_index].params == 2) {
                    if (stack.length >= 3) {
                      param1 = stack[c_index-1];
                      param2 = stack[c_index-2];
                      op_stack_length += 2;
                    } else if (stack.length == 2) {
                      param1 = stack[c_index-1];
                      op_stack_length += 1;
                    } else {
                      console.log("Error Invalid number of stack parameters for SET.NAME.")
                    }
                  }

                  var ref_match = /R\[?(\-?\d+)?\]?C\[?(\-?\d+)?\]?/gmi.exec(param2.value);
                  if (ref_match !== null) {
                    var row_shift = (ref_match[1] !== undefined) ? ref_match[1] : 0;
                    var col_shift = (ref_match[2] !== undefined) ? ref_match[2] : 0;

                    var new_cell_ref = this.get_shifted_cell_name(workbook.current_cell,row_shift,col_shift);
                    if (workbook.sheets[workbook.current_sheet_name].data.hasOwnProperty(new_cell_ref)) {
                      param2 = workbook.sheets[workbook.current_sheet_name].data[new_cell_ref];
                    } else {
                      param2 = "@" + workbook.current_sheet_name + "!" + new_cell_ref;
                    }
                  }

                  if (param2.value !== null) {
                    if (param2.type == "string") {
                      workbook.varables[param2.value] = param1.value;
                    } else if (param2.type == "reference") {
                      if (param2.value.charAt(0) == "@") {
                        var sheet_name = workbook.current_sheet_name;
                        var cell_ref = param2.value

                        if (param2.value.indexOf("!") > 0) {
                          sheet_name = param2.value.split("!")[0];
                          cell_ref = param2.value.split("!")[1];
                        }

                        if (workbook.sheets.hasOwnProperty(sheet_name)) {
                          workbook.sheets[sheet_name].data[cell_ref] = param1.value;
                        }
                      } else {
                        workbook.varables[param2.value] = param1.value;
                      }
                    }
                  }

                  if (param1.type == "reference") {
                    if (param1.value.charAt(0) == "@") {
                      var sheet_name = workbook.current_sheet_name;
                      var cell_ref = param1.value

                      if (cell_ref.indexOf("!") > 0) {
                        sheet_name = cell_ref.split("!")[0].substring(1);
                        cell_ref = cell_ref.split("!")[1];
                      }

                      if (workbook.sheets.hasOwnProperty(sheet_name)) {
                        if (workbook.sheets[sheet_name].data.hasOwnProperty(cell_ref)) {
                          param1.value = workbook.sheets[sheet_name].data[cell_ref];
                        } else {
                          var recalc_cell = workbook.current_sheet_name+"!"+workbook.current_cell;
                          if (!workbook.recalc_objs.includes(recalc_cell)) {
                            workbook.recalc_objs.push(recalc_cell);
                          }
                        }
                      }
                    }
                  }

                  var formula = "=SET.NAME(" + param2.value + ", " + param1.value + ")";
                  stack.splice(c_index-op_stack_length, c_index+1);
                  stack.unshift({
                    'value':   param1.value,
                    'type':    param1.type,
                    'formula': formula
                  });
                  c_index++;
                } else if (function_name == "SIGN") {
                  // Determines the sign of a number. Returns 1 if the number is positive, zero (0) if the number is 0, and -1 if the number is negative.
                  c_index++;
                } else if (function_name == "USERFUNCTION") {
                  // TODO finish implementation of user defined functions
                  if (stack.length > stack[c_index].params) {
                    var params = stack.slice(c_index - stack[c_index].params, c_index);
                    var params2 = [];
                    var user_func_name = params[0].value;
                    var ref_name = "";

                    if (params.length > 1) {
                      for (var pi=1; pi<params.length; pi++) {
                        params2.push(params[pi].value);
                      }
                    }

                    var user_func_name = (params[0].hasOwnProperty("ref_name")) ? params[0].ref_name : params[0].value;
                    var sub_result = user_func_name + "(" + params2.join(",") + ")";

                    if (params[0].hasOwnProperty("ref_name")) {
                      user_func_name = params[0].ref_name;
                      ref_name = params[0].ref_name;

                      stack.splice(c_index-params.length, c_index+1, {
                        'value': sub_result,
                        'type': "string",
                        'ref_name': ref_name
                      });
                    } else {
                      stack.splice(c_index-params.length, c_index+1, {
                        'value': sub_result,
                        'type': "string"
                      });
                    }
                  }

                  c_index++;
                } else {
                  // Unknown function
                  console.log("Unknown Function");
                  c_index++;
                }
              } else {
                var cell_ref_match = /\@([a-zA-Z0-9]+)\!(\w+[0-9]+)/gm.exec(stack[c_index]);
                if (cell_ref_match !== null) {
                  // Cell Reference
                  if (workbook.sheets[cell_ref_match[1]].data.hasOwnProperty(cell_ref_match[2])) {
                    var ref_cell = workbook.sheets[cell_ref_match[1]].data[cell_ref_match[2]];
                    stack.splice(c_index, 1, {
                      'value': ref_cell.value,
                      'type': "string"
                    });
                  } else {
                    // Add to recalc
                    workbook.recalc_objs.push(workbook.current_cell);
                  }
                }
                // Skip other stirngs for now

                c_index++;
              }
            } catch(err) {
              console.log(err);
              c_index++;
            }
          } else {
            // Program error somewhere :(
            c_index++;
          }

        } else {
          // Skip numbers and strings
          c_index++
        }
      }
    }

    if (stack.length > 1) {
      // If the stack still has multiple items, something is wrong.
    }

    return stack[0];
  }

  /**
   * Extract attributes from a Visual Basic for Applications (VBA) file.
   *
   * @param {Uint8Array}           file_bytes Array with int values 0-255 representing the bytes of the VBA file to be analyzed.
   * @return {{attributes: array}} The attributes of the given VBA file bytes.
   */
  extract_vba(file_bytes) {
    var vba_data = {
      'attributes': []
    };

    var root_entry_start = -1;
    var attribute_start = -1;
    var found_attributes = [];

    // Find Attributes
    for (var i=0; i<file_bytes.length-19;i++) {
      if (this.array_equals(file_bytes.slice(i,i+19), [82,0,111,0,111,0,116,0,32,0,69,0,110,0,116,0,114,0,121])) {
        root_entry_start = i;
      } else if (this.array_equals(file_bytes.slice(i,i+5), [73,68,61,34,123])) {
        // ID="{
        var project_stream_start = i;
        var project_stream_end = project_stream_start + 639;
        var project_stream_str = Static_File_Analyzer.get_ascii(file_bytes.slice(project_stream_start,project_stream_end));

        // End any open attributes
        var decompressed_vba_attribute_bytes = this.decompress_vba(file_bytes.slice(attribute_start, i));
        vba_data.attributes.push(Static_File_Analyzer.get_ascii(decompressed_vba_attribute_bytes));
      } else if (this.array_equals(file_bytes.slice(i,i+8), [65,116,116,114,105,98,117,116])) {
        // Attribute
        if (attribute_start > 0) {
          var decompressed_vba_attribute_bytes = this.decompress_vba(file_bytes.slice(attribute_start, i));
          vba_data.attributes.push(Static_File_Analyzer.get_ascii(decompressed_vba_attribute_bytes));
          attribute_start = i-4;
        } else {
          attribute_start = i-4;
        }
      }
    }

    return vba_data;
  }

  /**
   * Compares two arrays to check if every value in the two given arrays are equal.
   *
   * @param {array}  a Any array to compare.
   * @param {array}  b Any array to compare.
   * @return {boolean} Returns true if every value in the two given arrays are equal.
   */
  array_equals(a, b) {
    if ((this.is_typed_array(a) || Array.isArray(a)) && (this.is_typed_array(b) || Array.isArray(b))) {
      return a.length === b.length && a.every((val, index) => val === b[index]);
    } else {
      return false;
    }
  }

  /**
   * Returns the ASCII representation of an array of bytes.
   * @static
   *
   * @param {array}   text_bytes Array with int values 0-255 representing byte values.
   * @return {string} The ASCII representation of the bytes given.
   */
  static get_ascii(text_bytes) {
    var ascii_text = "";

    for (let i = 0; i < text_bytes.length; i++) {
      ascii_text += String.fromCharCode(parseInt(text_bytes[i]));
    }

    return ascii_text;
  }

  /**
   * Calculates the BIFF12 record number and size given the to possilbe record bytes
   *
   * @param {array} record_bytes An array with 2-6 elements, each a an integer from 0-255.
   * @return {{record_number: integer, record_size: integer, offset: integer} The BIFF12 record number, size and byte offset increment. Returns a record number of -1 if record could not be determined.
   */
  get_biff12_record_info(record_bytes) {
    var record_bits = [];
    var record_number = -1;
    var record_size = 0;
    var record_size_bytes = [];
    var record_size_start = 0;

    // We need the bits of each byte
    for (var i=0; i<record_bytes.length; i++) {
      record_bits.push(this.get_bin_from_int(record_bytes[i]));
    }

    // Get the record number, records are one or two bytes depending on the first bit.
    if (record_bits[0][0] == 1) {
      // Two byte record number, only use the last 7 bits of each byte to get record number.
      record_number = this.get_int_from_bin(record_bits[1].slice(1)) * 128 + this.get_int_from_bin(record_bits[0].slice(1));
      record_size_start = 2;
    } else {
      // One byte record number, only use the last 7 bits to get record number.
      record_number = this.get_int_from_bin(record_bits[0].slice(1));
      record_size_start = 1;
    }

    // Get the record size, this can be 1-4 bytes.
    // The high bit in each byte specifies whether an additional byte is used.
    for (var i=0; i<4; i++) {
      record_size_bytes.push(this.get_int_from_bin(record_bits[record_size_start+i].slice(1)));
      if (record_bits[record_size_start+i][0] == 0) {
        break;
      }
    }

    record_size = record_size_bytes[0];
    for (var i=1; i<record_size_bytes.length; i++) {
      record_size += record_size_bytes[i] * (i*128);
    }

    return {
      'record_number': record_number,
      'record_size':   record_size,
      'offset':        record_size_start + record_size_bytes.length
    };
  }

  /**
   * Converts a number, given as an integer, to a binary array.
   *
   * @param {integer} integer A integer value to be converted to binary.
   * @return {array}  An array with int values of 0 or 1, representing the binary value of the given integer.
   */
  get_bin_from_int(integer) {
    var binary_array = Array(8);
    var bin_str = ("00000000" + (integer >>> 0).toString(2)).slice(-8);

    binary_array[0] = parseInt(bin_str.charAt(0));
    binary_array[1] = parseInt(bin_str.charAt(1));
    binary_array[2] = parseInt(bin_str.charAt(2));
    binary_array[3] = parseInt(bin_str.charAt(3));
    binary_array[4] = parseInt(bin_str.charAt(4));
    binary_array[5] = parseInt(bin_str.charAt(5));
    binary_array[6] = parseInt(bin_str.charAt(6));
    binary_array[7] = parseInt(bin_str.charAt(7));

    return binary_array;
  }

  /**
   * Converts an array with int values 0-255 to a binary array.
   *
   * @param {array} u8int_array Array with int values 0-255 representing byte values.
   * @return {array}  An array with int values of 0 or 1, representing the binary value of the given integer.
   */
  get_binary_array(u8int_array) {
    var binary_array = Array(u8int_array.length * 8);
    var bin_str = "";

    for (var bi=0; bi<u8int_array.length; bi++) {
      bin_str = ("00000000" + (u8int_array[bi]).toString(2)).slice(-8);

      binary_array[bi*8+0] = parseInt(bin_str.charAt(0));
      binary_array[bi*8+1] = parseInt(bin_str.charAt(1));
      binary_array[bi*8+2] = parseInt(bin_str.charAt(2));
      binary_array[bi*8+3] = parseInt(bin_str.charAt(3));
      binary_array[bi*8+4] = parseInt(bin_str.charAt(4));
      binary_array[bi*8+5] = parseInt(bin_str.charAt(5));
      binary_array[bi*8+6] = parseInt(bin_str.charAt(6));
      binary_array[bi*8+7] = parseInt(bin_str.charAt(7));
    }

    return binary_array;
  }

  /**
   * Created the default object structure for the output of this class.
   *
   * @return {object} The defaut object structure for the analyzed file.
   */
  get_default_file_json() {
    return {
      file_format: "unknown",
      file_generic_type: "unknown",
      file_format_ver: "unknown",
      file_encrypted: "unknown",
      file_encryption_type: "unknown",
      file_components: [],
      metadata: {
        author: "unknown",
        creation_application: "unknown",
        creation_os: "unknown",
        creation_date: "0000-00-00 00:00:00",
        description: "unknown",
        last_modified_date: "0000-00-00 00:00:00",
        last_saved_location: "unknown",
        title: "unknown",
      },
      scripts: {
        script_type: "none",
        extracted_script: "",
      },
      analytic_findings: [],
      iocs: []
    };
  }

  /**
   * Converts an array with eight int values 0-255 to a date.
   * Bytes must be a 64 bit integer representing the number of 100-nanosecond intervals since January 1, 1601
   *
   * @param {array}    bytes Array with eight int values 0-255 representing byte values.
   * @param {String}   endianness Value indicating how to interperate the bit order of the byte array. Default is BIG_ENDIAN.
   * @return {integer} The integer value of the given bit array.
   */
  get_eight_byte_date(bytes, endianness = this.BIG_ENDIAN) {
    var int_bits = "";

    if (endianness == this.LITTLE_ENDIAN) {
      for (var byte_index = (bytes.length-1); byte_index >= 0; byte_index--) {
        int_bits += ("00000000" + (bytes[byte_index]).toString(2)).slice(-8);
      }
    } else {
      for (var byte_index = 0; byte_index < bytes.length; byte_index++) {
        int_bits += ("00000000" + (bytes[byte_index]).toString(2)).slice(-8);
      }
    }

    try {
      var int_val = parseInt(int_bits, 2);
      var date_obj = new Date((int_val-116444736000000000)/10000);
      return date_obj.toISOString();
    } catch (error) {
      return new Date(0).toISOString();
    }

  }

  /**
   * Converts an array with int values 0 or 1 to unsined integer.
   *
   * @param {array}    binary_array Array with int values 0 or 1 representing binary values.
   * @param {String}   endianness Value indicating how to interperate the bit order of the binary array. Default is BIG_ENDIAN.
   * @return {integer} The integer value of the given bit array.
   */
  get_int_from_bin(binary_array, endianness = this.BIG_ENDIAN) {
    var int_val = 0;

    if (endianness == this.LITTLE_ENDIAN) {
      for (var i=0; i<binary_array.length; i++) {
        int_val += binary_array[i] * Math.pow(2, i);
      }
    } else {
      var bit_pos = 0;
      for (var i=binary_array.length-1; i>=0; i--) {
        int_val += binary_array[i] * Math.pow(2, bit_pos);
        bit_pos++;
      }
    }

    return int_val;
  }

  /**
   * Converts a Hex encoded IP into the standard format; only does IPv4.
   *
   * @throws An error if hex_ip is not in the correct format.
   *
   * @param {String}  hex_ip IP in the format of 0xXXXXXXXX
   * @return {String} IP address in standard notation
   */
  static get_ip_from_hex(hex_ip) {
    if (/0x[0-9a-f]{8}/gmi.test(hex_ip)) {
      var str_ip = "";

      for (var i=0; i<hex_ip.length; i+=2) {
        if (i==0) continue;
        str_ip += parseInt(hex_ip.substr(i,2), 16) + ".";
      }

      return str_ip.slice(0, -1);
    } else {
      throw "The provided hex IP is not formatted correctly.";
    }
  }

  /**
   * Converts an array with four int values 0-255 to an integer.
   *
   * @param {array}    bytes Array with four int values 0-255 representing byte values.
   * @param {String}   endianness Value indicating how to interperate the bit order of the byte array. Default is BIG_ENDIAN.
   * @return {integer} The integer value of the given bit array.
   */
  get_four_byte_int(bytes, endianness = this.BIG_ENDIAN) {
    var int_bits = "";

    if (endianness == this.LITTLE_ENDIAN) {
      for (var byte_index = (bytes.length-1); byte_index >= 0; byte_index--) {
        int_bits += ("00000000" + (bytes[byte_index]).toString(2)).slice(-8);
      }
    } else {
      for (var byte_index = 0; byte_index < bytes.length; byte_index++) {
        int_bits += ("00000000" + (bytes[byte_index]).toString(2)).slice(-8);
      }
    }

    return parseInt(int_bits, 2);
  }

  /**
   * Converts an array with two int values 0-255 to an integer.
   *
   * @param {array}    bytes Array with two int values 0-255 representing byte values.
   * @param {String}   endianness Value indicating how to interperate the bit order of the byte array. Default is BIG_ENDIAN.
   * @return {integer} The integer value of the given bit array.
   */
  get_two_byte_int(bytes, endianness = this.BIG_ENDIAN) {
    var int_bits = "";

    if (endianness == this.LITTLE_ENDIAN) {
      for (var byte_index = (bytes.length-1); byte_index >= 0; byte_index--) {
        int_bits += ("00000000" + (bytes[byte_index]).toString(2)).slice(-8);
      }
    } else {
      for (var byte_index = 0; byte_index < bytes.length; byte_index++) {
        int_bits += ("00000000" + (bytes[byte_index]).toString(2)).slice(-8);
      }
    }

    return parseInt(int_bits, 2);
  }

  /**
   * Converts an array with four int values 0-255 to a msdos timestamp.
   *
   * @see http://ntfs.com/exfat-time-stamp.htm
   *
   * @param {array}   bytes Array with four int values 0-255 representing byte values.
   * @return {String} The timestamp converted from the four byte array.
   */
  get_msdos_timestamp(date_bytes) {
    var timestamp_bits = "";

    for (var byte_index = date_bytes.length-1; byte_index >= 0; byte_index--) {
      timestamp_bits += ("00000000" + (date_bytes[byte_index]).toString(2)).slice(-8);
    }

    var date_int = parseInt(timestamp_bits, 2);

    var time_bits = timestamp_bits.slice(0,16);
    var year = ((date_int >> 25) & 127) + 1980;
    var month = ((date_int >> 21) & 15).toString();
    var day = ((date_int >> 16) & 31).toString();
    var hour = ((date_int >> 11) & 31).toString();
    var minute = ((date_int >> 5) & 63).toString();
    var second = ((date_int << 1) & 63).toString();

    month = month.length < 2 ? "0"+month : month;
    day = day.length < 2 ? "0"+day : day;
    hour = hour.length < 2 ? "0"+hour : hour;
    minute = minute.length < 2 ? "0"+minute : minute;
    second = second.length < 2 ? "0"+second : second;

    var msdos_date = year + "-" + month + "-" + day + " " + hour + ":" + minute + ":" + second;

    return msdos_date;
  }

  /**
   * Builds an object containing the formula, if there is one, and the value of a cell in an OOXLM spreadsheet.
   *
   * @param {string}  cell_ref                The cell reference to get data from. Usualy in the format [sheet_name]![column][row] but can be just [column][row].
   * @param {object}  spreadsheet_sheet_names This contains information on all the sheets within a spreadsheet.
   * @param {string}  active_sheet            The name of the active sheet withing the spreadsheet we are using.
   * @return {{formula: String, value: String}} An object containing the formula and value of a given cell.
   */
  get_ooxlm_cell_data(cell_ref, spreadsheet_sheet_names, active_sheet) {
    var sheet_name;
    var cell_name;

    if (cell_ref.indexOf("!") > 0) {
      var cell_ref_parts = cell_ref.split("!");
      sheet_name = cell_ref_parts[0];
      cell_name = cell_ref_parts[1];
    } else {
      // No sheet reference, use active sheet
      sheet_name = active_sheet;
      cell_name = cell_ref;
    }

    // Remove quotes and commas
    sheet_name = sheet_name.replaceAll("'", "");
    sheet_name = sheet_name.replaceAll("\"", "");
    cell_name = cell_name.replaceAll(",", "");

    var cell_data_obj = spreadsheet_sheet_names[sheet_name].data[cell_name];

    if (cell_data_obj !== null && cell_data_obj !== undefined) {
      return cell_data_obj;
    } else {
      // No value found
      return {
        'formula': null,
        'value': null
      };
    }
  }

  /**
   * Returns a new cell reference based on a relative row and column shift.
   *

   * @param {String}   current_cell Array with int values 0-255 representing byte values.
   * @param {integer}  row_shift Array with int values 0-255 representing byte values.
   * @param {integer}  col_shift Array with int values 0-255 representing byte values.
   * @return {string}  A new cell reference based on the given relative row and column shift values.
   */
  get_shifted_cell_name(current_cell, row_shift=0, col_shift=0) {
    var sheet_ref = "";
    var return_val = current_cell;

    row_shift = parseInt(row_shift);
    col_shift = parseInt(col_shift);

    if (current_cell.indexOf("!") >= 0) {
      sheet_ref = current_cell.split("!")[0];
      current_cell = current_cell.split("!")[1];
    }

    var cell_match = /([a-zA-Z]+)([0-9]+)/gm.exec(current_cell);

    if (cell_match !== null) {
      var current_col = cell_match[1];
      var current_row = parseInt(cell_match[2]);
      current_row += row_shift;

      for (var i=1; i<=col_shift; i++) {
        current_col = increment_xls_column(current_col);
      }

      if (sheet_ref == "") {
        return_val = current_col + current_row;
      } else {
        return_val = sheet_ref + "!" + current_col + current_row;
      }
    }

    return return_val;
  }

  /**
   * Returns the Unicode representation of an array of bytes.
   * This code is coppied from Ed Wynne's blog on weblog.rogueamoeba.com
   * @static
   *
   * @see https://weblog.rogueamoeba.com/2017/02/27/javascript-correctly-converting-a-byte-array-to-a-utf-8-string/
   *
   * @param {array}   text_bytes Array with int values 0-255 representing byte values.
   * @return {string} The Unicode representation of the bytes given.
   */
  static get_string_from_array(text_bytes) {
      const extra_byte_map = [ 1, 1, 1, 1, 2, 2, 3, 0 ];
      var count = text_bytes.length;
      var str = "";

      for (var index = 0;index < count;) {
        var ch = text_bytes[index++];

        if (ch & 0x80) {
          var extra = extra_byte_map[(ch >> 3) & 0x07];
          if (!(ch & 0x40) || !extra || ((index + extra) > count))
            return null;

          ch = ch & (0x3F >> extra);
          for (;extra > 0;extra -= 1) {
            var chx = text_bytes[index++];
            if ((chx & 0xC0) != 0x80)
              return null;

            ch = (ch << 6) | (chx & 0x3F);
          }
        }

        str += String.fromCharCode(ch);
      }

      return str;
    }

  /**
   * Gets the content an XLS cell.
   *
   * @param {string}  cell_ref A string in the form of Sheetname!ColumnRow
   * @param {object}  sheet    The object containing all sheets and their data.
   * @return {Object} The found cell object.
   */
  get_xls_cell(cell_ref, sheets) {
    var cell_obj;
    var cell_ref_arr = cell_ref.split("!");
    var sheet_obj;

    if (sheets.hasOwnProperty(cell_ref_arr[0]) && sheets[cell_ref_arr[0]].data.hasOwnProperty(cell_ref_arr[1])) {
      sheet_obj = sheets[cell_ref_arr[0]];
    } else {
      for (const [key, value] of Object.entries(sheets)) {
        sheet_obj = value;

        if (sheets[key].data.hasOwnProperty(cell_ref_arr[1])) {
          break;
        }
      }
    }

    if (sheet_obj !== undefined && sheet_obj.data !== undefined) {
      if (sheet_obj.data.hasOwnProperty(cell_ref_arr[1])) {
        cell_obj = sheet_obj.data[cell_ref_arr[1]];
      } else {
        // Error return blank cell
        cell_obj = {
          'formula': null,
          'value': ""
        }
      }
    } else {
      // Error return blank cell
      cell_obj = {
        'formula': null,
        'value': ""
      }
    }

    // Check to see if there are unresolved cell references in call value.
    var at_ref_match = /@([a-zA-Z0-9]+\![a-zA-Z]+[0-9]+)/gmi.exec(cell_obj.value);

    while (at_ref_match !== null) {
      var ref_val = this.get_xls_cell(at_ref_match[1], sheets).value;

      if (ref_val != "") {
        cell_obj.value = cell_obj.value.replace(at_ref_match[0],ref_val);
        at_ref_match = /@([a-zA-Z0-9]+\![a-zA-Z]+[0-9]+)/gmi.exec(cell_obj.value);
      }
    }

    return cell_obj;
  }

  /**
   * Gets the content of the XML tag from a given start index.
   *
   * @param {string}  source_text String representing an XML file.
   * @param {string}  tag_name The name of the XLM tag to extract content from.
   * @param {int}     start_index The start index within the source_text to start looking for the tag_name.
   * @return {String} The extracted content of the XML tag.
   */
  get_xml_tag_content(source_text, tag_name, start_index=0) {
    var open_tag = "<" + tag_name;
    var closetag = "</" + tag_name + ">";

    var tag_content = "";
    var open_tag_start = source_text.indexOf(open_tag, start_index) + open_tag.length;

    if (open_tag_start > open_tag.length) {
      var open_tag_end = source_text.indexOf(">", open_tag_start);
      var content_start = open_tag_end + 1;
      var content_end = source_text.indexOf(closetag, content_start);
      var tag_content = source_text.substring(content_start, content_end);
    } else {
      return "unknown";
    }

    return tag_content;
  }

  /**
   * Returns the extracted compression and encryption types of a Zip file.
   * This is a helper function for analyze_zip.
   *
   * @param {array}   extract_version_bytes Array with int values 0-255 representing byte values.
   * @return {{file_compression_method: string, file_encryption_type: string}} The extracted compression and encryption types
   */
  get_zip_extract_version_properties(extract_version_bytes) {
    var extract_version_properties = {
      file_compression_method: "unknown",
      file_encryption_type: "none"
    };

    switch (extract_version_bytes[0]) {
      case 10:
        // Default value
        break;
      case 11:
        // File is a volume label
        break;
      case 20:
        // File is a folder (directory)
        // File is compressed using Deflate compression
        // File is encrypted using traditional PKWARE encryption
        extract_version_properties.file_compression_method = "Deflate";
        break;
      case 21:
        // File is compressed using Deflate64(tm)
        extract_version_properties.file_compression_method = "Deflate64";
        break;
      case 25:
        // File is compressed using PKWARE DCL Implode
        extract_version_properties.file_compression_method = "PKWARE";
        break;
      case 27:
        // File is a patch data set
        break;
      case 45:
        // File uses ZIP64 format extensions
        break;
      case 46:
        // File is compressed using BZIP2 compression
        extract_version_properties.file_compression_method = "BZIP2";
        break;
      case 50:
        // File is encrypted using DES
        extract_version_properties.file_encryption_type = "DES";
        break;
      case 50:
        // File is encrypted using DES
        // File is encrypted using 3DES
        // File is encrypted using original RC2 encryption
        extract_version_properties.file_encryption_type = "DES";
        break;
      case 51:
        // File is encrypted using AES encryption
        // File is encrypted using corrected RC2 encryption
        extract_version_properties.file_encryption_type = "AES";
        break;
      case 52:
        // File is encrypted using corrected RC2-64 encryption
        break;
      case 61:
        // File is encrypted using non-OAEP key wrapping
        break;
      case 62:
        // Central directory encryption
        break;
      case 63:
        // File is compressed using LZMA
        // File is compressed using PPMd+
        // File is encrypted using Blowfish
        // File is encrypted using Twofish
        break;
      default:
        // Unknown extract version
    }

    return extract_version_properties;
  }

  /**
   * Returns the decompressed bytes from a given Zip file archive index.
   * @static
   * @see https://gildas-lormeau.github.io/zip.js/core-api.html
   *
   * @throws An error if the needed Zip decompression library is not available.
   *
   * @param {array}  file_bytes Array with int values 0-255 representing byte values.
   * @param {int}    entry_index The index within the Zip archive of the target file.
   * @return {array} The decompressed bytes of the target file in the Zip archive.
   */
  static async get_zipped_file_bytes(file_bytes, entry_index, password=null) {
    if (window.zip) {
      var options = { useWebWorkers: false };
      var uint8_array = new Uint8Array(file_bytes);

      if (password !== null) options['password'] = password;

      var new_zip = new zip.ZipReader(new zip.Uint8ArrayReader(uint8_array), options);
      var new_zip_entries = await new_zip.getEntries({});
      var unzipped_file_bytes = await new_zip_entries[entry_index].getData(new zip.Uint8ArrayWriter());

      return unzipped_file_bytes;
    } else {
      throw "Zip decompression library not found. Please include zip-full.js from https://github.com/gildas-lormeau/zip.js";
    }
  }

  /**
   * Converts a column index to a letter value.
   *
   * @param {String}  col_index A string representing the column index.
   * @return {String} next_col_index  A String giving the next letter or multiletter column name.
   */
  increment_xls_column(col_index) {
    var col_conversion = ["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"];

    var next_col_index = col_conversion.indexOf(col_index.slice(-1).toUpperCase());
    if (next_col_index == 25) {
      if (col_index.length == 1) {
        next_col_index = "AA";
      } else {
        col_index.slice(0,-2) + col_conversion[col_conversion.indexOf(col_index.slice(-2,-1)) + 1] + "A";
      }
    } else {
      next_col_index = col_index.slice(0,-1) + col_conversion[next_col_index+1];
    }

    return next_col_index;
  }

  /**
   * Returns if the given array is an instance of ArrayBuffer or not.
   *
   * @param {array}    array Any array.
   * @return {boolean} Returns true if the given array is an instance of ArrayBuffer.
   */
  is_typed_array(array) {
    return !!(array.buffer instanceof ArrayBuffer && array.BYTES_PER_ELEMENT);
  }

  /**
   * Parses compound file binary files and streams.
   *
   * @see https://msdn.microsoft.com/en-us/library/dd942421.aspx
   *
   * @param {array}   file_bytes The bytes representing the compound file binary.
   * @return {Object} An object representing the parsed compound file binary.
   */
  parse_compound_file_binary(file_bytes) {
    if (this.array_equals(file_bytes.slice(0,4), [0xD0,0xCF,0x11,0xE0])) {
      var cmb_obj = {
        byte_order: "LITTLE_ENDIAN",
        format_version_major: 0,
        format_version_minor: 0,
        sector_size: 512,
        entries: []
      };

      var current_byte = 0;
      var compound_file_binary_minor_ver_bytes = file_bytes.slice(24,26);
      var compound_file_binary_major_ver_bytes = file_bytes.slice(26,28);

      if (this.array_equals(compound_file_binary_major_ver_bytes, [3,0])) {
        cmb_obj.format_version_major = "3";
      } else if (this.array_equals(compound_file_binary_major_ver_bytes, [4,0])) {
        cmb_obj.format_version_major = "4";
      }

      if (compound_file_binary_minor_ver_bytes[0] == 62) {
        cmb_obj.format_version_minor = "3E";
      }

      // Byte order LITTLE_ENDIAN or BIG_ENDIAN
      var byte_order_bytes = file_bytes.slice(28,30);
      cmb_obj.byte_order = (byte_order_bytes[1] == 255) ? this.LITTLE_ENDIAN : this.BIG_ENDIAN;

      var sector_size_bytes = file_bytes.slice(30,32);
      cmb_obj.sector_size = 512; // Size in bytes

      //Sector size will indicate where the beginning of file record starts.
      if (this.array_equals(sector_size_bytes, [9,0])) {
        cmb_obj.sector_size = 512;
      } else if (this.array_equals(sector_size_bytes, [12,0])) {
        cmb_obj.sector_size = 4096;
      }

      var number_of_directory_sectors = this.get_four_byte_int(file_bytes.slice(40,44), cmb_obj.byte_order);
      var number_of_sectors = this.get_four_byte_int(file_bytes.slice(44,48), cmb_obj.byte_order);
      var sec_id_1 = this.get_four_byte_int(file_bytes.slice(48,52), cmb_obj.byte_order);
      var min_stream_size = this.get_four_byte_int(file_bytes.slice(56,60), cmb_obj.byte_order);
      var short_sec_id_1 = this.get_four_byte_int(file_bytes.slice(60,64), cmb_obj.byte_order);
      var number_of_short_sectors = this.get_four_byte_int(file_bytes.slice(64,68), cmb_obj.byte_order);
      var master_sector_id_1 = this.get_four_byte_int(file_bytes.slice(68,72), cmb_obj.byte_order);
      var number_of_master_sectors = this.get_four_byte_int(file_bytes.slice(72,76), cmb_obj.byte_order);
      var difat_bytes = file_bytes.slice(76,512);
      var difat_index = Array();
      var difat_loc = Array();

      // Index file byte locations of objects
      for (var di=0; di<difat_bytes.length; di+=4) {
        var di_index = this.get_four_byte_int(difat_bytes.slice(di,di+4), cmb_obj.byte_order);
        if (di_index != 4294967295) {
          difat_index.push(di_index);

          var di_location = (di_index + 1) * cmb_obj.sector_size;
          difat_loc.push(di_location);
        }
      }

      // Proccess DIFAT Array?
      for (var di=0; di<difat_loc.length; di++) {
        var next_sector = file_bytes.slice(difat_loc[di], difat_loc[di]+4);

        if (this.array_equals(next_sector, [0xFA,0xFF,0xFF,0xFF])) {
          // MAXREGSECT
        } else if (this.array_equals(next_sector, [0xFB,0xFF,0xFF,0xFF])) {
          // Reserved for future use
        } else if (this.array_equals(next_sector, [0xFC,0xFF,0xFF,0xFF])) {
          // DIFSECT
        } else if (this.array_equals(next_sector, [0xFD,0xFF,0xFF,0xFF])) {
          // FATSECT
        } else if (this.array_equals(next_sector, [0xFE,0xFF,0xFF,0xFF])) {
          // ENDOFCHAIN
        } else if (this.array_equals(next_sector, [0xFF,0xFF,0xFF,0xFF])) {
          // FREESECT
        }
      }

      // Section flags
      var has_summary_information = false;

      // Directory Entry Structure
      var sec_1_pos = 512 + (sec_id_1 * cmb_obj.sector_size); // Should be Root Entry
      var next_directory_entry = sec_1_pos;

      while (!this.array_equals(file_bytes.slice(next_directory_entry,next_directory_entry+4), [0,0,0,0])) {
        var directory_name_bytes = file_bytes.slice(next_directory_entry, next_directory_entry+64);
        var directory_name = Static_File_Analyzer.get_string_from_array(directory_name_bytes.filter(i => i > 5));
        directory_name = (directory_name !== null) ? directory_name.trim() : "";

        var directory_name_buf_size = this.get_four_byte_int(file_bytes.slice(next_directory_entry+64, next_directory_entry+66), cmb_obj.byte_order);

        // 0 - Empty, 1 - User storage, 2 - User Stream, 3 - LockBytes, 4 - Property, 5 - Root storage
        var entry_type = file_bytes[next_directory_entry+66];

        // First four bytes of unique id are flipped?
        var unique_id1 = file_bytes.slice(next_directory_entry+80, next_directory_entry+84).reverse();
        var unique_id2 = file_bytes.slice(next_directory_entry+84, next_directory_entry+96);

        var prop_count = this.get_four_byte_int(file_bytes.slice(next_directory_entry+96, next_directory_entry+100), cmb_obj.byte_order);
        var creation_time_bytes = file_bytes.slice(next_directory_entry+100, next_directory_entry+108);
        var modification_time_bytes = file_bytes.slice(next_directory_entry+108, next_directory_entry+116);

        var creation_time = this.get_eight_byte_date(creation_time_bytes, cmb_obj.byte_order);
        var modification_time = this.get_eight_byte_date(modification_time_bytes, cmb_obj.byte_order);

        var entry_sec_id = this.get_four_byte_int(file_bytes.slice(next_directory_entry+116, next_directory_entry+120), cmb_obj.byte_order);
        var stream_size = this.get_four_byte_int(file_bytes.slice(next_directory_entry+120, next_directory_entry+124), cmb_obj.byte_order);
        var stream_start = 512 + (entry_sec_id * cmb_obj.sector_size);
        var stream_bytes = file_bytes.slice(stream_start, stream_start+stream_size);
        var stream_properties = {};

        var guid = "";
        for (var k=0; k<unique_id1.length; k++) {
          var hex_code = unique_id1[k].toString(16).toUpperCase();
          guid += (hex_code.length == 1) ? "0" + hex_code : hex_code;
        }

        guid += "-";

        for (var k=0; k<unique_id2.length; k++) {
          var hex_code = unique_id2[k].toString(16).toUpperCase();
          guid += (hex_code.length == 1) ? "0" + hex_code : hex_code;
          if (guid.length==8 || guid.length==13 || guid.length==18 || guid.length==23) {
            guid += "-";
          }
        }

        // http://sedna-soft.de/articles/summary-information-stream/
        if (directory_name == "SummaryInformation") {
          has_summary_information = true;
          stream_properties = this.parse_cfb_summary_information(stream_bytes, cmb_obj);
        }

        if (stream_start < file_bytes.length && entry_type != 0 && directory_name != "") {
          cmb_obj.entries.push({
            entry_name:  directory_name,
            entry_type:  entry_type,
            entry_guid:  guid,
            entry_start: stream_start,
            entry_bytes: stream_bytes,
            entry_properties: stream_properties
          });
        }

        next_directory_entry += 128;
        if (next_directory_entry > file_bytes.length) break;
      }

      // Temp fix for too long sections
      if (has_summary_information == false) {
        var summary_information_start = -1;
        var summary_information_end = -1;

        for (var fbi=0; fbi<file_bytes.length; fbi++) {
          if (this.array_equals(file_bytes.slice(fbi,fbi+25), [0x00,0x00,0x05,0x00,0x53,0x00,0x75,0x00,0x6D,0x00,0x6D,0x00,0x61,0x00,0x72,0x00,0x79,0x00,0x49,0x00,0x6E,0x00,0x66,0x00,0x6F])) {
            has_summary_information = true;
            continue;
          } else if (summary_information_start > 0 && this.array_equals(file_bytes.slice(fbi,fbi+4), [0xFE,0xFF,0x00,0x00])) {
            summary_information_end = fbi;
            var summary_stream = file_bytes.slice(summary_information_start, summary_information_end);
            stream_properties = this.parse_cfb_summary_information(summary_stream, cmb_obj);

            cmb_obj.entries.push({
              entry_name:  "SummaryInformation",
              entry_type:  2,
              entry_guid:  "",
              entry_start: summary_information_start,
              entry_bytes: summary_stream ,
              entry_properties: stream_properties
            });

            break;
          } else if (has_summary_information && this.array_equals(file_bytes.slice(fbi,fbi+4), [0xFE,0xFF,0x00,0x00])) {
            summary_information_start = fbi;
            continue;
          }
        }
      }

      // TODO implement Short-Stream
      //short_sec_id_1
      //number_of_short_sectors
      // sector length 64 bytes

    } else {
      throw "File Magic Number is not a CFB file.";
    }

    return cmb_obj;
  }

  /**
   * Parses the summary information stream in a compound file binary file.
   *
   * @see https://sedna-soft.de/articles/summary-information-stream/
   *
   * @param {array}   stream_bytes The bytes representing the compound file binary.
   * @param {Object}  cmb_obj compound file binary file object.
   * @return {Object} An object with all the extracted properties from the summary information stream.
   */
  parse_cfb_summary_information(stream_bytes, cmb_obj) {
    var stream_properties = {};

    if (this.array_equals(stream_bytes.slice(0,4), [0xFE,0xFF,0x00,0x00])) {
      stream_properties['os_version'] = stream_bytes[4] + "." + stream_bytes[5];
      stream_properties['os'] = (stream_bytes[6] == 2) ? "Windows" : (stream_bytes[6] == 1) ? "MacOS" : "Other OS";

      var section_count = this.get_four_byte_int(stream_bytes.slice(18, 22), cmb_obj.byte_order);
      var section_ofset = this.get_four_byte_int(stream_bytes.slice(44, 48), cmb_obj.byte_order);
      var section_length = this.get_four_byte_int(stream_bytes.slice(section_ofset, section_ofset+4), cmb_obj.byte_order);
      var section_prop_count = this.get_four_byte_int(stream_bytes.slice(section_ofset+4, section_ofset+8), cmb_obj.byte_order);

      var section_prop_info = [];
      var current_offset = section_ofset+8;
      for (var pi=0; pi<section_prop_count; pi++) {
        current_offset += 8;
        var prop_offset = this.get_four_byte_int(stream_bytes.slice(current_offset+4, current_offset+8), cmb_obj.byte_order) + 52;

        if (prop_offset < stream_bytes.length) {
          section_prop_info.push({
            'id': this.get_four_byte_int(stream_bytes.slice(current_offset, current_offset+4), cmb_obj.byte_order),
            'offset': prop_offset
          });
        }
      }

      for (var pi=0; pi<section_prop_info.length; pi++) {
        switch (section_prop_info[pi].id) {
          case 1:
            // Code page (02)
            stream_properties['code_page'] = this.get_two_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+2), cmb_obj.byte_order);
            break;
          case 2:
            // Title (1e)
            var string_len = this.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['title'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 3:
            // Subject (1e)
            var string_len = this.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['subject'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 4:
            // Author (1e)
            var string_len = this.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['author'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 5:
            // Keywords (1e)
            var string_len = this.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['keywords'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 6:
            // Comments (1e)
            var string_len = this.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['comments'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 7:
            // Template (1e)
            var string_len = this.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['template'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 8:
            // Last Saved By (1e)
            var string_len = this.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['last_saved_by'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 9:
            // Revision Number (1e)
            var string_len = this.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['revision_number'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 10:
            // Total Editing Time (40)
            var date_bytes = stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+8);
            stream_properties['total_editing_time'] = this.get_eight_byte_date(date_bytes, cmb_obj.byte_order);
            break;
          case 11:
            // Last Printed (40)
            var date_bytes = stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+8);
            stream_properties['last_printed'] = this.get_eight_byte_date(date_bytes, cmb_obj.byte_order);
            break;
          case 12:
            // Create Time/Date (40)
            var date_bytes = stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+8);
            stream_properties['create_date'] = this.get_eight_byte_date(date_bytes, cmb_obj.byte_order);
            break;
          case 13:
            // Last Saved Time/Date (40)
            var date_bytes = stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+8);
            stream_properties['last_saved'] = this.get_eight_byte_date(date_bytes, cmb_obj.byte_order);
            break;
          case 14:
            // Number of Pages (03)
            stream_properties['page_count'] = this.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            break;
          case 15:
            // Number of Words (03)
            stream_properties['word_count'] = this.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            break;
          case 16:
            // Number of Characters (03)
            stream_properties['charater_count'] = this.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            break;
          case 17:
            // Thumbnail (47)
            break;
          case 18:
            // Name of Creating Application (1e)
            var string_len = this.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['creating_application'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 19:
            // Security (03)
            stream_properties['security'] = this.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            break;
          case 2147483648:
            // Locale ID (13)
            break;
        }
      }
    }

    return stream_properties;
  }

  /**
   * Parses an Excel formula record.
   *
   * @see https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/8e3c6978-6c9f-4915-a826-07613204b244
   *
   * @param {object}   cell_record_obj The object containing the raw RK record data.
   * @param {object}   document_obj Object containing data for this document.
   * @param {object}   file_info The output object for finsings and extracted info for the target file.
   * @param {String}   byte_order Optional. this is the byte order to read records in. Default is Little Endian.
   * @return {Object}  An object with the parsed cell data.
   */
  parse_xls_formula_record(cell_record_obj, document_obj, file_info, byte_order=this.LITTLE_ENDIAN) {
    document_obj.current_sheet_name = cell_record_obj.sheet_name;
    document_obj.current_cell = cell_record_obj.cell_name;

    var file_bytes = cell_record_obj.record_bytes;
    var cell_ref = cell_record_obj.cell_name;

    var cell_value = null;
    var cell_ref_full;
    var cell_recalc = false;
    var downloaded_files = [];

    var cell_ixfe = this.get_two_byte_int(file_bytes.slice(4, 6), byte_order);

    // FormulaValue - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/39a0757a-c7bb-4e85-b144-3e7837b059d7
    var formula_byte1 = file_bytes[6];
    var formula_byte2 = file_bytes[7];
    var formula_byte3 = file_bytes[8];
    var formula_byte4 = file_bytes[9];
    var formula_byte5 = file_bytes[10];
    var formula_byte6 = file_bytes[11];
    var formula_expr  = this.get_two_byte_int(file_bytes.slice(12, 14), byte_order);

    if (formula_expr == 65535) {
      /*
      if (formula_byte1 == 0) {
        // String Value
        // Ignore byte3
      } else if (formula_byte1 == 1) {
        // Boolean Value
        cell_value = (formula_byte3 == 0) ? false : true;
      } else if (formula_byte1 == 2) {
        // BErr - Error value - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/91beb411-d175-4c4e-b65f-e3bfbc53064c
        if (formula_byte3 == 0x00) {
          cell_value = "#NULL!";
        } else if (formula_byte3 == 0x07) {
          cell_value = "#DIV/0!";
        } else if (formula_byte3 == 0x0F) {
          cell_value = "#VALUE!";
        } else if (formula_byte3 == 0x17) {
          cell_value = "#REF!";
        } else if (formula_byte3 == 0x1D) {
          cell_value = "#NAME?";
        } else if (formula_byte3 == 0x24) {
          cell_value = "#NUM!";
        } else if (formula_byte3 == 0x2A) {
          cell_value = "#N/A";
        }
      } else if (formula_byte1 == 3) {
        // Blank String
        cell_value = "";
      } else {
        // Error
      }
      */
    } else {
      // Xnum - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/f4aa5725-5bb8-46a9-9fb5-7f0393070a4c
      var buf = new ArrayBuffer(8);
      var view = new DataView(buf);

      view.setUint8(0, formula_byte1);
      view.setUint8(1, formula_byte2);
      view.setUint8(2, formula_byte3);
      view.setUint8(3, formula_byte4);
      view.setUint8(4, formula_byte5);
      view.setUint8(5, formula_byte6);
      view.setUint8(6, file_bytes[12]);
      view.setUint8(7, file_bytes[13]);

      cell_value = view.getFloat64(0, true);
    }

    var formula_bits = this.get_bin_from_int(file_bytes[14]);
    var always_calc = (formula_bits[0] == 1) ? true : false;
    var shared_formula = (formula_bits[3] == 1) ? true : false;

    var reserved3 = file_bytes[15];
    var cache = file_bytes.slice(16, 20);

    // CellParsedFormula - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/7dd67f0a-671d-4905-b87b-4cc07295e442
    var rgce_byte_size = this.get_two_byte_int(file_bytes.slice(20, 22), byte_order);
    var rgce_bytes = file_bytes.slice(22, 22+rgce_byte_size);

    // Rgce - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/6cdf7d38-d08c-4e56-bd2f-6c82b8da752e
    var current_rgce_byte = 0;
    var formula_type = 0;
    var cell_formula = "";
    var cell_value;
    var formula_calc_stack = [];

    while (current_rgce_byte < rgce_bytes.length) {
      // Ptg / formula_type - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/9310c3bb-d73f-4db0-8342-28e1e0fcb68f
      formula_type = rgce_bytes[current_rgce_byte];
      current_rgce_byte += 1;

      if (formula_type == 0x03) {
        // PtgAdd - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/27db2f45-11e8-4238-94ed-92fd9c5721fb
        formula_calc_stack.push({
          'value': "+",
          'type':  "operator"
        });
        var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x04) {
        // PtgSub - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/ee15a1fa-77bb-45e1-8c8c-0e7bef7f7552
        formula_calc_stack.push({
          'value': "-",
          'type':  "operator"
        });
        var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x05) {
        // PtgMul - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/52863fc5-3d3c-4874-90e6-a7961902849f
        formula_calc_stack.push({
          'value': "*",
          'type':  "operator"
        });
        var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x06) {
        // PtgDiv - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/10585b24-618d-47f4-8ffa-65811d18ad13
        formula_calc_stack.push({
          'value': "/",
          'type':  "operator"
        });
        var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x07) {
        // PtgPower - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/e115b216-5dda-4a5b-95d2-cadf0ada9a82
        formula_calc_stack.push({
          'value': "^",
          'type':  "operator"
        });
        var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x08) {
        // PtgConcat - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/054d699a-4383-4bbf-9df2-6a4020119c1e
        formula_calc_stack.push({
          'value': "&",
          'type':  "operator"
        });

        // Stack is implemented as Poish notation, if there is no concat already insert one.
        if (cell_formula.indexOf("&") < 0) {
          if (formula_calc_stack.length > 2) {
            if (formula_calc_stack.at(-2).hasOwnProperty('ref_name')) {
              var ref_name = formula_calc_stack.at(-2).ref_name;
              var insert_index = cell_formula.indexOf(ref_name);
              cell_formula = cell_formula.slice(0,insert_index) + "&" + cell_formula.slice(insert_index);
            }
          }
        }
        cell_formula += "&";
        var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x0B) {
        // PtgEq - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/d197275e-cb7f-455c-b9b5-7e968412d470
        formula_calc_stack.push({
          'value': "==",
          'type':  "operator"
        });
        cell_formula += "==";
        //var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x0E) {
        // PtgNe - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/0e49033d-5dc7-40f1-8fca-eb3b8b1c2c91
        formula_calc_stack.push({
          'value': "!=",
          'type':  "operator"
        });
        cell_formula += "!=";
        //var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x16) {
        // PtgMissArg - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/69352e6c-e712-48d7-92d1-0bf7c1f61f69
        formula_calc_stack.push({
          'value': "",
          'type':  "string"
        });
        cell_formula += "\"\"";
      } else if (formula_type == 0x17) {
        // String
        var string_size = rgce_bytes[current_rgce_byte];
        var byte_option_bits = this.get_bin_from_int(rgce_bytes[current_rgce_byte+1]);
        var double_byte_chars = (byte_option_bits[0] == 1) ? true : false;
        var string_end;

        if (double_byte_chars) {
          // Characters are two bytes each.
          string_end = current_rgce_byte + 2 + (string_size * 2);
        } else {
          // Characters are one byte each.
          string_end = current_rgce_byte + 2 + string_size;
        }

        var string_val = Static_File_Analyzer.get_string_from_array(rgce_bytes.slice(current_rgce_byte+2, string_end));;

        if (document_obj.varables.hasOwnProperty(string_val)) {
          // Reference to a document variable
          formula_calc_stack.push({
            'value': document_obj.varables[string_val],
            'type':  "reference"
          });
        } else {
          formula_calc_stack.push({
            'value': string_val,
            'type':  "string"
          });
        }

        current_rgce_byte = string_end;
      } else if (formula_type == 0x18) {
        if (rgce_bytes[current_rgce_byte] == 0x01) {
          // PtgElfLel - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/67784d96-e87d-4f97-b643-f8f2176a6148
        } else if (rgce_bytes[current_rgce_byte] == 0x02) {
          // PtgElfRw - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/20348be6-68c6-4506-b744-fd38ec0aa675
        } else if (rgce_bytes[current_rgce_byte] == 0x03) {
          // PtgElfCol - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/c76517f7-6a4e-47e8-8087-6e927758bbed
        } else if (rgce_bytes[current_rgce_byte] == 0x06) {
          // PtgElfRwV - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/42e28815-da53-45ba-80f2-2a68ddbbfcf9
        } else if (rgce_bytes[current_rgce_byte] == 0x07) {
          // PtgElfColV - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/167409e7-9363-4b61-9434-47e559e80f2d
        } else if (rgce_bytes[current_rgce_byte] == 0x0A) {
          // PtgElfRadical - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/dc352cde-62fc-4c68-99fd-186d6bc4d610
        } else if (rgce_bytes[current_rgce_byte] == 0x0B) {
          // PtgElfRadicalS - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/e3112a89-f771-4043-82a9-18b3d4c1e137
        } else if (rgce_bytes[current_rgce_byte] == 0x0D) {
          // PtgElfColS - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/cc02acdf-f404-4318-9847-8d4cbf523966
        } else if (rgce_bytes[current_rgce_byte] == 0x0F) {
          // PtgElfColSV - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/6ed51fe3-4baf-4163-8851-888de8477525
        } else if (rgce_bytes[current_rgce_byte] == 0x10) {
          // PtgElfRadicalLel - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/304191e6-2c82-4542-8477-a1ffd548442e
        } else if (rgce_bytes[current_rgce_byte] == 0x1D) {
          // PtgSxName - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/aa0ebf5c-29d2-4ec5-8639-46f844e7647d
        }

        // All the above records are the same size.
        current_rgce_byte += 5;
      } else if (formula_type == 0x19) {
        if (rgce_bytes[current_rgce_byte] == 0x01) {
          // PtgAttrSemi - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/615c5518-010a-4268-b71b-b60074bdb11b
          // next two bytes unused, should be zero
          current_rgce_byte += 3;
        } else if (rgce_bytes[current_rgce_byte] == 0x02) {
          // PtgAttrIf - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/d81e5fb4-3004-409a-9a31-1a60662d9e59
          var offset = this.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+1,current_rgce_byte+3), byte_order);
          current_rgce_byte += 3;
        } else if (rgce_bytes[current_rgce_byte] == 0x04) {
          // PtgAttrChoose - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/24fb579c-c65d-4771-94a8-4380cecdc8c8
          var c_offset = this.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+1,current_rgce_byte+3), byte_order) + 1;
          var rgOffset_bytes = rgce_bytes.slice(current_rgce_byte+3,current_rgce_byte+3+c_offset);
          current_rgce_byte += 3 + c_offset;
        } else if (rgce_bytes[current_rgce_byte] == 0x08) {
          // PtgAttrGoto - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/081e17b9-02a6-4e78-ad28-09538f35a312
          var offset = this.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+1,current_rgce_byte+3), byte_order);
          current_rgce_byte += 3;
        } else if (rgce_bytes[current_rgce_byte] == 0x10) {
          // PtgAttrSum - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/79ef57f6-27ab-4fec-b893-7dd727e771d1
          // next two bytes unused, should be zero
          current_rgce_byte += 3;
        } else if (rgce_bytes[current_rgce_byte] == 0x20 || rgce_bytes[current_rgce_byte] == 0x21) {
          // PtgAttrBaxcel - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/fcd76e10-6072-4dcf-b591-47edc8822792
          // This is my implementaiton, not based on MS / Excel.
          formula_calc_stack.push({
            'value': "=",
            'type':  "operator"
          });
          // next two bytes unused, should be zero
          current_rgce_byte += 3;
        } else if (rgce_bytes[current_rgce_byte] == 0x40) {
          // PtgAttrSpace - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/38a4d7be-040b-4206-b078-62f5aeec72f3
          var ptg_attr_space_type = this.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+1,current_rgce_byte+3), byte_order);
          current_rgce_byte += 3;
        } else if (rgce_bytes[current_rgce_byte] == 0x41) {
          // PtgAttrSpaceSemi - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/5d8c3df5-9be5-46d9-8105-a1a19ceca3d4
          var type = this.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+1,current_rgce_byte+3), byte_order);
          current_rgce_byte += 3;
        } else {
          // error
          current_rgce_byte += 1;
        }
      } else if (formula_type == 0x1E) {
        // PtgInt - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/508ecf18-3b81-4628-95b3-7a9d2a295bca
        var ptg_int_val = this.get_two_byte_int(rgce_bytes.slice(current_rgce_byte,current_rgce_byte+2), byte_order);
        formula_calc_stack.push({
          'value': ptg_int_val,
          'type':  "number"
        });
        current_rgce_byte += 2;
      } else if (formula_type == 0x1F) {
        // PtgNum - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/40e69183-2cd3-4051-87ba-2f3ccb82bcfa
        var float_bytes = rgce_bytes.slice(current_rgce_byte,current_rgce_byte+8);
        var buf = new ArrayBuffer(8);
        var view = new DataView(buf);

        view.setUint8(0, float_bytes[0]);
        view.setUint8(1, float_bytes[1]);
        view.setUint8(2, float_bytes[2]);
        view.setUint8(3, float_bytes[3]);
        view.setUint8(4, float_bytes[4]);
        view.setUint8(5, float_bytes[5]);
        view.setUint8(6, float_bytes[6]);
        view.setUint8(7, float_bytes[7]);

        var float_val = view.getFloat64(0, true);

        formula_calc_stack.push({
          'value': float_val,
          'type':  "number"
        });

        current_rgce_byte += 8;
      } else if (formula_type == 0x23) {
        // PtgName - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/5f05c166-dfe3-4bbf-85aa-31c09c0258c0
        // reference to a defined name
        var var_index = this.get_four_byte_int(rgce_bytes.slice(current_rgce_byte,current_rgce_byte+4), byte_order);

        if (var_index-1 < document_obj.defined_names.length) {
          var var_name = document_obj.defined_names[var_index-1];

          if (document_obj.varables.hasOwnProperty(var_name.name)) {
            var var_value = document_obj.varables[var_name.name];
            var var_type = typeof document_obj.varables[var_name.name];

            var cell_ref_match = /\@([a-zA-Z0-9]+)\!(\w+[0-9]+)/gm.exec(var_value);
            if (cell_ref_match !== null) {
              // Cell Reference
              if (document_obj.sheets[cell_ref_match[1]].data.hasOwnProperty(cell_ref_match[2])) {
                var ref_cell = document_obj.sheets[cell_ref_match[1]].data[cell_ref_match[2]];
                var_value = ref_cell.value;
                var_type = typeof ref_cell.value;
              } else {
                // Add to recalc
                document_obj.recalc_objs.push(cell_record_obj.sheet_name + "!" + cell_record_obj.cell_name);
                var_type = "reference";
                cell_recalc = true;
              }
            }

            formula_calc_stack.push({
              'value': var_value,
              'type':  var_type,
              'ref_name': var_name.name
            });
          } else {
            formula_calc_stack.push({
              'value': var_name.name,
              'type':  "string"
            });
          }

          current_rgce_byte += 4;
        } else {
          current_rgce_byte += 1;
        }
      } else if (formula_type == 0x24 || formula_type == 0x44) {
        // PtgRef - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/fc7c380b-d793-4219-a897-e47e13c4e055
        // The PtgRef operand specifies a reference to a single cell in this sheet.
        var loc_row = this.get_two_byte_int(rgce_bytes.slice(current_rgce_byte,current_rgce_byte+2), byte_order);
        var col_rel = this.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+2,current_rgce_byte+4), byte_order);
        var col_rel_bits = this.get_bin_from_int(col_rel);
        var loc_col = this.get_int_from_bin(col_rel_bits.slice(0,13));
        var is_col_relative = (col_rel_bits[14] == 1) ? true : false;
        var is_row_relative = (col_rel_bits[15] == 1) ? true : false;

        var cell_ref = this.convert_xls_column(loc_col) + (loc_row+1);
        var spreadsheet_obj = document_obj.sheets[cell_record_obj.sheet_name];
        var full_cell_name = cell_record_obj.sheet_name + "!" + cell_ref;

        // Check to what the next rgce_byte is, as that will affect what action is taken.
        if (rgce_bytes[current_rgce_byte+6] == 0x60) {
          // Put reference
          // Calculate the stack.
          var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
          stack_result = stack_result.replaceAll(/\\?[\"\']&\\?[\"\']/gm, "");

          if (stack_result.charAt(0) == "=") {
            // This is an Excel formula or macro
            var c_formula_name = stack_result.split("(")[0].toUpperCase();

            if (c_formula_name == "=CALL" || c_formula_name == "=EXEC" || c_formula_name == "=IF") {
              file_info.scripts.script_type = "Excel 4.0 Macro";

              if (file_info.scripts.extracted_script.indexOf(stack_result) < 0) {
                file_info.scripts.extracted_script += stack_result + "\n\n";
              }

              // Keep a list of downloaded file names.
              var file_dl_match = /\=?CALL\s*\(\s*[\"\']urlmon[\"\']\s*,[^\,]+\,[^\,]+\,[^\,]+\,([^\,]+)(?:\,([^\,]+))?(?:\,([^\,]+))?/gmi.exec(stack_result);
              if (file_dl_match !== null) {
                if (file_dl_match[1].charAt(0) == "\"") {
                  downloaded_files.push(file_dl_match[1].slice(1,-1));
                }

                if (file_dl_match[2].charAt(0) == "\"") {
                  downloaded_files.push(file_dl_match[2].slice(1,-1));
                }

                if (file_dl_match[2].charAt(0) == "\"") {
                  downloaded_files.push(file_dl_match[3].slice(1,-1));
                }
              }

              // Check EXEC for usage of downloaded files.
              if (c_formula_name == "=EXEC") {
                for (var dl=0; dl<downloaded_files.length; dl++) {
                  if (stack_result.indexOf(downloaded_files[dl]) > 0) {
                    var new_finding = "SUSPICIOUS - Macro Execution of a Downloaded File";
                    if (!file_info.analytic_findings.includes(new_finding)) {
                      file_info.analytic_findings.push(new_finding);
                    }
                    break;
                  }
                }
              }

              // Check for IoCs
              file_info = this.search_for_iocs(stack_result, file_info);
            }
          }

          cell_value = (cell_value === null) ? stack_result : cell_value + stack_result;

          spreadsheet_obj.data[cell_ref] = {
            'value': cell_value,
            'formula': cell_formula
          }

          formula_calc_stack.shift();
          current_rgce_byte += 8;
        } else {
          // Get reference
          if (spreadsheet_obj.data.hasOwnProperty(cell_ref)) {
            if (spreadsheet_obj.data[cell_ref].value !== null || spreadsheet_obj.data[cell_ref].value !== undefined) {
              // Cell has a value we can use this.
              formula_calc_stack.push({
                'value': spreadsheet_obj.data[cell_ref].value,
                'type':  "string"
              });

              cell_formula += spreadsheet_obj.name + "!" + cell_ref;
            } else {
              // No cell value, calculate formula
              // TODO: not yet implemented
            }

            break;
          } else {
            // Cell reference was not found or hasn't been loaded yet.
            // This may mean that cells are stored in the file in a different order than need to be calculated.
            // Store the cell names that cant be calculated and go back to recalc after all cells are loaded.
            cell_ref_full = spreadsheet_obj.name + "!" + cell_ref;
            var recalc_cell = cell_record_obj.sheet_name + "!" + cell_record_obj.cell_name;
            cell_recalc = true;

            formula_calc_stack.push({
              'value': "@"+cell_ref_full,
              'type':  "reference",
              'ref_name': cell_ref_full
            });
            cell_formula += cell_ref_full;

            if (!document_obj.recalc_objs.includes(recalc_cell)) document_obj.recalc_objs.push(recalc_cell);
          }

          current_rgce_byte += 4;
        }
      } else if (formula_type == 0x41 || formula_type == 0x21) {
        // PtgFunc - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/87ce512d-273a-4da0-a9f8-26cf1d93508d
        var ptg_bits = this.get_bin_from_int(rgce_bytes[current_rgce_byte-1]);
        var iftab = this.get_two_byte_int(rgce_bytes.slice(current_rgce_byte,current_rgce_byte+2), byte_order);

        // Execute a function - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/00b5dd7d-51ca-4938-b7b7-483fe0e5933b
        if (iftab == 0x0000) {
          // COUNT
        } else if (iftab == 0x0001) {
          // IF
        } else if (iftab == 0x0030) {
          // Text
          // TODO - this is a hack and not really implemented.
          cell_formula = "=TEXT(" + cell_formula + ")";
          formula_calc_stack.splice(-1, 2, {
            'value': formula_calc_stack.splice(-2, 1)[0].value,
            'type':  "string"
          });
        } else if (iftab == 0x004F) {
          // ABSREF - Returns the absolute reference of the cells that are offset from a reference by a specified amount
        } else if (iftab == 0x005A) {
          // DEREF - Reference another cell
          cell_formula += "=";
        } else if (iftab == 0x006F) {
          // CHAR
          formula_calc_stack.push({
            'value':  "_xlfn.CHAR",
            'type':   "string",
            'params': param_count
          });

          cell_formula += "=CHAR(" + formula_calc_stack.at(-2).value + ")";
          cell_value = (cell_value === null) ? "" : cell_value;
          cell_value += this.execute_excel_stack(formula_calc_stack, document_obj).value;
        } else if (iftab == 0x0082) {
          // t-params
          if (formula_calc_stack.length > 1) {
            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
            cell_formula = "=T(" + cell_formula + ")";
            cell_value = (cell_value === null) ? stack_result : cell_value+stack_result;
          }
        } else if (iftab == 0x0096) {
          // Call Function
          console.log("Call function not implemented.");
        } else if (iftab == 0x00E1) {
          // End IF
        } else {
          // Non implemented function
          console.log("Unknown function " + iftab); // DEBUG
          console.log("^ Last function: " + last_formula_type); // DEBUG
        }

        current_rgce_byte += 2;
      } else if (formula_type == 0x42) {
        // PtgFuncVar - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/5d105171-6b73-4f40-a7cd-6bf2aae15e83
        var param_count = rgce_bytes[current_rgce_byte];
        var tab_bits = this.get_binary_array(rgce_bytes.slice(current_rgce_byte+1,current_rgce_byte+3));
        var tab_int = rgce_bytes[current_rgce_byte+1];
        current_rgce_byte += 3;

        if (tab_bits[15] == 0) {
          // Ftab value - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/00b5dd7d-51ca-4938-b7b7-483fe0e5933b
          if (tab_int == 0x00) {
            // COUNT
            formula_calc_stack.push({
              'value':  "_xlfn.COUNT",
              'type':   "string",
              'params': param_count
            });
          } else if (tab_int == 0x01) {
            // IF
            formula_calc_stack.push({
              'value':  "_xlfn.IF",
              'type':   "string",
              'params': param_count
            });
          } else if (tab_int == 0x1A) {
            // SIGN - https://support.microsoft.com/en-us/office/sign-function-109c932d-fcdc-4023-91f1-2dd0e916a1d8
            formula_calc_stack.push({
              'value':  "_xlfn.SIGN",
              'type':   "string",
              'params': param_count
            });
          } else if (tab_int == 0x36) {
            // HALT
            formula_calc_stack.push({
              'value':  "_xlfn.HALT",
              'type':   "string",
              'params': param_count
            });
          } else if (tab_int == 0x37) {
            // RETURN
            formula_calc_stack.push({
              'value':  "_xlfn.RETURN",
              'type':   "string",
              'params': param_count
            });
          } else if (tab_int == 0x58) {
            // SET.NAME
            formula_calc_stack.push({
              'value':  "_xlfn.SET.NAME",
              'type':   "string",
              'params': param_count
            });

            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
            cell_formula += stack_result.formula;
            cell_value = stack_result.value;
          } else if (tab_int == 0x6C) {
            // STDEVPA - Calculates standard deviation
          } else if (tab_int == 0x6E) {
            // EXEC
            formula_calc_stack.push({
              'value':  "_xlfn.EXEC",
              'type':   "string",
              'params': param_count
            });

            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
            file_info.scripts.script_type = "Excel 4.0 Macro";
            file_info = this.analyze_excel_macro(file_info, document_obj.sheets, stack_result.value);
          } else if (tab_int == 0x6F) {
            // CHAR
            formula_calc_stack.push({
              'value':  "_xlfn.CHAR",
              'type':   "string",
              'params': param_count
            });

            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
          } else if (tab_int == 0x80) {
            // ISNUMBER
            formula_calc_stack.push({
              'value':  "_xlfn.ISNUMBER",
              'type':   "string",
              'params': param_count
            });
          } else if (tab_int == 0x95) {
            // REGISTER
            formula_calc_stack.push({
              'value':  "_xlfn.REGISTER",
              'type':   "string",
              'params': param_count
            });

            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
            cell_formula = stack_result.formula;
          } else if (tab_int == 0xA9) {
            // COUNTA - counts the number of cells that are not empty in a range.
            // https://support.microsoft.com/en-us/office/counta-function-7dc98875-d5c1-46f1-9a82-53f3219e2509
            formula_calc_stack.push({
              'value':  "_xlfn.COUNTA",
              'type':   "string",
              'params': param_count
            });
          } else if (tab_int == 0xFF) {
            // User Defined Function
            formula_calc_stack.push({
              'value': "_xlfn.USERFUNCTION",
              'type':  "string",
            'params': param_count
            });

            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
            cell_formula = stack_result.value;
          } else {
            console.log("Unknown PtgFuncVar: " + tab_int); // DEBUG
          }
        } else {
          // Cetab value - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/0b8acba5-86d2-4854-836e-0afaee743d44
        }

        // Execute formula_calc_stack
        for (var c=0; c<formula_calc_stack.length; c++) {
          if (param_count == 1 && formula_calc_stack.length > 1) {
            function_name = "";
            var stack_result = {};
            // Execute the stack, if it's length is greater than 1.
            if (formula_calc_stack.length > 1) {
              stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
              cell_value = stack_result.value;
            }

            if (stack_result.hasOwnProperty("formula") && stack_result.formula != "") {
              cell_formula += stack_result.formula;
            } else {
              cell_formula += function_name + "(" + cell_formula + ")";
            }

            break;
          } else if (param_count >= 2) {
            if (formula_calc_stack[c].value !== null && formula_calc_stack[c].value.length > 0) {
              if (formula_calc_stack[c].value == "=") {
                // c + 1 is the varable name, c + 2 is the value.
                if (formula_calc_stack.length > 2) {
                  document_obj.varables[formula_calc_stack[c+1].value] = formula_calc_stack[c+2].value;

                  //Set a human readable value for this cell
                  cell_formula += formula_calc_stack[c+1].value + "=" + "\"" + formula_calc_stack[c+2].value  + "\"";
                  formula_calc_stack = formula_calc_stack.slice(3);
                } else if (formula_calc_stack.length == 2) {
                  if (c == 0) {
                    document_obj.varables[formula_calc_stack[c+1].value] = "";
                    cell_formula += formula_calc_stack[c+1].value + "=" + "\"\"";
                    formula_calc_stack = formula_calc_stack.slice(2);
                  }
                }

              } else if (formula_calc_stack[c].value.length > 6 && formula_calc_stack[c].value.substring(0, 6).toLowerCase() == "_xlfn.") {
                // Execute an Excel function.
                var function_name = formula_calc_stack[c].value.substring(6);

                if (c+1 < formula_calc_stack.length) {
                  cell_formula += function_name + "(" + formula_calc_stack[c+1].value + ")";
                } else {
                  cell_formula += function_name + "(" + formula_calc_stack[c].value + ")";
                }

                var cal_result = this.execute_excel_stack(formula_calc_stack, document_obj);
              }
            }
          }
        }

        if (formula_calc_stack.length > 1) {
          // Check to see if formula_calc_stack consists of only strings
          var is_all_strings = true;
          var string_concat = "";
          for (var c=0; c<formula_calc_stack.length; c++) {
            if (formula_calc_stack[c].type != "string") {
              is_all_strings = false;
              break;
            } else {
              string_concat += formula_calc_stack[c].value;
            }
          }

          if (is_all_strings) {
            // Concat
            formula_calc_stack = [{
              'type':  "string",
              'value': string_concat
            }];
            cell_value = string_concat;
          }
        }

      } else if (formula_type == 0x43) {
        // PtgName - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/5f05c166-dfe3-4bbf-85aa-31c09c0258c0
        var ptg_bits = this.get_bin_from_int(rgce_bytes[current_rgce_byte-1]);

        // PtgDataType - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/80d504ba-eb5d-4a0f-a5da-3dcc792dd78e
        var data_type_int = this.get_int_from_bin(ptg_bits.slice(5,7));
        var name_index = this.get_four_byte_int(rgce_bytes.slice(current_rgce_byte,current_rgce_byte+4), byte_order);

        if (name_index <= document_obj.defined_names.length) {
          var ref_var_name = document_obj.defined_names[name_index-1];

          if (document_obj.varables.hasOwnProperty(ref_var_name.name)) {
            formula_calc_stack.push({
              'value': document_obj.varables[ref_var_name.name],
              'type':  "string",
              'ref_name': ref_var_name.name
            });

          } else {
            // Probably definning the variable
            formula_calc_stack.push({
              'value': ref_var_name.name,
              'type':  "reference"
            });
          }
        } else {
          // error looking up varable.
        }

        current_rgce_byte += 4;
      } else if (formula_type == 0x5A) {
        // PtgRef3d - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/1ca817be-8df3-4b80-8d35-46b5eb753577
        // The PtgRef3d operand specifies a reference to a single cell on one or more sheets.
        var ixti = this.get_two_byte_int(rgce_bytes.slice(current_rgce_byte,current_rgce_byte+2), byte_order);
        var loc_row = this.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+2,current_rgce_byte+4), byte_order);
        var col_rel = this.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+4,current_rgce_byte+6), byte_order);
        var col_rel_bits = this.get_bin_from_int(col_rel);
        var loc_col = this.get_int_from_bin(col_rel_bits.slice(0,13));
        var is_col_relative = (col_rel_bits[14] == 1) ? true : false;
        var is_row_relative = (col_rel_bits[15] == 1) ? true : false;

        var cell_ref = this.convert_xls_column(loc_col) + (loc_row+1);
        var full_cell_name;
        var ref_found = false;
        var ixti_org = ixti;
        var ref_sheet_name = "";
        var spreadsheet_obj;

        var possible_sheet_names = [];
        for (var si=0; si<document_obj.sheet_index_list.length; si++) {
          var p_sheet_name = document_obj.sheet_index_list[si];
          if (document_obj.sheets[p_sheet_name].data.hasOwnProperty(cell_ref)) {
            possible_sheet_names.push(p_sheet_name);
          }
        }

        if (possible_sheet_names.length == 1) {
          if (document_obj.sheet_indexes[ixti] === null || document_obj.sheet_indexes[ixti] === undefined) {
            document_obj.sheet_indexes[ixti] = possible_sheet_names[0];
            ref_sheet_name = document_obj.sheet_indexes[ixti];
            spreadsheet_obj = document_obj.sheets[ref_sheet_name];
            full_cell_name = ref_sheet_name + "!" + cell_ref;
            ref_found = true;
          } else {
            if (document_obj.sheet_indexes[ixti] != possible_sheet_names[0]) {
              // missmatach
              if (document_obj.sheet_indexes.indexOf(possible_sheet_names[0]) >= 0) {
                // Only match is already indexed, so that means the desired cell isn't loaded yet.
                ref_sheet_name = document_obj.sheet_indexes[ixti];
                spreadsheet_obj = document_obj.sheets[ref_sheet_name];
                full_cell_name = ref_sheet_name + "!" + cell_ref;
                ref_found = false;
              } else {
                // Possible bad data loaded, reset index.
                document_obj.sheet_indexes[ixti] == null;
              }

              cell_recalc = true;
            } else {
              ref_sheet_name = document_obj.sheet_indexes[ixti];
              spreadsheet_obj = document_obj.sheets[ref_sheet_name];
              full_cell_name = ref_sheet_name + "!" + cell_ref;
              ref_found = true;
            }
          }
        } else {
          if (document_obj.sheet_indexes[ixti] !== null && document_obj.sheet_indexes[ixti] !== undefined) {
            ref_sheet_name = document_obj.sheet_indexes[ixti];
            spreadsheet_obj = document_obj.sheets[ref_sheet_name];
            full_cell_name = ref_sheet_name + "!" + cell_ref;

            if (spreadsheet_obj.data.hasOwnProperty(cell_ref)) {
              ref_found = true;
            } else {
              ref_found = false;
            }
          } else {
            cell_recalc = true;
          }
        }

        if (cell_ref == "F10") {
          var debug90=0;
        } else if (cell_record_obj.cell_name == "E4") {
          var debug90=0;
        }

        if (spreadsheet_obj === null || spreadsheet_obj === undefined) {
          var debug90=0;
        }

        if (ref_found == true) {
          if (spreadsheet_obj.data[cell_ref].value !== null || spreadsheet_obj.data[cell_ref].value !== undefined) {
            // Cell has a value we can use this.
            formula_calc_stack.push({
              'value': spreadsheet_obj.data[cell_ref].value,
              'type':  "string",
              'ref_name': full_cell_name
            });

            cell_formula += spreadsheet_obj.name + "!" + cell_ref;
          } else {
            // No cell value, calculate formula
            // TODO: not yet implemented
          }
        }

        if (ref_found == false) {
          // Cell reference was not found or hasn't been loaded yet.
          // This may mean that cells are stored in the file in a different order than need to be calculated.
          // Store the cell names that cant be calculated and go back to recalc after all cells are loaded.
          cell_ref_full = ref_sheet_name + "!" + cell_ref;
          var recalc_cell = cell_record_obj.sheet_name + "!" + cell_record_obj.cell_name;
          cell_recalc = true;

          formula_calc_stack.push({
            'value': "@"+cell_ref_full,
            'type':  "reference",
            'ref_name': cell_ref_full
          });
          cell_formula += cell_ref_full;

          if (!document_obj.recalc_objs.includes(recalc_cell)) document_obj.recalc_objs.push(recalc_cell);
        }

        current_rgce_byte += 6;
      } else if (formula_type == 0x60) {
        // PtgArray - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/61167ac8-b0ca-42e5-b82c-41a25d12324c
        var data_type = this.get_bin_from_int(formula_type).slice(5,7);

        formula_calc_stack.push({
          'value': "[]",
          'type':  "operator"
        });

        current_rgce_byte += 1;
      } else {
        // Non implemented formula_type
        console.log("Unknown formula_type " + formula_type); // DEBUG
      }
    }

    if (formula_calc_stack.length > 0 && cell_value === null) {
      cell_value = formula_calc_stack[0].value;
    }

    return {
      'sheet_name': cell_record_obj.sheet_name,
      'cell_name': cell_record_obj.cell_name,
      'cell_recalc': cell_recalc,
      'cell_data': {
        'formula': cell_formula,
        'value': cell_value
      }
    };
  }

  /**
   * Parses an Excel Label Set record
   *
   * @see https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/3f52609d-816f-44a7-aad1-e0fe2abccebd
   *
   * @param {object}   cell_record_obj The object containing the raw lebel set record data.
   * @param {array}    string_constants The array of defined string constants.
   * @param {String}   byte_order Optional. this is the byte order to read records in. Default is Little Endian.
   * @return {Object}  An object with the parsed cell data.
   */
  parse_xls_label_set_record(cell_record_obj, string_constants, byte_order=this.LITTLE_ENDIAN) {
    var bytes = cell_record_obj.record_bytes;

    var cell_row  = this.get_two_byte_int(bytes.slice(0, 2), byte_order) + 1;
    var cell_col  = this.get_two_byte_int(bytes.slice(2, 4), byte_order);
    var cell_ref  = this.convert_xls_column(cell_col) + cell_row;

    var cell_ixfe = this.get_two_byte_int(bytes.slice(4, 6), byte_order);

    var isst = this.get_four_byte_int(bytes.slice(6, 10), byte_order);
    var cell_value = string_constants[isst];

    return {
      'sheet_name': cell_record_obj.sheet_name,
      'cell_name' : cell_ref,
      'cell_data': {
        'formula': null,
        'value': cell_value
      }
    };
  }

  /**
   * Parses an Excel RK record.
   *
   * @see https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/656e0e79-8b9d-4854-803f-23ec62080678
   * @see https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/04fa5340-122f-49db-93ea-00cc75501efc
   *
   * @param {object}   cell_record_obj The object containing the raw RK record data.
   * @param {String}   byte_order Optional. this is the byte order to read records in. Default is Little Endian.
   * @return {Object}  An object with the parsed cell data.
   */
  parse_xls_rk_record(cell_record_obj, byte_order=this.LITTLE_ENDIAN) {
    var bytes = cell_record_obj.record_bytes;

    var cell_row  = this.get_two_byte_int(bytes.slice(0, 2), byte_order) + 1;
    var cell_col  = this.get_two_byte_int(bytes.slice(2, 4), byte_order);
    var cell_ref  = this.convert_xls_column(cell_col) + cell_row;

    var cell_ixfe = this.get_two_byte_int(bytes.slice(4, 6), byte_order);
    var rk_number_bits = this.get_binary_array(bytes.slice(6, 10), byte_order);
    var cell_value = 0;
    var rk_bits = this.get_bin_from_int(bytes[6]);

    if (rk_bits[1] == 0) {
      // rk_number is the 30 most significant bits of a 64-bit binary floating-point number as defined in [IEEE754]. The remaining 34-bits of the floating-point number MUST be 0.
      var rk_bytes = bytes.slice(7, 10).reverse();

      rk_bits[0] = 0;
      rk_bits[1] = 0;
      rk_bytes.push(this.get_int_from_bin(rk_bits.reverse()));

      var buf = new ArrayBuffer(8);
      var view = new DataView(buf);

      view.setUint8(0, rk_bytes[0]);
      view.setUint8(1, rk_bytes[1]);
      view.setUint8(2, rk_bytes[2]);
      view.setUint8(3, rk_bytes[3]);
      view.setUint8(4, 0);
      view.setUint8(5, 0);
      view.setUint8(6, 0);
      view.setUint8(7, 0);

      cell_value = view.getFloat64(0, false);
    } else {
      // rk_number is a signed integer.
      var rk_number = this.get_int_from_bin(rk_number_bits.slice(3), byte_order);
      cell_value = (rk_number_bits[2] == 1) ? rk_number * -1 : rk_number;
    }

    if (rk_bits[0] == 1) {
      // The value of RkNumber is the value of rk_number divided by 100.
      cell_value = cell_value / 100;
    }

    return {
      'sheet_name': cell_record_obj.sheet_name,
      'cell_name' : cell_ref,
      'cell_data': {
        'formula': null,
        'value': cell_value
      }
    };
  }

  /**
   * Returns pretty print formated VBA code.
   *
   * @param  {String} vba_code The VBA code to format.
   * @return {String} The pretty print formated VBA code.
   */
  pretty_print_vba(vba_code) {
    var indent = "";
    var indent_amt = 0;
    var output_code = "";
    var code_lines = vba_code.split("\n");
    var line_tokens;
    var current_line_token;

    var indent_triggers = ["If","Else","ElseIf","For","Open","Sub","While","With"];
    var indent_end = ["Close","Else","ElseIf","End","Next","Wend"];

    for (var i=0; i<code_lines.length; i++) {
      line_tokens = code_lines[i].split(" ");

      if (line_tokens[0] == "Public" || line_tokens[0] == "Private") {
        current_line_token = line_tokens[1].trim();
      } else {
        current_line_token = line_tokens[0].trim();
      }

      if (indent_triggers.includes(current_line_token.trim())) {
        if (code_lines[i].slice(-1) == "_") {
          output_code += indent + code_lines[i].slice(0,-1) + code_lines[i+1] + "\n";
          i++;
        } else {
          output_code += indent + code_lines[i] + "\n";
        }

        indent_amt++;
        indent = (indent_amt > 0) ? Array(indent_amt+1).join("\t") : "";
      } else if (indent_end.includes(current_line_token.trim())) {
        indent_amt--;
        indent = (indent_amt > 0) ? Array(indent_amt+1).join("\t") : "";
        output_code += indent + code_lines[i] + "\n";

        if (code_lines[i].trim() == "End Sub") output_code += "\n";
      } else {
        output_code += indent + code_lines[i] + "\n";
      }
    }

    return output_code;
  }

  /**
   * Returns an array of DBCell records
   *
   * @param  {object} file_bytes - The bytes representing the spreadsheet file.
   * @param  {object} document_obj - The object repreasenting the spreadsheet document.
   * @param  {String} byte_order - Optional, default is LITTLE_ENDIAN.
   * @return {array} An array containing all the records raw bytes.
   */
  read_dbcell_records(file_bytes, document_obj, byte_order=this.LITTLE_ENDIAN) {
    // Find workbook entry
    var cell_records = [];
    var sheet_name = "";

    for (var i=512; i<file_bytes.length; i++) {
      if (file_bytes[i] == 0xD7 && file_bytes[i+1] == 0x00 && file_bytes[i+3] == 0x00) {
        var record_size1 = this.get_two_byte_int(file_bytes.slice(i+2,i+4), byte_order);
        var first_row_record = this.get_four_byte_int(file_bytes.slice(i+4, i+8), byte_order);
        var cell_record_pos = i - first_row_record; // DEBUG - double check this
        //i += (record_size>0) ? record_size1 -1 : 1;

        if (record_size1 > 4) {
          while (cell_record_pos > 0 && cell_record_pos < i) {
            // Derive the current Sheetname
            var spreadsheet_sheet_indexes = Object.entries(document_obj.sheets);
            sheet_name = spreadsheet_sheet_indexes.at(-1)[1].name;
            for (var si=0; si<spreadsheet_sheet_indexes.length-1; si++) {
              if (cell_record_pos > spreadsheet_sheet_indexes[si][1].file_pos && cell_record_pos < spreadsheet_sheet_indexes[si+1][1].file_pos) {
                sheet_name = spreadsheet_sheet_indexes[si][1].name;
                break;
              }
            }

            var cell_row = 0;
            var cell_col = -1;
            var cell_name = "";
            var record_type_str = "unknown";
            var record_type_bytes = file_bytes.slice(cell_record_pos, cell_record_pos+2);
            cell_record_pos += 2;

            var record_size = this.get_two_byte_int(file_bytes.slice(cell_record_pos, cell_record_pos+2), byte_order);
            cell_record_pos += 2;

            var record_bytes = file_bytes.slice(cell_record_pos, cell_record_pos+record_size);

            if (record_type_bytes[0] == 0x00 && record_type_bytes[1] == 0x02) {
              // Unknown record 0x00 0x02 - Dimensions? - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/5fd3837c-9f3d-4952-8a85-ad93ddb37ced
              cell_record_pos += record_size;
            } else if (record_type_bytes[0] == 0x08 && record_type_bytes[1] == 0x02) {
              // Row Record - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/4aab09eb-49ed-4d01-a3b1-1d726247d3c2
              record_type_str = "Row";
              cell_record_pos += record_size;
            } else if (record_type_bytes[0] == 0xFD && record_type_bytes[1] == 0x00) {
              // Label Set - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/3f52609d-816f-44a7-aad1-e0fe2abccebd
              record_type_str = "LabelSst";
              cell_row = this.get_two_byte_int(file_bytes.slice(cell_record_pos, cell_record_pos+2), byte_order) + 1;
              cell_col = this.get_two_byte_int(file_bytes.slice(cell_record_pos+2, cell_record_pos+4), byte_order);
              cell_record_pos += record_size;
            } else if (record_type_bytes[0] == 0x07 && record_type_bytes[1] == 0x02) {
              // String - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/504b6cfc-d57b-4296-92f4-ceefc0a2ca9b
              // This is probably the pre-calculated cell vaue of the previous cell.
              record_type_str = "String";
              cell_record_pos += record_size;
            } else if (record_type_bytes[0] == 0x06 && record_type_bytes[1] == 0x00) {
              // Cell Formula - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/8e3c6978-6c9f-4915-a826-07613204b244
              record_type_str = "Formula";
              cell_row = this.get_two_byte_int(file_bytes.slice(cell_record_pos, cell_record_pos+2), byte_order) + 1;
              cell_col = this.get_two_byte_int(file_bytes.slice(cell_record_pos+2, cell_record_pos+4), byte_order);
              cell_record_pos += record_size;
            } else if (record_type_bytes[0] == 0x7E && record_type_bytes[1] == 0x02) {
              // RK - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/656e0e79-8b9d-4854-803f-23ec62080678
              // The RK record specifies the numeric data contained in a single cell.
              record_type_str = "RK";
              cell_row = this.get_two_byte_int(file_bytes.slice(cell_record_pos, cell_record_pos+2), byte_order) + 1;
              cell_col = this.get_two_byte_int(file_bytes.slice(cell_record_pos+2, cell_record_pos+4), byte_order);
              cell_record_pos += record_size;
            } else if (record_type_bytes[0] == 0xBE && record_type_bytes[1] == 0x00) {
              // MulBlank - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/a9ab7fa1-183a-487c-a506-6b4a19e770be
              // These are blank cells
              cell_record_pos += record_size;
              console.log("MulBlank"); // DEBUG
            } else {
              // Unknown record
              var u_rec_int = this.get_two_byte_int([record_type_bytes[0],record_type_bytes[1]], byte_order);
              //console.log("Unknown record: " + u_rec_int + " - " + record_type_bytes[0] + " " + record_type_bytes[1]);
              cell_record_pos += record_size;
            }

            if (cell_row != 0 && cell_col >= 0) {
              cell_name = this.convert_xls_column(cell_col) + cell_row;
            }

            if (record_type_str != "unknown") {
              cell_records.push({
                'sheet_name': sheet_name,
                'cell_name': cell_name,
                'record_type': record_type_str,
                'record_type_bytes': record_type_bytes,
                'record_size': record_size,
                'record_bytes': record_bytes
              });
            }
          }

        }
      }
    }

    return cell_records;
  }

  /**
   * Searches for IoCs and adds found IoCs and any related findings to the file_info object.
   *
   * @param  {String} search_text The text to search.
   * @param  {object} file_json The class outbut object, see get_default_file_json for format.
   * @return {Object} The updated file_json object.
   */
  search_for_iocs(search_text, file_json) {
    var found_urls = this.search_for_url(search_text);

    for (var i=0; i<found_urls.urls.length; i++) {
      if (!file_json.iocs.includes(found_urls.urls[i])) {
        file_json.iocs.push(found_urls.urls[i]);
      }
    }

    for (var i=0; i<found_urls.findings.length; i++) {
      if (!file_json.analytic_findings.includes(found_urls.findings[i])) {
        file_json.analytic_findings.push(found_urls.findings[i]);
      }
    }

    return file_json;
  }

  /**
   * Searches for and returns URL detected in the provided text.
   *
   * @param  {String} search_text The text to search.
   * @return {Object} An array of any found URLs.
   */
  search_for_url(search_text) {
    var found_urls = [];
    var findings = [];

    var url_regex = /((?:https?\:\/\/|\\\\)[a-zA-Z0-9\.\/\-\:\_\~\?\#\[\]\@\!\$\&\(\)\*\+\%\=]+)/gmi;
    var url_match = url_regex.exec(search_text);

    while (url_match !== null) {
      // Check for hex IP
      var hex_ip_match = /(?:\/|\\)(0x[0-9a-f]+)\//gmi.exec(url_match[1]);
      if (hex_ip_match !== null) {
        findings.push("SUSPICIOUS - Hex Obfuscated IP Address");

        try {
          var str_ip = Static_File_Analyzer.get_ip_from_hex(hex_ip_match[1]);
          var do_url = url_match[1].replace(hex_ip_match[1], str_ip);
          do_url = (do_url.endsWith(")")) ? do_url.slice(0,-1) : do_url;
          found_urls.push(do_url);
        } catch(err) {
          if (url_match[1].endsWith(")")) {
            found_urls.push(url_match[1].slice(0,-1));
          } else {
            found_urls.push(url_match[1]);
          }
        }
      } else {
        if (url_match[1].endsWith(")")) {
          found_urls.push(url_match[1].slice(0,-1));
        } else {
          found_urls.push(url_match[1]);
        }
      }

      url_match = url_regex.exec(search_text);
    }

    return {
      'urls': found_urls,
      'findings': findings
    }
  }
}
