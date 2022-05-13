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

    if (file_text == "") {
      file_text = Static_File_Analyzer.get_ascii(file_bytes);
    }

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
    } else if (this.array_equals(file_bytes.slice(0,4), [37,80,68,70])) {
      file_info = this.analyze_pdf(file_bytes, file_text);
    } else if (this.array_equals(file_bytes.slice(0,4), [137,80,78,71])) {
      file_info = this.analyze_png(file_bytes, file_text);
    } else if (this.array_equals(file_bytes.slice(0,8), [208,207,17,224,161,177,26,225])) {
      file_info = this.analyze_xls(file_bytes);
    } else if (this.array_equals(file_bytes.slice(0,5), [60,63,120,109,108])) {
      file_info = this.analyze_xml(file_bytes);
    } else if (this.array_equals(file_bytes.slice(0,4), [80,75,3,4])) {
      file_info = this.analyze_zip(file_bytes);
    } else {
      // Probably a text or mark up/down language
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

    var rules = [
      {
        name:  "SUSPICIOUS - VBA Macro Calls Shell Command",
        regex: /Shell\(\s*[^\,\)]+\s*(?:,\s*[a-zA-Z]+\s*)?\)/gmi
      },
      {
        name:  "SUSPICIOUS - Certutil used to download a file",
        regex: /certutil\.exe\s+-urlcache\s+-split\s+-f\s+/gmi
      }
    ];

    for (var r=0; r < rules.length; r++) {
      if (rules[r].regex.test(script_text)) {
        findings.push(rules[r].name);
      }
    }

    return findings;
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
        //console.log(objects_matches[1]); // DEBUG
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
   * Extract attributes from a Visual Basic for Applications (VBA) file.
   *
   * @param {Uint8Array}           file_bytes Array with int values 0-255 representing the bytes of the VBA file to be analyzed.
   * @return {{attributes: array}} The attributes of the given VBA file bytes.
   */
  analyze_vba(file_bytes) {
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
   * Extracts meta data and other information from Excel Binary File Format (.xls) files.
   *
   * @see https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/cd03cb5f-ca02-4934-a391-bb674cb8aa06
   * @see https://www.loc.gov/preservation/digital/formats/fdd/fdd000510.shtml
   * @see https://blog.reversinglabs.com/blog/excel-4.0-macros
   * @see http://www.openoffice.org/sc/compdocfileformat.pdf
   * @see https://inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_xls(file_bytes) {
    var file_info = this.get_default_file_json();

    file_info.file_format = "xls";
    file_info.file_generic_type = "Spreadsheet";

    var current_byte = 0;
    var compound_file_binary_minor_ver_bytes = file_bytes.slice(24,26);
    var compound_file_binary_major_ver_bytes = file_bytes.slice(26,28);

    if (this.array_equals(compound_file_binary_major_ver_bytes, [3,0])) {
      file_info.file_format_ver = "3";
    } else if (this.array_equals(compound_file_binary_major_ver_bytes, [4,0])) {
      file_info.file_format_ver = "4";
    }

    // Byte order LITTLE_ENDIAN or BIG_ENDIAN
    var byte_order_bytes = file_bytes.slice(28,30);
    var byte_order = (byte_order_bytes[1] == 255) ? this.LITTLE_ENDIAN : this.BIG_ENDIAN;

    var sector_size_bytes = file_bytes.slice(30,32);
    var sector_size = 512; // Size in bytes

    //Sector size will indicate where the beginning of file record starts.
    if (this.array_equals(sector_size_bytes, [9,0])) {
      sector_size = 512;
    } else if (this.array_equals(sector_size_bytes, [12,0])) {
      sector_size = 4096;
    }

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

    if (file_bytes[sector_size] == 9) {
      // Beginning of file record found.

      // BIFF 5 and 7 has a length of 8 bytes. For BIFF 8, the length of the BOF record can be either 8 or 16 bytes.
      var biff_record_length = this.get_two_byte_int(file_bytes.slice(sector_size+2,sector_size+4), byte_order);

      // Byte value of 5 representing BIFF 5/7 and 6 representing BIFF 8.
      var biff_version = file_bytes[sector_size+5];
      var xlm_val = file_bytes.slice(sector_size+6,sector_size+8);

      if (this.array_equals(xlm_val, [40,0])) {
        // Excel 4.0 macro sheet
      }

      current_byte = sector_size+8;

      var rup_build = this.get_two_byte_int(file_bytes.slice(current_byte,current_byte+=2), byte_order);
      var rup_year = this.get_two_byte_int(file_bytes.slice(current_byte,current_byte+=2), byte_order);

      var spreadsheet_sheet_names = {};

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
            'data': {}
          };

          //BRAI record

          // id - 1 byte
          // rt - 1 byte
          // fUnlinkedIfmt - 1 bit
          // reserved - 15 bits
          // ifmt  - 2 bytes
          // formula

          i += boundsheet_length+3;
        }
      }


    } else {
      // File format error.
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
      file_entry.compressed_size = this.get_four_byte_int(file_bytes.slice(current_file_start+18,current_file_start+22));
      file_entry.uncompressed_size = this.get_four_byte_int(file_bytes.slice(current_file_start+22,current_file_start+26));
      file_entry.file_name_length = this.get_two_byte_int(file_bytes.slice(current_file_start+26,current_file_start+28));
      file_entry.extra_field_length = this.get_two_byte_int(file_bytes.slice(current_file_start+28,current_file_start+30));

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
      file_info.file_components.push(file_entry.file_name);
    }

    // Check if this file is really an OOXML Document / Office document
    // Ref: http://officeopenxml.com/anatomyofOOXML.php
    if (has_content_types_xml == true && has_rels_dir == true) {
      var spreadsheet_auto_open = false;
      var spreadsheet_auto_open_name = "";
      var spreadsheet_defined_names = {};
      var spreadsheet_sheet_names = {}; // Spreadsheet names index
      var spreadsheet_sheet_relations = {};

      for (var i = 0; i < archive_files.length; i++) {
        if (archive_files[i].file_name.toLowerCase().substring(0, 5) == "ppt/") {
          file_info.file_format = "pptx";
          file_info.file_generic_type = "Presentation";
        } else if (archive_files[i].file_name.toLowerCase().substring(0, 5) == "word/") {
          file_info.file_format = "docx";
          file_info.file_generic_type = "Document";
        } else if (archive_files[i].file_name.toLowerCase().substring(0, 3) == "xl/") {
          file_info.file_format = (file_info.file_format != "xlsm") ? "xlsx" : "xlsm";
          file_info.file_generic_type = "Spreadsheet";

          if (archive_files[i].file_name.toLowerCase() == "xl/workbook.xml") {
            // Look for more meta data
            var workbook_xml_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i);
            var workbook_xml = Static_File_Analyzer.get_string_from_array(workbook_xml_bytes);

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

          } else if (archive_files[i].file_name.toLowerCase() == "xl/_rels/workbook.xml.rels") {
            // This will build the relationships for this spreadsheet. We can use this to find malicious code.
            var workbook_xml_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i);
            var workbook_xml = Static_File_Analyzer.get_string_from_array(workbook_xml_bytes);

            var relationship_regex = /\<Relationship\s*Id\s*\=\s*[\"\']([a-zA-Z0-9]+)[\"\']\s+Type\s*\=\s*[\"\']([^\"\']+)[\"\']\s*Target\s*\=\s*[\"\']([^\"\']+)[\"\']/gmi;
            var relationship_matches = relationship_regex.exec(workbook_xml);

            while (relationship_matches != null) {
              spreadsheet_sheet_relations[relationship_matches[1]] = {
                'type':   relationship_matches[2],
                "target": relationship_matches[3]
              }

              relationship_matches = relationship_regex.exec(workbook_xml);
            }
          }
        }

        // Look for macros
        if (/vbaProject\.bin/gmi.test(archive_files[i].file_name)) {
          file_info.scripts.script_type = "VBA Macro";
          file_info.file_format = "xlsm";

          // Zip Decompression
          var macro_data = await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i);
          var vba_data = this.analyze_vba(macro_data);

          for (var s = 0; s < vba_data.attributes.length; s++) {
            var sub_match = /\n[a-z\s]+Sub[^\(]+\([^\)]*\)/gmi.exec(vba_data.attributes[s]);

            if (sub_match != null) {
              var vba_code = vba_data.attributes[s].substring(sub_match.index).trim();
              var findings = this.analyze_embedded_script(vba_code);

              for (var f=0; f<findings.length; f++) {
                file_info.analytic_findings.push(findings[f]);
              }

              file_info.scripts.extracted_script += vba_code + "\n\n";
            }
          }
        } else if (/docProps\/core\.xml/gmi.test(archive_files[i].file_name)) {
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
        if (spreadsheet_auto_open == true) {
          var auto_open_cell = spreadsheet_defined_names[spreadsheet_auto_open_name];
          var auto_open_sheet_obj = spreadsheet_sheet_names[auto_open_cell.split("!")[0]];

          // Preload sheet target / file names into spreadsheet_sheet_names
          for (const [key, value] of Object.entries(spreadsheet_sheet_names)) {
            spreadsheet_sheet_names[key].file_name = spreadsheet_sheet_relations[value.rid].target;
          }

          // Index cell values and formaulas in all sheets
          for (var fi = 0; fi < archive_files.length; fi++) {
            for (const [key, value] of Object.entries(spreadsheet_sheet_names)) {
              if (archive_files[fi].file_name == "xl/" + value.file_name) {
                var sheet_xml_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, fi);
                var sheet_xml = Static_File_Analyzer.get_string_from_array(sheet_xml_bytes);

                var c_tags_regex = /\<\s*c\s*r\s*\=\s*[\"\']([a-zA-Z0-9]+)[\"\'][^\>]+\>\s*(?:\<\s*f\s*\>([^\<]+)\<\/f\>\s*)?\<\s*v\s*\>([^\<]+)\<\/v\>/gmi;
                var c_tags_matches = c_tags_regex.exec(sheet_xml);

                while (c_tags_matches != null) {
                  var cell_id = c_tags_matches[1];
                  spreadsheet_sheet_names[key]['data'][cell_id] = {
                    'formula': c_tags_matches[2],
                    'value': c_tags_matches[3]
                  }

                  c_tags_matches = c_tags_regex.exec(sheet_xml);
                }

                break;
              }
            }
          }

          /* Apparently the actual cell for auto open isn't important, we just
             need to execute all the formulas in the sheet part of auto open.
             We have already indexed that formulas, so let's execute them.
          */
          for (const [key, value] of Object.entries(auto_open_sheet_obj.data)) {
            var formula_output = this.calculate_cell_formula(value.formula, spreadsheet_sheet_names, auto_open_sheet_obj.name, file_info);

          }

        }
      }
    }

    return file_info;
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
            var byte_length = this.get_int_from_bin(copy_token_bits.slice(number_of_offset_bits+1, copy_token_bits.length+1), this.BIG_ENDIAN) + 3;
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
                  //length_diff = end_index - ((decompressed_buffer.length-1) + (bytes_to_copy.length-original_copy_bytes_len));
                  length_diff -= overflow_bytes.length;
                }
              }
            }

            decompressed_buffer.push(...bytes_to_copy);
          }
        }
      }

    } else {
      // Error, header block not find
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

    var formula_regex = /\=?([a-zA-Z]+)\(([^\,\)]+\,?)([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?([^\,\)]+\,?)?\)/gmi;
    var formula_matches = formula_regex.exec(cell_formula);

    while (formula_matches != null) {
      var formula_name = formula_matches[1];
      var formula_params = [];
      var param_index = 2;

      while (formula_matches[param_index] !== null && formula_matches[param_index] !== undefined) {
        if ((formula_matches[param_index].match(/\!/g) || []).length > 1) {
          //Multiple cell references
          if ((formula_matches[param_index].match(/\&amp\;/gi) || []).length > 1) {
            // Concat
            var concat_parts = formula_matches[param_index].split("&amp;");
            var concat_result = "";

            for (var p=0; p<concat_parts.length; p++) {
              concat_result += this.get_ooxlm_cell_data(concat_parts[p], spreadsheet_sheet_names, active_sheet).value;
            }

            formula_params[param_index] = concat_result;
          }
        } else {
          var cell_ref_obj = this.get_ooxlm_cell_data(formula_matches[param_index], spreadsheet_sheet_names, active_sheet);

          if (cell_ref_obj !== null && cell_ref_obj !== undefined) {
            if (cell_ref_obj.value !== null && cell_ref_obj.value !== undefined) {
              // Value is already calculated
              formula_params[param_index] = cell_ref_obj.value;
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
    if (formula_name.toUpperCase() == "CALL") {
      file_info.analytic_findings.push("SUSPICIOUS - Use of CALL function");
      file_info.scripts.extracted_script += formula_matches.input + "\n\n";
    } else if (formula_name.toUpperCase() == "CHAR") {

    } else if (formula_name.toUpperCase() == "EXEC") {
      file_info.analytic_findings.push("SUSPICIOUS - Use of EXEC function");
      file_info.scripts.extracted_script += formula_matches.input + "\n\n";
    } else if (formula_name.toUpperCase() == "FORMULA") {
      /*  FORMULA(formula_text, reference)
          Formula_text - text, number, reference, or formula
          reference - Cell Reference
          Takes the value in formula_text and places it in the spreadsheet at the location defined by reference.
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
    }
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
   * Converts an array with four int values 0-255 to an integer.
   *
   * @param {array}    bytes Array with four int values 0-255 representing byte values.
   * @param {String}   endianness Value indicating how to interperate the bit order of the byte array. Default is BIG_ENDIAN.
   * @return {integer} The integer value of the given bit array.
   */
  get_four_byte_int(bytes, endianness = this.BIG_ENDIAN) {
    var int_bits = "";

    if (endianness = this.LITTLE_ENDIAN) {
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

    if (endianness = this.LITTLE_ENDIAN) {
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
  static async get_zipped_file_bytes(file_bytes, entry_index) {
    if (window.zip) {
      var uint8_array = new Uint8Array(file_bytes);
      var new_zip = new zip.ZipReader(new zip.Uint8ArrayReader(uint8_array), {useWebWorkers: false});
      var new_zip_entries = await new_zip.getEntries({});
      var unzipped_file_bytes = await new_zip_entries[entry_index].getData(new zip.Uint8ArrayWriter());

      return unzipped_file_bytes;
    } else {
      throw "Zip decompression library not found. Please include zip-full.js from https://github.com/gildas-lormeau/zip.js";
    }
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

}
