/*
 Copyright (c) 2025 Alec Dhuse. All rights reserved.

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
  static BIG_ENDIAN = "BIG_ENDIAN";
  static LITTLE_ENDIAN = "LITTLE_ENDIAN";
  static XML_DOMAINS = ["openoffice.org","purl.org","schemas.microsoft.com","schemas.openxmlformats.org","w3.org"];

  /**
   * Empty constructor.
   *
   */
  constructor() {

  }

  /**
   * Created the default object structure for the output of this class.
   *
   * @param {Uint8Array} file_bytes    Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param {String}     file_text     [Optional] The text version of the file, it can be provided to save compute time, otherwise it will be generated in this constructor.
   * @param {String}     file_password [Optional] File password for encrypted or protected files.
   * @return {object}    An object with analyzed file results. See get_default_file_json for the format.
   */
  async analyze(file_bytes, file_text="", file_password=undefined) {
    var file_info = await Static_File_Analyzer.get_default_file_json();

    if (Static_File_Analyzer.array_equals(file_bytes.slice(7,14), [42,42,65,67,69,42,42])) {
      file_info = this.analyze_ace(file_bytes);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,8), [208,207,17,224,161,177,26,225])) {
      file_info = this.analyze_cbf(file_bytes);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,2), [77,90])) {
      file_info = this.analyze_exe(file_bytes);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,5), [0x47,0x49,0x46,0x38,0x39])) {
      file_info = this.analyze_gif(file_bytes);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,2), [31,139])) {
      file_info = this.analyze_gz(file_bytes);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(32769,32774), [67,68,48,48,49]) ||
               Static_File_Analyzer.array_equals(file_bytes.slice(32769,32775), [66,69,65,48,49,1])) {
      file_info = this.analyze_iso9660(file_bytes, file_text);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,3), [0xFF,0xD8,0xFF])) {
      file_info = await this.analyze_jpeg(file_bytes, file_text);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,4), [76,0,0,0])) {
      file_info = this.analyze_lnk(file_bytes);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,16), [0xE4,0x52,0x5C,0x7B,0x8C,0xD8,0xA7,0x4D,0xAE,0xB1,0x53,0x78,0xD0,0x29,0x96,0xD3])) {
      file_info = this.analyze_one(file_bytes);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,6), [82,97,114,33,26,7])) {
      file_info = this.analyze_rar(file_bytes);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,4), [0x7b,0x5c,0x72,0x74])) {
      file_info = this.analyze_rtf(file_bytes);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,4), [37,80,68,70])) {
      if (file_text == "") file_text = Static_File_Analyzer.get_ascii(file_bytes);
      file_info = await this.analyze_pdf(file_bytes, file_text);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,4), [137,80,78,71])) {
      if (file_text == "") file_text = Static_File_Analyzer.get_ascii(file_bytes);
      file_info = this.analyze_png(file_bytes, file_text);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,4), [0x49,0x49,0x2A,0x00])) {
      file_info = this.analyze_tiff(file_bytes);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,4), [0x78,0x9f,0x3e,0x22])) {
      file_info = this.analyze_tnef(file_bytes);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,5), [0,1,0,0,0])) {
      file_info = this.analyze_ttf(file_bytes); // TTF True Type Font
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,5), [60,63,120,109,108])) {
      file_info = this.analyze_xml(file_bytes);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,4), [80,75,3,4])) {
      file_info = await this.analyze_zip(file_bytes, file_password);
    } else if (file_bytes[0] == 0x78 && [0x01,0x5e,0x9c,0xda,0x20,0x7d,0xbb,0xf9].includes(file_bytes[1])) {
      file_info = this.analyze_zlib(file_bytes);
    } else {
      // Probably a text or mark up/down language
      if (file_text == "") file_text = Static_File_Analyzer.get_ascii(file_bytes);

      if (/\<(?:html|\!doctype\s+html|script|meta\s+content)/gmi.test(file_text)) {
        file_info = this.analyze_html(file_bytes, file_text);
      } else if (/\<!doctype\s+/gmi.test(file_text)) {
        // generic XML
      }
    }

    // Look for scripts and IoCs in file_components
    for (let i=0; i<file_info.file_components.length; i++) {
      let static_analyzer = new Static_File_Analyzer();
      let analyzer_results = await static_analyzer.analyze(file_info.file_components[i].file_bytes, "", "");

      if (analyzer_results.scripts.script_type != "none") {
        this.add_extracted_script(analyzer_results.scripts.script_type, analyzer_results.scripts.extracted_script, file_info);
      }

      for (let i=0; i<analyzer_results.iocs.length; i++) {
        file_info = Static_File_Analyzer.search_for_iocs(analyzer_results.iocs[i], file_info);
      }
    }

    // Attempt to identify threat actor and or malware.
    file_info = await this.identify_threat(file_info);

    // Generate file hashes
    file_info.file_hashes.sha256 = await Hash_Tools.get_sha256(file_bytes);
    file_info.file_hashes.md5 = await Hash_Tools.get_md5(file_bytes);

    return file_info;
  }

  /**
   * Attempts to validate if an array of bytes represents a valid file.
   *
   * @param  {array}    file_bytes
   * @return {{'is_valid','type'}} Object that returns if this is a valid file and it's type.
   */
  static is_valid_file(file_bytes) {
    var return_val = {'is_valid': false, 'type': "unknown"};

    if (Static_File_Analyzer.array_equals(file_bytes.slice(7,14), [42,42,65,67,69,42,42])) {
      return_val = {'is_valid': true, 'type': "ace"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,2), [77,90])) {
      return_val = {'is_valid': true, 'type': "exe"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,5), [0x47,0x49,0x46,0x38,0x39])) {
      return_val = {'is_valid': true, 'type': "gif"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,2), [31,139])) {
      return_val = {'is_valid': true, 'type': "gz"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(32769,32774), [67,68,48,48,49]) ||
               Static_File_Analyzer.array_equals(file_bytes.slice(32769,32775), [66,69,65,48,49,1])) {
      return_val = {'is_valid': true, 'type': "iso"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,3), [0xFF,0xD8,0xFF])) {
      return_val = {'is_valid': true, 'type': "jpeg"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,4), [76,0,0,0])) {
      return_val = {'is_valid': true, 'type': "lnk"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,16), [0xE4,0x52,0x5C,0x7B,0x8C,0xD8,0xA7,0x4D,0xAE,0xB1,0x53,0x78,0xD0,0x29,0x96,0xD3])) {
      return_val = {'is_valid': true, 'type': "one"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,6), [82,97,114,33,26,7])) {
      return_val = {'is_valid': true, 'type': "rar"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,4), [0x7b,0x5c,0x72,0x74])) {
      return_val = {'is_valid': true, 'type': "rtf"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,4), [37,80,68,70])) {
      return_val = {'is_valid': true, 'type': "pdf"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,4), [137,80,78,71])) {
      return_val = {'is_valid': true, 'type': "png"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,8), [208,207,17,224,161,177,26,225])) {
      let file_type = CFB_Parser.identify_file_type(file_bytes);
      return_val = {'is_valid': true, 'type': file_type};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,5), [0x78,0x9f,0x3e,0x22])) {
      return_val = {'is_valid': true, 'type': "tnef"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,5), [0,1,0,0,0])) {
      return_val = {'is_valid': true, 'type': "ttf"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,5), [60,63,120,109,108])) {
      return_val = {'is_valid': true, 'type': "xml"};
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(0,4), [80,75,3,4])) {
      return_val = {'is_valid': true, 'type': "zip"};
    } else if (file_bytes[0] == 0x78 && [0x01,0x5e,0x9c,0xda,0x20,0x7d,0xbb,0xf9].includes(file_bytes[1])) {
      return_val = {'is_valid': true, 'type': "zlib"};
    } else {
      // Probably a text or mark up/down language
      let file_text = "";

      if (file_bytes.length > 256) {
        file_text = Static_File_Analyzer.get_ascii(file_bytes.slice(0,256));
      } else {
        file_text = Static_File_Analyzer.get_ascii(file_bytes);
      }

      if (/\<(?:html|\!doctype\s+html|script|meta\s+content)/gmi.test(file_text)) {
        return_val = {'is_valid': true, 'type': "html"};
      } else if (/\<!doctype\s+/gmi.test(file_text)) {
        return_val = {'is_valid': true, 'type': "xml"};
      }
    }

    return return_val;
  }

  /**
   * Add found extracted script to output.
   *
   * @param  {String}    script_type Name of the script type to add.
   * @param  {String}    script_text The actual script text.
   * @param  {object}    file_info   The file_info object to add the script to.
   * @return {undefined}
   */
  add_extracted_script(script_type, script_text, file_info) {
    file_info.scripts.script_type = script_type;

    if (!file_info.scripts.extracted_script.includes(script_text)) {
      file_info.scripts.extracted_script += script_text;
      file_info.scripts.extracted_script += (script_type == "Excel 4.0 Macro") ? "\n" : "\n\n";
    }
  }

  /**
   * Adds a TTP to the given file_info JSON object.
   * This is meant for MITRE ATT&CK® TTPs, but there is no validating.
   *
   * @param  {String}    ttp_id          The TTP ID.
   * @param  {String}    ttp_tactic      Which tactic the TTPs refers to.
   * @param  {String}    ttp_description Optional description of how this TTP is being used.
   * @param  {object}    file_info       The file_info object to add the script to.
   * @return {undefined}
   */
  static add_ttp(ttp_id, ttp_tactic, ttp_description="", file_info) {
    let ttp_found = false;
    let add_to_description = false;

    for (let i=0; i<file_info.ttps.length; i++) {
      if (file_info.ttps[i].ttp_id == ttp_id && file_info.ttps[i].ttp_tactic == ttp_tactic) {
        if (file_info.ttps[i].ttp_description == ttp_description) {
          ttp_found = true;
          break;
        } else {
          ttp_found = true;
          add_to_description = true;
          file_info.ttps[i].ttp_description += " " + ttp_description;
          break;
        }
      }
    }

    if (ttp_found == false) {
      file_info.ttps.push({
        'ttp_id':          ttp_id,
        'ttp_tactic':      ttp_tactic,
        'ttp_description': ttp_description
      });
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
    var file_info = Static_File_Analyzer.get_default_file_json();

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
   * Extracts meta data and other information from Excel Binary File Format (.xls) files.
   *
   * @see http://www.openoffice.org/sc/compdocfileformat.pdf
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_cbf(file_bytes) {
    let file_info = Static_File_Analyzer.get_default_file_json();

    file_info.file_format = CFB_Parser.identify_file_type(file_bytes);

    let document_obj = {
      'type': "unknown",
      'byte_order': Static_File_Analyzer.LITTLE_ENDIAN,
      'document_properties': {},
      'compound_file_binary': {}
    };

    document_obj.compound_file_binary = this.parse_compound_file_binary(file_bytes);
    document_obj.byte_order = document_obj.compound_file_binary.byte_order; // Byte order LITTLE_ENDIAN or BIG_ENDIAN
    file_info.file_format_ver = document_obj.compound_file_binary.format_version_major;

    var number_of_directory_sectors = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(40,44), document_obj.byte_order);
    var number_of_sectors = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(44,48), document_obj.byte_order);
    var sec_id_1 = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(48,52), document_obj.byte_order);
    var min_stream_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(56,60), document_obj.byte_order);
    var short_sec_id_1 = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(60,64), document_obj.byte_order);
    var number_of_short_sectors = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(64,68), document_obj.byte_order);
    var master_sector_id_1 = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(68,72), document_obj.byte_order);
    var number_of_master_sectors = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(72,76), document_obj.byte_order);

    var sec_1_pos = 512 + (sec_id_1 * document_obj.compound_file_binary.sector_size); // Should be Root Entry
    var workbook_pos = sec_1_pos + 128;
    var summary_info_pos = workbook_pos + 128;
    var doc_summary_info_pos = summary_info_pos + 128;

    if (Static_File_Analyzer.array_equals(file_bytes.slice(workbook_pos, workbook_pos+13),[0x45,0x00,0x6E,0x00,0x63,0x00,0x72,0x00,0x79,0x00,0x70,0x00,0x74])) {
      file_info.file_encrypted = "true";
    } else {
      file_info.file_encrypted = "false";
    }

    for (var c=0; c<document_obj.compound_file_binary.entries.length; c++) {
      if (document_obj.compound_file_binary.entries[c].entry_name.toLowerCase() != "root entry") {
        file_info.file_components.push({
          'name': document_obj.compound_file_binary.entries[c].entry_name,
          'type': "cfb",
          'directory': false,
          'file_bytes': document_obj.compound_file_binary.entries[c].entry_bytes
        });

        // Update creation and modification date/times
        if (document_obj.compound_file_binary.entries[c].entry_properties.creation_time != "1601-01-01T00:00:00.000Z") {
          if (document_obj.compound_file_binary.entries[c].entry_properties.creation_time < file_info.metadata.creation_date ||
              file_info.metadata.creation_date == "0000-00-00 00:00:00") {
            file_info.metadata.creation_date = document_obj.compound_file_binary.entries[c].entry_properties.creation_time;
          }
        }

        if (document_obj.compound_file_binary.entries[c].entry_properties.modification_time > file_info.metadata.last_modified_date) {
          file_info.metadata.last_modified_date = document_obj.compound_file_binary.entries[c].entry_properties.modification_time;
        }
      }

      if (document_obj.compound_file_binary.entries[c].entry_name.toLowerCase() == "summaryinformation") {
        document_obj.document_properties = document_obj.compound_file_binary.entries[c].entry_properties;
        var creation_os = "unknown";

        if (document_obj.document_properties.hasOwnProperty("os")) {
          creation_os = document_obj.document_properties.os + " " + (document_obj.document_properties.hasOwnProperty("os_version") ? document_obj.document_properties.os_version : "");
        }

        file_info.metadata.author = (document_obj.document_properties.hasOwnProperty("author")) ? document_obj.document_properties.author : "unknown";
        file_info.metadata.creation_application = (document_obj.document_properties.hasOwnProperty("creating_application")) ? document_obj.document_properties.creating_application : "unknown";
        file_info.metadata.creation_os = creation_os;
        file_info.metadata.creation_date = (document_obj.document_properties.hasOwnProperty("create_date")) ? document_obj.document_properties.create_date : "0000-00-00 00:00:00";
        file_info.metadata.description = (document_obj.document_properties.hasOwnProperty("subject")) ? document_obj.document_properties.subject : "unknown";
        file_info.metadata.last_modified_date = (document_obj.document_properties.hasOwnProperty("last_saved")) ? document_obj.document_properties.last_saved : "0000-00-00 00:00:00";
        file_info.metadata.title = (document_obj.document_properties.hasOwnProperty("title")) ? document_obj.document_properties.title : "unknown";
      } else if (document_obj.compound_file_binary.entries[c].entry_name.toLowerCase() == "start") {
        if (file_info.file_format == "vba") {
          let script_start = document_obj.compound_file_binary.entries[c].entry_start;
          let script_end = file_bytes.length;

          if (document_obj.compound_file_binary.entries.length > c+1) {
            script_end = document_obj.compound_file_binary.entries[c+1].entry_start;
          }

          let section_bytes = file_bytes.slice(script_start,script_end);

          while (section_bytes.length > 0) {
            if (section_bytes[2] == 0xB0) {
              // Not VBA code
              let block_size = section_bytes[1];
              section_bytes = section_bytes.slice(192);
            } else if (section_bytes[2] == 0xB1) {
              // VBA code
              let decompressed_bytes = this.decompress_vba(section_bytes);
              let vba_code = Static_File_Analyzer.get_ascii(decompressed_bytes);
              file_info.parsed = vba_code;

              // Extract VBA code
              var matches = vba_code.match(/Attribute[^\n\r]+(?:\n|\r)*/g);
              var last_match = matches[matches.length-1];
              var extracted_vba = vba_code.substring(vba_code.indexOf(last_match) + last_match.length);
              this.add_extracted_script("VBA Macro", this.pretty_print_vba(extracted_vba), file_info);

              var analyzed_results = this.analyze_embedded_script(extracted_vba);

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
              break;
            }
          }
        }
      } else if (document_obj.compound_file_binary.entries[c].entry_name.toLowerCase() == "vba") {
        file_info.file_format = "vba";
        file_info.file_generic_type = "Embedded Script";
      } else if (document_obj.compound_file_binary.entries[c].entry_name.toLowerCase() == "worddocument") {
        file_info.file_format = "doc";
        file_info.file_generic_type = "Document";
        document_obj.type = "document";
      } else if (document_obj.compound_file_binary.entries[c].entry_name.toLowerCase() == "workbook") {
        if (file_info.file_format != "vba") {
          file_info.file_format = "xls";
          file_info.file_generic_type = "Spreadsheet";
          document_obj.type = "spreadsheet";
        }
      }
    }

    if (file_info.file_format == "xls") {
      file_info = this.analyze_xls(file_bytes, file_info, document_obj);
    } else if (file_info.file_format == "msg") {
      file_info.file_generic_type = "Mail Message";
      document_obj.type = "mailmessage";
      file_info = this.analyze_msg(file_bytes, file_info, document_obj.compound_file_binary);
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
        this.add_extracted_script("Excel 4.0 Macro", "="+macro_functions[i], file_info);

        if (/CALL\(/gm.test(macro_functions[i])) {
          new_finding = "SUSPICIOUS - Use of CALL function";
        } else if (/EXEC\(/gm.test(macro_functions[i])) {
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

    file_info = Static_File_Analyzer.search_for_iocs(macro_string, file_info);

    return file_info;
  }

  /**
   * Extracts meta data and other information from .exe executable files.
   *
   * @see https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_exe(file_bytes) {
    var file_info = Static_File_Analyzer.get_default_file_json();
    var id_byte_vals = [1,3,5,7,15,129,201];

    // Header offset starts at 3C / 60
    var header_offset = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(60,62), Static_File_Analyzer.LITTLE_ENDIAN);
    var file_type_id_byte = file_bytes[header_offset+23];

    if (id_byte_vals.includes(file_type_id_byte)) {
      // File is an EXE
      file_info.file_format = "exe";
      file_info.file_generic_type = "Executable";
    } else {
      // File is a DLL
      file_info.file_format = "dll";
      file_info.file_generic_type = "Shared Library";
    }

    // Get current date
    var current_date_obj = new Date();
    var current_date = current_date_obj.toISOString().split("T")[0];

    // Get compile time
    var compile_time_offset = header_offset + 8;
    var compile_timestamp_int = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(compile_time_offset,compile_time_offset+4), Static_File_Analyzer.LITTLE_ENDIAN);
    var compile_timestamp = new Date(compile_timestamp_int*1000);
    file_info.metadata.creation_date = compile_timestamp.toISOString().slice(0, 19).replace("T", " ");;

    if (file_info.metadata.creation_date.split(" ")[0] > current_date) {
      file_info.analytic_findings.push("SUSPICIOUS - Future Compile Date");
    }

    // Get optional header size
    var optional_header_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(header_offset+20,header_offset+22), Static_File_Analyzer.LITTLE_ENDIAN);

    if (optional_header_size > 0) {
      var optional_header_offset = header_offset+24;
      var optional_header_bytes = file_bytes.slice(optional_header_offset, optional_header_offset+optional_header_size);

      if (optional_header_bytes.length > 67) {
        var checksum = Static_File_Analyzer.get_four_byte_int(optional_header_bytes.slice(64,68), Static_File_Analyzer.LITTLE_ENDIAN);

        if (checksum == 0) {
          file_info.analytic_findings.push("SUSPICIOUS - No Image File Checksum");
        }
      }

    }


    return file_info;
  }

  /**
   * Extracts meta data and other information from gif image files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_gif(file_bytes) {
    var file_info = Static_File_Analyzer.get_default_file_json();

    file_info.file_format = "gif";
    file_info.file_generic_type = "Image";

    // This format does not support encryption
    file_info.file_encrypted = "false";
    file_info.file_encryption_type = "none";

    return file_info;
  }

  /**
   * Extracts meta data and other information from gz archive files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_gz(file_bytes) {
    var file_info = Static_File_Analyzer.get_default_file_json();

    file_info.file_format = "gz";
    file_info.file_generic_type = "File Archive";

    // This format does not support encryption
    file_info.file_encrypted = "false";
    file_info.file_encryption_type = "none";

    return file_info;
  }

  /**
   * Extracts meta data and other information from HTML files.
   *
   * @param {Uint8Array}  file_bytes  Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param {String}      file_text   The HTML text of the file.
   * @return {Object}     file_info   A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_html(file_bytes, file_text) {
    var file_info = Static_File_Analyzer.get_default_file_json();

    file_info.file_generic_type = "Document";

    let html_obj = new HTML_Parser(file_bytes, file_text);

    file_info.file_format = html_obj.file_format;
    file_info.file_components = html_obj.file_components;
    file_info.analytic_findings = html_obj.analytic_findings;

    // Extract embedded script
    let extracted_scripts = HTML_Parser.extract_embedded_scripts(file_text);

    for (let i=0; i<extracted_scripts.length; i++) {
      this.add_extracted_script(extracted_scripts[i].script_type, extracted_scripts[i].script_code, file_info);
      file_info = Static_File_Analyzer.search_for_iocs(extracted_scripts[i].script_code, file_info);
    }

    return file_info;
  }

  /**
   * Extracts meta data and other information from .iso image files.
   *
   * @param {Uint8Array}  file_bytes  Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param {String}      file_text   The text of the file.
   * @return {Object}     file_info   A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_iso9660(file_bytes, file_text="") {
    var file_info = Static_File_Analyzer.get_default_file_json();

    file_info.file_format = "iso";
    file_info.file_generic_type = "Disk Image";

    // Check for El Torito format
    if (Static_File_Analyzer.array_equals(file_bytes.slice(34821,34832), [49,1,69,76,32,84,79,82,73,84,79])) {
      // This format does not support encryption
      file_info.file_encrypted = "false";
      file_info.file_encryption_type = "none";

      var parsed_iso = new ISO_9660_Parser(file_bytes);
      file_info.file_format_ver = "El Torito V1";
      file_info.metadata = parsed_iso.metadata;
      file_info.file_components = parsed_iso.files;
      file_info.parsed = JSON.stringify(parsed_iso.descriptors, null, 2);
    } else if (Static_File_Analyzer.array_equals(file_bytes.slice(34817,34822), [67,68,48,48,49])) {
      // iso9660
      var parsed_iso = new ISO_9660_Parser(file_bytes);
      file_info.metadata = parsed_iso.metadata;
      file_info.file_components = parsed_iso.files;
      file_info.file_format_ver = parsed_iso.file_format_ver;
      file_info.parsed = JSON.stringify(parsed_iso.descriptors, null, 2);
    } else {
      // Assume this is a Universal Disk Format (UDF) formatted ISO
      file_info = this.analyze_udf(file_bytes, file_text);
    }

    // Check creation application
    if (Static_File_Analyzer.array_equals(file_bytes.slice(33342,33349), [73,77,71,66,85,82,78])) {
      var app_version = Static_File_Analyzer.get_ascii(file_bytes.slice(33350,33359)).trim();
      file_info.metadata.creation_application = "ImgBurn " + app_version;
      file_info.metadata.creation_os = "Windows"; // ImgBurn is Windows Only
      file_info.file_encrypted = "false";
    } else if (file_info.metadata.creation_application.startsWith("OSCDIMG")) {
      file_info.metadata.creation_os = "Windows"; // Oscdimg is a Windows command-line tool
      file_info.file_encrypted = "false";
    }

    return file_info;
  }

  /**
   * Extracts meta data and other information from JPEG image files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  async analyze_jpeg(file_bytes, file_text) {
    var file_info = Static_File_Analyzer.get_default_file_json();

    file_info.file_format = "jpeg";
    file_info.file_generic_type = "Image";
    file_info.file_encrypted = "false";
    file_info.file_encryption_type = "none";

    var jfif_ver_bytes = file_bytes.slice(11,13);
    var jfif_ver_str = jfif_ver_bytes[0].toString();

    if (jfif_ver_bytes[1] < 10) {
      jfif_ver_str += ".0" +  jfif_ver_bytes[1].toString();
    }  else {
      if (jfif_ver_bytes[1].toString().length == 2) {
        jfif_ver_str += "." + jfif_ver_bytes[1].toString();
      } else {
        jfif_ver_str += "." + jfif_ver_bytes[1].toString() + "0";
      }
    }

    file_info.file_format_ver = "JFIF Version " + jfif_ver_str;

    // Check for RDF Metadata
    if (file_text == "") file_text = Static_File_Analyzer.get_ascii(file_bytes);
    let metadata = this.extract_rdf_metadata(file_bytes, file_text);

    if (metadata.found) {
      file_info.metadata.title = metadata.title;
      file_info.metadata.description = metadata.description;
      file_info.metadata.author = metadata.author;
      file_info.metadata.creation_date = metadata.creation_date;
      file_info.metadata.creation_application = metadata.creation_application;
    }

    var exif_header = [0x45, 0x78, 0x69, 0x66, 0x00, 0x00];
    var byte_order = "LITTLE_ENDIAN";

    // Find EXIF data
    for (let i=2; i<file_bytes.length; i+=2) {
      let byte_code = file_bytes.slice(i, i+2);

      // Look for Application Segment 1
      if (byte_code[0] == 0xFF && byte_code[1] == 0xE1) {
        let data_size = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(i+2, i+4));
        let data_bytes = file_bytes.slice(i+4, i+(data_size-1));
        let header_check_bytes = data_bytes.slice(0, 6);
        if (Static_File_Analyzer.array_equals(header_check_bytes, [0x45, 0x78, 0x69, 0x66, 0x00, 0x00])) {
          // Header check passed.
          let tiff_data = data_bytes.slice(6);
          let tiff_header_check_bytes = data_bytes.slice(6, 14);
          let tiff_start = i+10;

          // Get Byte Order
          if (tiff_header_check_bytes[0] == 0x49) {
            byte_order = "LITTLE_ENDIAN";
          } else if (tiff_header_check_bytes[0] == 0x4d) {
            byte_order = "BIG_ENDIAN";
          }

          let first_ifd_offset = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(tiff_start+4, tiff_start+8), byte_order) + tiff_start;

          let tiff_tags = Tiff_Tools.read_tiff_tags(file_bytes, first_ifd_offset, tiff_start, byte_order);
          let exif_data = {};
          let gps_data = {};

          if (tiff_tags.hasOwnProperty("ExifIFDPointer")) {
            exif_data = Tiff_Tools.read_tiff_tags(file_bytes, tiff_start+tiff_tags.ExifIFDPointer, tiff_start, byte_order);
          }

          if (tiff_tags.hasOwnProperty("GPSInfoIFDPointer")) {
            gps_data = Tiff_Tools.read_tiff_tags(file_bytes, tiff_start+tiff_tags.GPSInfoIFDPointer, tiff_start, byte_order);

            if (gps_data.hasOwnProperty("GPSLatitude")) {
              gps_data.GPSLatitude = gps_data.GPSLatitude[0] + (gps_data.GPSLatitude[1]/60) + (gps_data.GPSLatitude[2]/3600);
              if (gps_data.hasOwnProperty("GPSLatitudeRef")) {
                if (gps_data.GPSLatitudeRef.toUpperCase() == "S") gps_data.GPSLatitude *= -1;
              }
            }

            if (gps_data.hasOwnProperty("GPSLongitude")) {
              gps_data.GPSLongitude = gps_data.GPSLongitude[0] + (gps_data.GPSLongitude[1]/60) + (gps_data.GPSLongitude[2]/3600);
              if (gps_data.hasOwnProperty("GPSLongitudeRef")) {
                if (gps_data.GPSLongitudeRef.toUpperCase() == "W") gps_data.GPSLongitude *= -1;
              }
            }
          }

          let parsed_tags = {
            'tiff': tiff_tags,
            'exif': exif_data,
            'gps':  gps_data
          }

          file_info.parsed = JSON.stringify(parsed_tags,null,2);

          // Extract meta data
          if (tiff_tags.hasOwnProperty("Software")) {
            file_info.metadata.creation_application = tiff_tags['Software'];
          } else {
            if (tiff_tags.hasOwnProperty("Make")) {
              file_info.metadata.creation_application = tiff_tags['Make'];

              if (tiff_tags.hasOwnProperty("Model")) {
                file_info.metadata.creation_application += " " + tiff_tags['Model'];
              }
            } else {
              if (tiff_tags.hasOwnProperty("Model")) {
                file_info.metadata.creation_application = tiff_tags['Model'];
              }
            }
          }

          if (tiff_tags.hasOwnProperty("DateTime")) {
            file_info.metadata.creation_date = tiff_tags['DateTime'];
            file_info.metadata.last_modified_date = tiff_tags['DateTime'];
          }

          if (tiff_tags.hasOwnProperty("ImageDescription")) {
            file_info.metadata.description = tiff_tags['ImageDescription'];
          }

        }
      }

      // Look for Application Segment 2
      if (byte_code[0] == 0xFF && byte_code[1] == 0xE2) {
        let data_size = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(i+2, i+3));
        let data_bytes = file_bytes.slice(i+4, i+(data_size-2));
      }
    }

    return file_info;
  }

  /**
   * Extracts meta data and other information from LNK files.
   *
   * @see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_lnk(file_bytes) {
    var file_info = Static_File_Analyzer.get_default_file_json();

    var drive_types_arr = ['DRIVE_UNKNOWN','DRIVE_NO_ROOT_DIR','DRIVE_REMOVABLE','DRIVE_FIXED','DRIVE_REMOTE','DRIVE_CDROM','DRIVE_RAMDISK'];

    // For GUID defs see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsp/2dbe759c-c955-4770-a545-e46d7f6332ed
    var guids = {
      '20D04FE0-3AEA-1069-A2D8-08002B30309D': {
        'properties': {
          0: "My Computer"
        }
      },
      '28636AA6-953D-11D2-B5D6-00C04FD918D0': {
        'properties': {
          5:  "System.ComputerName",
          8:  "System.ItemPathDisplayNarrow",
          11: "System.ItemType",
          24: "System.ParsingName",
          25: "System.SFGAOFlags",
          30: "System.ParsingPath"
        }
      },
      '446D16B1-8DAD-4870-A748-402EA43D788C': {
        'properties': {
          100: "System.ThumbnailCacheId",
          104: "System.VolumeId"
        }
      },
      '46588AE2-4CBC-4338-BBFC-139326986DCE': {
        'properties': {
          4:  "SID"
        }
      },
      'B725F130-47EF-101A-A5F1-02608C9EEBAC': {
        'properties': {
          2:  "System.ItemFolderNameDisplay",
          4:  "System.ItemTypeText",
          10: "System.ItemNameDisplay",
          11: "System.ItemStoragePathDeprecated",
          12: "System.Size",
          13: "System.FileAttributes",
          14: "System.DateModified",
          15: "System.DateCreated",
          16: "System.DateAccessed",
          19: "System.Search.Contents",
          21: "System.FileFRN",
          22: "System.Search.Scope"
        }
      },
      'DABD30ED-0043-4789-A7F8-D013A4736622': {
        'properties': {
          100: "System.ItemFolderPathDisplayNarrow"
        }
      }

    };

    var hot_key_high_bit = ["","Shift","Control","","Alt"];
    var hot_key_low_bit = ["","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","F1","F2","F3","F4","F5","F6","F7","F8","F9","F10","F11","F12","F13","F14","F15","F16","F17","F18","F19","F20","F21","F22","F23","F24","Num Lock","Scroll Lock"];
    var show_commands = ["","SW_SHOWNORMAL","","SW_SHOWMAXIMIZED","","","","SW_SHOWMINNOACTIVE",""];

    file_info.file_format = "lnk";
    file_info.file_generic_type = "Shortcut";
    file_info.file_encrypted = "false";
    file_info.file_encryption_type = "none";

    var parsed_lnk = {};
    parsed_lnk['HeaderSize'] = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(0,4), Static_File_Analyzer.LITTLE_ENDIAN);
    parsed_lnk['LinkCLSID'] = this.get_guid(file_bytes.slice(4,20));

    var link_flags_arr = [
      Static_File_Analyzer.get_binary_array([file_bytes[20]]).reverse(),
      Static_File_Analyzer.get_binary_array([file_bytes[21]]).reverse(),
      Static_File_Analyzer.get_binary_array([file_bytes[22]]).reverse(),
      Static_File_Analyzer.get_binary_array([file_bytes[23]]).reverse(),
    ];

    var link_flags = [].concat.apply([], link_flags_arr);

    parsed_lnk['LinkFlags'] = {
      'HasLinkTargetIDList': (link_flags[0]==1) ? true : false,
      'HasLinkInfo': (link_flags[1]==1) ? true : false,
      'HasName': (link_flags[2]==1) ? true : false,
      'HasRelativePath': (link_flags[3]==1) ? true : false,
      'HasWorkingDir': (link_flags[4]==1) ? true : false,
      'HasArguments': (link_flags[5]==1) ? true : false,
      'HasIconLocation': (link_flags[6]==1) ? true : false,
      'IsUnicode': (link_flags[7]==1) ? true : false,
      'ForceNoLinkInfo': (link_flags[8]==1) ? true : false,
      'HasExpString': (link_flags[9]==1) ? true : false,
      'RunInSeparateProcess': (link_flags[10]==1) ? true : false,
      'Unused1': (link_flags[11]==1) ? true : false,
      'HasDarwinID': (link_flags[12]==1) ? true : false,
      'RunAsUser': (link_flags[13]==1) ? true : false,
      'HasExpIcon': (link_flags[14]==1) ? true : false,
      'NoPidlAlias': (link_flags[15]==1) ? true : false,
      'Unused2': (link_flags[16]==1) ? true : false,
      'RunWithShimLayer': (link_flags[17]==1) ? true : false,
      'ForceNoLinkTrack': (link_flags[18]==1) ? true : false,
      'EnableTargetMetadata': (link_flags[19]==1) ? true : false,
      'DisableLinkPathTracking': (link_flags[20]==1) ? true : false,
      'DisableKnownFolderTracking': (link_flags[21]==1) ? true : false,
      'DisableKnownFolderAlias': (link_flags[22]==1) ? true : false,
      'AllowLinkToLink': (link_flags[23]==1) ? true : false,
      'UnaliasOnSave': (link_flags[24]==1) ? true : false,
      'PreferEnvironmentPath': (link_flags[25]==1) ? true : false,
      'KeepLocalIDListForUNCTarget': (link_flags[26]==1) ? true : false,
      'Unused3': (link_flags[27]==1) ? true : false,
      'Unused4': (link_flags[28]==1) ? true : false,
      'Unused5': (link_flags[29]==1) ? true : false,
      'Unused6': (link_flags[30]==1) ? true : false,
      'Unused7': (link_flags[31]==1) ? true : false,
    };

    var file_attribute_flags = Static_File_Analyzer.get_binary_array(file_bytes.slice(24,28));
    parsed_lnk['FileAttributes'] = {
      'FILE_ATTRIBUTE_READONLY': (file_attribute_flags[0]==1) ? true : false,
      'FILE_ATTRIBUTE_HIDDEN': (file_attribute_flags[1]==1) ? true : false,
      'FILE_ATTRIBUTE_SYSTEM': (file_attribute_flags[2]==1) ? true : false,
      'Reserved1': (file_attribute_flags[3]==1) ? true : false,
      'FILE_ATTRIBUTE_DIRECTORY': (file_attribute_flags[4]==1) ? true : false,
      'FILE_ATTRIBUTE_ARCHIVE': (file_attribute_flags[5]==1) ? true : false,
      'Reserved2': (file_attribute_flags[6]==1) ? true : false,
      'FILE_ATTRIBUTE_NORMAL': (file_attribute_flags[7]==1) ? true : false,
      'FILE_ATTRIBUTE_TEMPORARY': (file_attribute_flags[8]==1) ? true : false,
      'FILE_ATTRIBUTE_SPARSE_FILE': (file_attribute_flags[9]==1) ? true : false,
      'FILE_ATTRIBUTE_REPARSE_POINT': (file_attribute_flags[10]==1) ? true : false,
      'FILE_ATTRIBUTE_COMPRESSED': (file_attribute_flags[11]==1) ? true : false,
      'FILE_ATTRIBUTE_OFFLINE': (file_attribute_flags[12]==1) ? true : false,
      'FILE_ATTRIBUTE_NOT_CONTENT_INDEXED': (file_attribute_flags[13]==1) ? true : false,
      'FILE_ATTRIBUTE_ENCRYPTED': (file_attribute_flags[14]==1) ? true : false,
    };

    parsed_lnk['CreationTime']  = this.get_eight_byte_date(file_bytes.slice(28,36), Static_File_Analyzer.LITTLE_ENDIAN);
    parsed_lnk['AccessTime'] = this.get_eight_byte_date(file_bytes.slice(36,44), Static_File_Analyzer.LITTLE_ENDIAN);
    parsed_lnk['WriteTime'] = this.get_eight_byte_date(file_bytes.slice(44,52), Static_File_Analyzer.LITTLE_ENDIAN);

    if (parsed_lnk['CreationTime'] != "1601-01-01T00:00:00.000Z") {
      file_info.metadata.creation_date = parsed_lnk['CreationTime'];
    }

    if (parsed_lnk['AccessTime'] != "1601-01-01T00:00:00.000Z") {
      file_info.metadata.last_modified_date = parsed_lnk['AccessTime'];
    }

    parsed_lnk['FileSize'] = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(52,56), Static_File_Analyzer.LITTLE_ENDIAN);
    parsed_lnk['IconIndex'] = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(56,60), Static_File_Analyzer.LITTLE_ENDIAN);
    parsed_lnk['ShowCommand'] = show_commands[Static_File_Analyzer.get_four_byte_int(file_bytes.slice(60,64), Static_File_Analyzer.LITTLE_ENDIAN)];

    if (hot_key_high_bit[file_bytes[65]] != "" && hot_key_low_bit[file_bytes[64]] != "") {
      parsed_lnk['HotKey'] = hot_key_high_bit[file_bytes[65]] + " + " + hot_key_low_bit[file_bytes[64]];
    } else {
      parsed_lnk['HotKey'] = "";
    }

    // Skip the 10 reserved bytes
    var byte_offset = 76;

    if (parsed_lnk['LinkFlags']['HasLinkTargetIDList'] == true) {
      // HasLinkTargetIDList
      parsed_lnk['TargetIDList'] = [];
      var id_list_size = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN);
      var id_list_bytes = file_bytes.slice(byte_offset,byte_offset+=id_list_size);

      var id_list_offset = 0;
      var item_id_bytes = [];
      var item_id_size;
      var item_id_code;

      while (id_list_offset < id_list_bytes.length) {
        item_id_size = Static_File_Analyzer.get_two_byte_int(id_list_bytes.slice(id_list_offset,id_list_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN) - 2;
        item_id_bytes = id_list_bytes.slice(id_list_offset,id_list_offset+=item_id_size);
        item_id_code = Static_File_Analyzer.get_two_byte_int(item_id_bytes.slice(0,2), Static_File_Analyzer.LITTLE_ENDIAN);

        if (item_id_code == 17199) {
          // Drive
          var drive = Static_File_Analyzer.get_ascii(item_id_bytes.slice(1,6).filter(i => i > 31));

          parsed_lnk['TargetIDList'].push({
            'type': "Drive",
            'value': drive
          });
        } else if (item_id_code == 20511) {
          // Class ID ?
          var item_id_guid = this.get_guid(item_id_bytes.slice(2,18));
          var item_id_guid_name = guids[item_id_guid].properties[0];

          parsed_lnk['TargetIDList'].push({
            'type': "CLSID",
            'value': item_id_guid + " = " + item_id_guid_name
          });
        } else {
          break;
        }
      }
    }

    if (parsed_lnk['LinkFlags']['HasLinkInfo'] == true) {
      // LinkInfo
      var link_info_start = byte_offset;
      var link_info_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);

      if (link_info_size < file_bytes.length) {
        var link_info_header_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
        var link_info_end = link_info_start + link_info_size;

        var link_info_flags = this.get_bin_from_int(file_bytes[byte_offset]).reverse();
        byte_offset+=4;

        var link_info_flags_obj = {
          'VolumeIDAndLocalBasePath': (link_info_flags[0]==1) ? true : false,
          'CommonNetworkRelativeLinkAndPathSuffix': (link_info_flags[1]==1) ? true : false
        };

        var volume_id_offset = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
        var local_base_path_offset = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);

        if (link_info_flags_obj.VolumeIDAndLocalBasePath) {
          // LocalBasePath
          var local_base_path_start = (link_info_start+local_base_path_offset);
          var local_base_path_bytes = this.get_null_terminated_bytes(file_bytes.slice(local_base_path_start), true);
          parsed_lnk['LocalBasePath'] = Static_File_Analyzer.get_ascii(local_base_path_bytes.filter(i => i > 31));
        }

        var common_network_relative_link_offset = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);

        var common_path_suffix_offset = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
        var common_path_suffix_start = (link_info_start+common_path_suffix_offset);

        if (link_info_header_size >= 0x24) {
          var local_base_path_offset_unicode = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
          var local_base_path_start_unicode = (link_info_start+local_base_path_offset_unicode);
          var local_base_path_unicode_bytes = this.get_null_terminated_bytes(file_bytes.slice(local_base_path_start_unicode), true);
          parsed_lnk['LocalBasePathUnicode'] = Static_File_Analyzer.get_string_from_array(local_base_path_unicode_bytes);

          var common_path_suffix_offset_unicode = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
          var common_path_suffix_start_unicode = (link_info_start+common_path_suffix_offset_unicode);

          var common_path_suffix_unicode_bytes = this.get_null_terminated_bytes(file_bytes.slice(common_path_suffix_start), true);
          parsed_lnk['CommonPathSuffixUnicode'] = Static_File_Analyzer.get_string_from_array(common_path_suffix_unicode_bytes);
        }

        var common_path_suffix_bytes = this.get_null_terminated_bytes(file_bytes.slice(common_path_suffix_start), false);
        parsed_lnk['CommonPathSuffix'] = Static_File_Analyzer.get_ascii(common_path_suffix_bytes.filter(i => i > 31));

        if (link_info_flags_obj.VolumeIDAndLocalBasePath) {
          // VolumeID
          var volume_obj_start = byte_offset;

          parsed_lnk['VolumeID'] = {
            'VolumeIDSize': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'DriveType': drive_types_arr[Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN)],
            'DriveSerialNumber': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'VolumeLabelOffset': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN)
          };

          var drive_volume_lbl_start = volume_obj_start + parsed_lnk['VolumeID']['VolumeLabelOffset'];

          if (parsed_lnk['VolumeID']['VolumeLabelOffset'] == 0x14) {
            // NULL-terminated string of Unicode characters
            var drive_volume_lbl_offset_unicode = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
            drive_volume_lbl_start = volume_obj_start + drive_volume_lbl_offset_unicode;
          }

          var drive_data_byte = this.get_null_terminated_bytes(file_bytes.slice(drive_volume_lbl_start));
          parsed_lnk['VolumeID']['VolumeLabel'] = Static_File_Analyzer.get_ascii(drive_data_byte.filter(i => i > 31));
        }

        if (link_info_flags_obj.CommonNetworkRelativeLinkAndPathSuffix) {
          // CommonNetworkRelativeLink
          var cnrl_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
          var cnrl_flags = Static_File_Analyzer.get_binary_array(file_bytes.slice(byte_offset,byte_offset+=4));
          var net_name_offset = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
          var device_name_offset = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
          var network_provider_type = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);

          if (net_name_offset > 0x14) {
            var net_name_offset_unicode = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
          }

          if (parsed_lnk['VolumeID']['VolumeLabelOffset'] > 0x14) {
            var device_name_offset_unicode = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
          }
        }

        byte_offset = link_info_end;
      } else {
        console.log("Error parsing LNK file: Invalid LinkInfoSize.");
        byte_offset -= 4;
      }

    }

    // StringData
    parsed_lnk['StringData'] = {};

    if (parsed_lnk['LinkFlags'].HasName) {
      var char_count = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN);
      char_count = (parsed_lnk['LinkFlags'].IsUnicode) ? char_count*2 : char_count;
      parsed_lnk['StringData']['NAME_STRING'] = Static_File_Analyzer.get_string_from_array(file_bytes.slice(byte_offset,byte_offset+=char_count).filter(i => i !== 0));
    }

    if (parsed_lnk['LinkFlags'].HasRelativePath) {
      var char_count = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN);
      char_count = (parsed_lnk['LinkFlags'].IsUnicode) ? char_count*2 : char_count;
      parsed_lnk['StringData']['RELATIVE_PATH'] = Static_File_Analyzer.get_string_from_array(file_bytes.slice(byte_offset,byte_offset+=char_count).filter(i => i !== 0));
    }

    if (parsed_lnk['LinkFlags'].HasWorkingDir) {
      var char_count = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN);
      char_count = (parsed_lnk['LinkFlags'].IsUnicode) ? char_count*2 : char_count;
      parsed_lnk['StringData']['WORKING_DIR'] = Static_File_Analyzer.get_string_from_array(file_bytes.slice(byte_offset,byte_offset+=char_count).filter(i => i !== 0));
    }

    if (parsed_lnk['LinkFlags'].HasArguments) {
      var char_count = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN);
      char_count = (parsed_lnk['LinkFlags'].IsUnicode) ? char_count*2 : char_count;
      parsed_lnk['StringData']['COMMAND_LINE_ARGUMENTS'] = Static_File_Analyzer.get_string_from_array(file_bytes.slice(byte_offset,byte_offset+=char_count).filter(i => i !== 0));
    }

    if (parsed_lnk['LinkFlags'].HasIconLocation) {
      var char_count = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN);
      char_count = (parsed_lnk['LinkFlags'].IsUnicode) ? char_count*2 : char_count;
      parsed_lnk['StringData']['ICON_LOCATION'] = Static_File_Analyzer.get_string_from_array(file_bytes.slice(byte_offset,byte_offset+=char_count).filter(i => i !== 0));
    }

    // ExtraData
    parsed_lnk['ExtraData'] = [];
    var block_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);

    while (block_size >= 4) {
      var block_sig = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
      var block_end = byte_offset + block_size;

      if (block_sig == 0xA0000001) {
        // EnvironmentVariableDataBlock
        var target_ansi_bytes = file_bytes.slice(byte_offset,byte_offset+=260);
        var env_variable_ansi = Static_File_Analyzer.get_string_from_array(target_ansi_bytes.filter(i => i !== 0));
        var env_variable_unicode = "";

        if (byte_offset < block_end) {
          var target_unicode_bytes = file_bytes.slice(byte_offset,byte_offset+=520);
          env_variable_unicode = Static_File_Analyzer.get_string_from_array(target_unicode_bytes.filter(i => i !== 0));
        }

        parsed_lnk['ExtraData'].push({
          'type': "EnvironmentVariableDataBlock",
          'data': {
            'TargetAnsi': env_variable_ansi,
            'TargetUnicode': env_variable_unicode
          }
        });
      } else if (block_sig == 0xA0000002) {
        // ConsoleDataBlock
        parsed_lnk['ExtraData'].push({
          'type': "distributed_link_tracker_properties",
          'data': {
            'fill_attributes': Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN),
            'popup_fill_attributes': Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN),
            'screen_buffer_size_x': Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN),
            'screen_buffer_size_y': Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN),
            'window_size_x': Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN),
            'window_size_y': Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN),
            'window_origin_x': Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN),
            'window_origin_y': Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN),
            'unused1': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'unused2': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'font_size': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'font_family': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'font_weight': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'font_name_bytes': file_bytes.slice(byte_offset,byte_offset+=64),
            'cursor_size': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'full_screen': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'quick_edit': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'insert_mode': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'auto_position': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'history_buff_size': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'number_of_history_buffers': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'history_no_dup': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN),
            'color_table': file_bytes.slice(byte_offset,byte_offset+=64)
          }
        });
      } else if (block_sig == 0xA0000003) {
        // TrackerDataBlock
        var tracker_length = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
        var tracker_version = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
        var distributed_link_tracker_properties = {};

        distributed_link_tracker_properties['MachineID'] = Static_File_Analyzer.get_string_from_array(file_bytes.slice(byte_offset,byte_offset+=16).filter(i => i !== 0));

        var droid_bytes = file_bytes.slice(byte_offset,byte_offset+=32);
        distributed_link_tracker_properties['Droid'] = {};
        distributed_link_tracker_properties['Droid']['VolumeIdentifier'] = this.get_guid(droid_bytes.slice(0,16));
        distributed_link_tracker_properties['Droid']['FileIdentifier'] = this.get_guid(droid_bytes.slice(16,32));

        var droid_birth_bytes = file_bytes.slice(byte_offset,byte_offset+=32);
        distributed_link_tracker_properties['DroidBirth'] = {};
        distributed_link_tracker_properties['DroidBirth']['VolumeIdentifier'] = this.get_guid(droid_birth_bytes.slice(0,16));
        distributed_link_tracker_properties['DroidBirth']['FileIdentifier'] = this.get_guid(droid_birth_bytes.slice(16,32));

        var mac_address_bytes = droid_birth_bytes.slice(26,32);
        var mac_address_str = "";
        for (var mi=0; mi<mac_address_bytes.length; mi++) {
          mac_address_str += Static_File_Analyzer.get_hex_string_from_byte_array([mac_address_bytes[mi]]);

          if (mac_address_str.length == 2 || mac_address_str.length == 5 || mac_address_str.length == 8 || mac_address_str.length == 11 || mac_address_str.length == 14) {
            mac_address_str += ":";
          }
        }

        distributed_link_tracker_properties['MAC_Address'] = mac_address_str;
        parsed_lnk['ExtraData'].push({'type': "DistributedLinkTrackerProperties", 'data': distributed_link_tracker_properties});
      } else if (block_sig == 0xA0000004) {
        // ConsoleFEDataBlock
        var code_page = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
      } else if (block_sig == 0xA0000005) {
        // SpecialFolderDataBlock
        var special_folder_id = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
        var special_folder_offset = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
        // TODO get special folder info.
      } else if (block_sig == 0xA0000006) {
        // DarwinDataBlock
        var target_ansi_bytes = file_bytes.slice(byte_offset,byte_offset+=260);
        var darwin_ansi = Static_File_Analyzer.get_string_from_array(target_ansi_bytes.filter(i => i !== 0));

        if (byte_offset < block_end) {
          var target_unicode_bytes = file_bytes.slice(byte_offset,byte_offset+=520);
          var darwin_unicode = Static_File_Analyzer.get_string_from_array(target_unicode_bytes.filter(i => i !== 0));
        }
      } else if (block_sig == 0xA0000007) {
        // IconEnvironmentDataBlock
        var target_ansi_bytes = file_bytes.slice(byte_offset,byte_offset+=260);
        var icon_path_ansi = Static_File_Analyzer.get_string_from_array(target_ansi_bytes.filter(i => i !== 0));

        if (byte_offset < block_end) {
          var target_unicode_bytes = file_bytes.slice(byte_offset,byte_offset+=520);
          var icon_path_unicode = Static_File_Analyzer.get_string_from_array(target_unicode_bytes.filter(i => i !== 0));
        }
      } else if (block_sig == 0xA0000008) {
        // ShimDataBlock
        break;
      } else if (block_sig == 0xA0000009) {
        // PropertyStoreDataBlock
        var data_block_properties = [];
        var id_name = "Unknown";
        var storage_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);

        while (storage_size > 0) {
          var version = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
          var format_id = file_bytes.slice(byte_offset,byte_offset+=16);
          var guid = this.get_guid(format_id.slice(0,16));

          if (guid == "D5CDD505-2E9C-101B-9397-08002B2CF9AE" || guid == "05D5CDD5-9C2E-1B10-9397-08002B2CF9AE") {
            // String
            var value_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);

            while (value_size != 0 && !isNaN(value_size)) {
              var name_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
              byte_offset++ // skip reserved byte

              var name_bytes = file_bytes.slice(byte_offset,byte_offset+=name_size);
              var name_str = Static_File_Analyzer.get_string_from_array(name_bytes);

              var value_bytes = file_bytes.slice(byte_offset,byte_offset+=(value_size-name_bytes));
              value_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
            }
          } else {
            // Serialized Property Value
            var struct_start = byte_offset;
            var value_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
            var struct_end = struct_start + value_size;

            while (value_size != 0 && !isNaN(value_size)) {
              var value = "";
              var value_type = "";
              var value_id = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
              byte_offset++ // skip reserved byte

              var type = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN);
              var padding = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(byte_offset,byte_offset+=2), Static_File_Analyzer.LITTLE_ENDIAN);

              // See: https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-OLEPS/%5bMS-OLEPS%5d.pdf - 2.15 TypedPropertyValue
              if (type == 0x0000) {
                // VT_EMPTY
                value_type = "VT_EMPTY";
                value = "";
              } else if (type == 0x0001) {
                // VT_NULL
                value_type = "VT_NULL";
                value = null;
              } else if (type == 0x0002) {
                // VT_I2 - 16-bit signed integer, followed by zero padding to 4 bytes
                value_type = "VT_I2";
              } else if (type == 0x0003) {
                // VT_I4 - 32-bit signed integer
                value_type = "VT_I4";
              } else if (type == 0x0004) {
                // VT_R4 - 4-byte (single-precision) IEEE floating-point number
                value_type = "VT_R4";
              } else if (type == 0x0005) {
                // VT_R8 - 8-byte (double-precision) IEEE floating-point number
                value_type = "VT_R8";
              } else if (type == 0x0006) {
                // VT_CY - CURRENCY
                value_type = "VT_CY";
              } else if (type == 0x0007) {
                // VT_DATE
                value_type = "VT_DATE";
              } else if (type == 0x0008) {
                // VT_BSTR - CodePageString
                value_type = "VT_BSTR";
              } else if (type == 0x0015) {
                // VT_UI8 - 8-byte unsigned integer
                value_type = "VT_UI8";
                value = this.get_eight_byte_int(file_bytes.slice(byte_offset,byte_offset+=8), Static_File_Analyzer.LITTLE_ENDIAN);
              } else if (type == 0x0016) {
                // VT_INT - 4-byte signed integer
                value_type = "VT_INT";
              } else if (type == 0x0017) {
                // VT_UINT - 4-byte unsigned integer
                value_type = "VT_UINT";
              } else if (type == 0x001F) {
                // VT_LPWSTR - UnicodeString
                value_type = "VT_LPWSTR";
                var char_length = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN) - 1;
                var value_bytes = file_bytes.slice(byte_offset,byte_offset+=(char_length*2));

                var two_bit = [6,15];
                var four_bit = [0,2,4,7,9,11]

                var pad_bytes = 4;
                if (two_bit.includes(byte_offset % 16)) pad_bytes = 2;

                // Per the spec, the string must followed by zero padding to a multiple of 4 bytes.
                byte_offset += pad_bytes;
                value = Static_File_Analyzer.get_string_from_array(value_bytes.filter(i => i > 31));
              } else if (type == 0x0040) {
                // VT_FILETIME
                value_type = "VT_FILETIME";
                value = this.get_eight_byte_date(file_bytes.slice(byte_offset,byte_offset+=8), Static_File_Analyzer.LITTLE_ENDIAN);
              } else if (type == 0x0048) {
                // VT_CLSID - MUST be a GUID
                value_type = "VT_CLSID";
                value = this.get_guid(file_bytes.slice(byte_offset,byte_offset+=16));
              }

              if (guids.hasOwnProperty(guid) && guids[guid].properties.hasOwnProperty(value_id)) {
                id_name = guids[guid].properties[value_id];
              } else {
                id_name = "Unknown";
              }

              data_block_properties.push({
                'guid': guid,
                'id': id_name,
                'id_value': value_id,
                'value_type': value_type,
                'value': value
              });

              // Check for useful metadata
              if (id_name == "System.ItemFolderPathDisplayNarrow") {
                var value_parts = value.split("(");

                if (value_parts == 1) {
                  file_info.metadata.last_saved_location = value_parts[0];
                } else {
                  file_info.metadata.last_saved_location = value_parts[1].slice(0, -1) + "\\" + value_parts[0];
                }
              } else if (id_name == "System.ItemTypeText") {
                file_info.metadata.creation_application = value;
              }

              value_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);

              if (value_size > (file_bytes.length - byte_offset)) {
                // Byte index is off, or this file is malformed.
                // Try backing up two bytes and re-reading.
                byte_offset -= 5;
                value_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
              }
            }
          }


          storage_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);

          if (storage_size > (file_bytes.length - byte_offset)) {
            // Byte index is off, or this file is malformed.
            // Try backing up two bytes and re-reading.
            byte_offset -= 2;
            storage_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
          }
        }

        parsed_lnk['ExtraData'].push({
          'type': "PropertyStoreDataBlock",
          'data': data_block_properties
        });
      } else if (block_sig == 0xA000000B) {
        // KnownFolderDataBlock
        var known_folder_id_bytes = file_bytes.slice(byte_offset,byte_offset+=16);
        var known_folder_offset = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
      } else if (block_sig == 0xA000000C) {
        // VistaAndAboveIDListDataBlock
        break;
      } else {
        break;
      }

      block_size = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(byte_offset,byte_offset+=4), Static_File_Analyzer.LITTLE_ENDIAN);
    }

    // Build LNK shell code
    var cmd_shell = "";
    if (parsed_lnk['LocalBasePathUnicode'] !== null && parsed_lnk['LocalBasePathUnicode'] !== undefined) {
      cmd_shell = parsed_lnk['LocalBasePathUnicode'];
    } else if (parsed_lnk['LocalBasePath'] !== null && parsed_lnk['LocalBasePath'] !== undefined) {
      cmd_shell = parsed_lnk['LocalBasePath'];
    } else if (parsed_lnk['StringData']['RELATIVE_PATH'] !== null && parsed_lnk['StringData']['RELATIVE_PATH'] !== undefined) {
      cmd_shell = parsed_lnk['StringData']['RELATIVE_PATH'];
    } else {
      for (var ed=0; ed<parsed_lnk['ExtraData'].length; ed++) {
        if (parsed_lnk['ExtraData'][ed].type == "EnvironmentVariableDataBlock") {
          if (parsed_lnk['ExtraData'][ed].data.TargetUnicode !== null && parsed_lnk['ExtraData'][ed].data.TargetUnicode !== undefined) {
            cmd_shell = parsed_lnk['ExtraData'][ed].data.TargetUnicode;
          } else {
            cmd_shell = parsed_lnk['ExtraData'][ed].data.TargetAnsi;
          }
        }
      }
    }

    if (parsed_lnk['ExtraData']['COMMAND_LINE_ARGUMENTS'] !== null && parsed_lnk['StringData']['COMMAND_LINE_ARGUMENTS'] !== undefined) {
      cmd_shell += " " + parsed_lnk['StringData']['COMMAND_LINE_ARGUMENTS'];
    }

    this.add_extracted_script("Windows Command Shell", cmd_shell, file_info);
    cmd_shell = cmd_shell.replaceAll(/(?:[^\s]\&\&[^\s]|[^\s]\&\&|\&\&[^\s])/gm, function(match, match_index, input_string) {
      var str_part1 = input_string.slice(match_index, match_index+1);
      var str_part2 = input_string.slice(match_index+3, match_index+4);
      return str_part1 + " && " + str_part2;
    });

    file_info = Static_File_Analyzer.search_for_iocs(cmd_shell, file_info);

    // Extract more meta data from what we have already collected.
    if (/[a-zA-Z]\:\\/gm.test(file_info.metadata.last_saved_location)) {
      file_info.metadata.creation_os = "Windows";
    }

    file_info.parsed = JSON.stringify(parsed_lnk, null, 2);

    return file_info;
  }

  /**
   * Extracts meta data and other information from Mail Message Binary File Format (.msg) files.
   *
   * @param  {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param  {object}      file_info    An object representing the extracted information from the parent Compound File Binary object.
   * @param  {object}      cfb_obj      A parsed Compound File Binary object
   * @return {Object}      file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_msg(file_bytes, file_info, cfb_obj) {
    file_info.file_format = "msg";
    file_info.file_generic_type = "Mail Message";

    let msg_properties = MSG_Tools.parse_msg_properties(cfb_obj);

    let sender_display_name = "";
    let sender_email = "";

    if (msg_properties.properties.hasOwnProperty("PidTagSenderEmailAddress")) {
      let data_type = msg_properties.properties['PidTagSenderEmailAddress'].data_type;
      if (data_type == "unicode" || data_type == "str") {
        if (sender_email == "") {
          sender_email = msg_properties.properties['PidTagSenderEmailAddress'].val;
        }
      }
    }

    if (msg_properties.properties.hasOwnProperty("PidTagSenderName")) {
      let data_type = msg_properties.properties['PidTagSenderName'].data_type;
      if (data_type == "unicode" || data_type == "str") {
        if (sender_display_name == "") {
          sender_display_name = msg_properties.properties['PidTagSenderName'].val;
        }
      }
    }

    if (msg_properties.properties.hasOwnProperty("PidTagSentRepresentingName")) {
      let data_type = msg_properties.properties['PidTagSentRepresentingName'].data_type;
      if (data_type == "unicode" || data_type == "str") {
        if (sender_display_name == "") {
          sender_display_name = msg_properties.properties['PidTagSentRepresentingName'].val;
        }
      }
    }

    if (msg_properties.properties.hasOwnProperty("PidTagSenderSmtpAddress")) {
      let data_type = msg_properties.properties['PidTagSenderSmtpAddress'].data_type;
      if (data_type == "unicode" || data_type == "str") {
        if (sender_email == "") {
          sender_email = msg_properties.properties['PidTagSenderSmtpAddress'].val;
        }
      }
    }

    if (msg_properties.properties.hasOwnProperty("PidTagSubject")) {
      file_info.metadata.title = msg_properties.properties['PidTagSubject'].val;
    }

    // Check for CVE-2023-23397
    if (msg_properties.properties.hasOwnProperty("PidLidReminderFileParameter")) {
      let file_reminder_str = msg_properties.properties['PidLidReminderFileParameter'].val;
      file_info = Static_File_Analyzer.search_for_iocs(file_reminder_str, file_info);

      var cve_regex = /\\.+[\.:].+/gm;
      var cve_match = cve_regex.exec(file_reminder_str);

      while (cve_match !== null) {
        file_info.analytic_findings.push("MALICIOUS - CVE-2023-23397 Exploit Found");
        break;
      }
    }

    sender_display_name = (sender_display_name.length > 0) ? sender_display_name + " " : "";
    file_info.metadata.author = sender_display_name + "<" + sender_email + ">";
    file_info.parsed = JSON.stringify(msg_properties.properties, null, 2);

    // Clear out file components from CFB parser and replace with MSG specific file components.
    file_info.file_components = [];

    // Init text encoder
    let utf8_encode = new TextEncoder();

    if (msg_properties.properties.hasOwnProperty("PidTagTransportMessageHeaders")) {
      file_info.file_components.push({
        'name': "Headers.txt",
        'type': "txt",
        'directory': false,
        'file_bytes': utf8_encode.encode(msg_properties.properties['PidTagTransportMessageHeaders'].val)
      });
    }

    if (msg_properties.properties.hasOwnProperty("PidTagBody")) {
      file_info.file_components.push({
        'name': "Message_Body.txt",
        'type': "txt",
        'directory': false,
        'file_bytes': utf8_encode.encode(msg_properties.properties['PidTagBody'].val)
      });

      // Check message body for IoCs
      file_info = Static_File_Analyzer.search_for_iocs(msg_properties.properties['PidTagBody'].val, file_info);
    }

    file_info.file_components = file_info.file_components.concat(msg_properties.message_attachments);

    return file_info;
  }

  /**
   * Extracts meta data and other information from One Note files.
   *
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_one(file_bytes) {
    var file_info = Static_File_Analyzer.get_default_file_json();

    file_info.file_format = "one";
    file_info.file_generic_type = "Document";

    // Read header
    let header_dict = {};

    header_dict['guidFileType'] = this.get_guid(file_bytes.slice(0,16));
    header_dict['guidFile'] = this.get_guid(file_bytes.slice(16,32));
    header_dict['guidLegacyFileVersion'] = this.get_guid(file_bytes.slice(32,48));
    header_dict['guidFileFormat'] = this.get_guid(file_bytes.slice(48,64));
    header_dict['ffvLastCodeThatWroteToThisFile'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(64,68), "LITTLE_ENDIAN");
    header_dict['ffvOldestCodeThatHasWrittenToThisFile'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(68,72), "LITTLE_ENDIAN");
    header_dict['ffvNewestCodeThatHasWrittenToThisFile'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(72,76), "LITTLE_ENDIAN");
    header_dict['ffvOldestCodeThatMayReadThisFile'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(76,80), "LITTLE_ENDIAN");

    header_dict['fcrLegacyFreeChunkList'] = {
      'offset': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(80,84), "LITTLE_ENDIAN"),
      'length': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(84,88), "LITTLE_ENDIAN")
    };

    header_dict['fcrLegacyTransactionLog'] = {
      'offset': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(88,92), "LITTLE_ENDIAN"),
      'length': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(92,96), "LITTLE_ENDIAN")
    };

    header_dict['cTransactionsInLog'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(96,100), "LITTLE_ENDIAN");
    header_dict['cbLegacyExpectedFileLength'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(100,104), "LITTLE_ENDIAN");
    header_dict['rgbPlaceholder'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(104,112), "LITTLE_ENDIAN");

    header_dict['fcrLegacyFileNodeListRoot'] = {
      'offset': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(112,116), "LITTLE_ENDIAN"),
      'length': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(116,120), "LITTLE_ENDIAN")
    };

    header_dict['cbLegacyFreeSpaceInFreeChunkList'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(120,124), "LITTLE_ENDIAN");
    header_dict['fNeedsDefrag'] = (file_bytes[124] == 1) ? true : false;
    header_dict['fRepairedFile'] = (file_bytes[125] == 1) ? true : false;
    header_dict['fNeedsGarbageCollect'] = (file_bytes[126] == 1) ? true : false;
    header_dict['fHasNoEmbeddedFileObjects'] = (file_bytes[127] == 1) ? true : false;
    header_dict['guidAncestor'] = this.get_guid(file_bytes.slice(128,144));
    header_dict['crcName'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(144,148), "LITTLE_ENDIAN");

    header_dict['fcrHashedChunkList'] = {
      'offset': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(148,156), "LITTLE_ENDIAN"),
      'length': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(156,160), "LITTLE_ENDIAN")
    };

    header_dict['fcrTransactionLog'] = {
      'offset': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(160,168), "LITTLE_ENDIAN"),
      'length': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(168,172), "LITTLE_ENDIAN")
    };

    header_dict['fcrFileNodeListRoot'] = {
      'offset': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(172,180), "LITTLE_ENDIAN"),
      'length': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(180,184), "LITTLE_ENDIAN")
    };

    header_dict['fcrFreeChunkList'] = {
      'offset': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(184,192), "LITTLE_ENDIAN"),
      'length': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(192,196), "LITTLE_ENDIAN")
    };

    header_dict['cbExpectedFileLength'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(196,204), "LITTLE_ENDIAN");
    header_dict['cbFreeSpaceInFreeChunkList'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(204,212), "LITTLE_ENDIAN");
    header_dict['guidFileVersion'] = this.get_guid(file_bytes.slice(212,228));
    header_dict['nFileVersionGeneration'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(228,236), "LITTLE_ENDIAN");
    header_dict['guidDenyReadFileVersion'] = this.get_guid(file_bytes.slice(236,252));
    header_dict['grfDebugLogFlags'] = file_bytes.slice(252,256);

    header_dict['fcrDebugLog'] = {
      'offset': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(256,264), "LITTLE_ENDIAN"),
      'length': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(264,268), "LITTLE_ENDIAN")
    };

    header_dict['fcrAllocVerificationFreeChunkList'] = {
      'offset': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(268,276), "LITTLE_ENDIAN"),
      'length': Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(276,280), "LITTLE_ENDIAN")
    };

    header_dict['bnCreated'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(280,284), "LITTLE_ENDIAN");
    header_dict['bnLastWroteToThisFile'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(284,288), "LITTLE_ENDIAN");
    header_dict['bnOldestWritten'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(288,292), "LITTLE_ENDIAN");
    header_dict['bnNewestWritten'] = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(292,296), "LITTLE_ENDIAN");
    header_dict['rgbReserved'] = file_bytes.slice(296,1024);

    if (header_dict['cbExpectedFileLength'] != file_bytes.length) {
      file_info.analytic_findings.push("SUSPICIOUS - Expected File Length Does Not Match Actual File Length");
    }

    // Root File Node List
    let rfnl_dict = {};
    let rfnl_bytes = file_bytes.slice(header_dict['fcrFileNodeListRoot'].offset, header_dict['fcrFileNodeListRoot'].offset + header_dict['fcrFileNodeListRoot'].length);

    // Transaction Log

    // Hashed Chunk List
    let hcl_bytes = file_bytes.slice(header_dict['fcrHashedChunkList'].offset, header_dict['fcrHashedChunkList'].offset + header_dict['fcrHashedChunkList'].length);
    //let hcl_dict = MS_Document_Parser.parse_file_node_list(hcl_bytes);

    // Look for embedded files
    let files = MS_Document_Parser.extract_embedded_file_from_one_note(file_bytes);
    file_info.file_components = files;

    // Set parsed file info
    file_info.parsed = JSON.stringify({
      'Header': header_dict,
      //'RootFileNodeList': rfnl_dict,
      //'HashedChunkList': hcl_dict
    }, null, 2);

    return file_info;
  }

  /**
   * Extracts meta data and other information from PDF files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  async analyze_pdf(file_bytes, file_text) {
    var file_info = Static_File_Analyzer.get_default_file_json();

    file_info.file_format = "pdf";
    file_info.file_generic_type = "Document";

    var pdf_version_str = Static_File_Analyzer.get_ascii(file_bytes.slice(5,16));
    file_info.file_format_ver = (pdf_version_str.indexOf("%") > 0) ? pdf_version_str.split("%")[0].trim() : pdf_version_str.split("\n")[0].trim();

    // If the file text is not given, generate it from the bytes
    if (file_text.length == 0) {
      file_text = Static_File_Analyzer.get_ascii(file_bytes);
    }

    // Get an array of the embedded objects
    let embedded_objs = await PDF_Parser.get_objects(file_info, file_bytes, file_text);

    // Get any embedded files and components
    file_info.file_components = await PDF_Parser.get_file_components(embedded_objs);

    // Push streams to file_components
    file_info.file_components.concat(file_info.file_components);

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
            file_info = Static_File_Analyzer.add_ttp("T1203", "Execution", "Exploits CVE-2019-7089 in Adobe Acrobat and Reader.", file_info);
            file_info.iocs.push(href_unc_match[1]);
          }
        }
      } else if (objects_matches[2] == ">>") {
        // Nested OBJ
        // Check for CVE-2018-4993 Ref: https://github.com/deepzec/Bad-Pdf/blob/master/badpdf.py
        var cve_match = /\/AA\s*\<\<\s*\/O\s*\<\<\s*\/F\s*\(\s*((?:\\{2,4}|https?\:\/\/)(?:[a-zA-Z0-9]+[\.\:]?)+\\*\s*)\s*\)\s*\/D\s*[^\n\r]+\s+\/S\s*\/GoToE/gmi.exec(objects_matches[1]);
        if (cve_match !== null) {
          file_info.analytic_findings.push("MALICIOUS - CVE-2018-4993 Exploit Found");
          file_info = Static_File_Analyzer.add_ttp("T1203", "Execution", "Exploits CVE-2018-4993 in Adobe Acrobat and Reader.", file_info);
          file_info.iocs.push(cve_match[1]);
        }
      }

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

      this.add_extracted_script("JavaScript", script_text, file_info);

      if (script_matches[1].toLowerCase() == "js" || script_matches[1].toLowerCase() == "javascript") {
        file_info.scripts.script_type = "JavaScript";
      }

      script_matches = script_regex.exec(file_text);
    }

    // Look for various items in objects
    for (let eoi=0; eoi<embedded_objs.length; eoi++) {
      if (embedded_objs[eoi].object_dictionary.hasOwnProperty("OpenAction")) {
        let open_action_val = embedded_objs[eoi].object_dictionary['OpenAction'];

        if (/^\d+\s+\d+\s+\w+/.test(open_action_val)) {
          let object_id = open_action_val.split(" ")[0] - 1;
          let action_obj = embedded_objs[object_id];

          if (action_obj.object_dictionary['Type'].toLowerCase() == "action") {
            if (action_obj.object_dictionary.hasOwnProperty("F")) {
              let finding_txt = "SUSPICIOUS - File launch on open: " + action_obj.object_dictionary['F'];
              finding_txt = (finding_txt.endsWith(")")) ? finding_txt.slice(0,-1) : finding_txt;
              file_info.analytic_findings.push(finding_txt);

              if (action_obj.object_dictionary['F'].startsWith("/")) {
                finding_txt = "SUSPICIOUS - Possible Local NTLM Information Leakage. More info: https://github.com/alecdhuse/Lantern-Shark/wiki/PDF-Exploit-Documentation#local-ntlm-information-leakage";
                file_info.analytic_findings.push(finding_txt);
              }
            }
          }

        } else {

        }
      }

    }


    // Look for URIs
    var uri_regex = /\/URI\s*\((\s*[\"\']{0,1}(?:http|https)\:\/\/[A-Za-z0-9\$\-\_\.\+\!\*\)\/\&\?\%]+[\"\']{0,1}\s*)\)/gmi;
    var uri_matches = uri_regex.exec(file_text);

    while (uri_matches != null) {
      file_info.iocs.push(uri_matches[1]);
      uri_matches = uri_regex.exec(file_text);
    }

    if (metadata_obj_found == false) {
      // Backup method to extract meta data, this need refining.

      // RDF Metadata
      file_info.metadata.creation_application = this.get_xml_tag_content(file_text, "xmp:CreatorTool", 0);
      if (file_info.metadata.creation_application == "unknown") {
        file_info.metadata.creation_application = this.get_xml_tag_content(file_text, "pdf:Producer", 0);
      }

      file_info.metadata.creation_date = this.get_xml_tag_content(file_text, "xmp:CreateDate", 0);
      file_info.metadata.last_modified_date = this.get_xml_tag_content(file_text, "xmp:ModifyDate", 0);
      file_info.metadata.author = this.get_xml_tag_content(file_text, "dc:creator", 0);
      file_info.metadata.author = file_info.metadata.author.replace(/\<\/?\w+\:?\w+\>/gm, "").trim(); //Remove XML tags from author string
      file_info.metadata.title = this.get_xml_tag_content(file_text, "dc:title", 0);

      if (file_info.metadata.title.indexOf("rdf:li")) {
        file_info.metadata.title = this.get_xml_tag_content(file_info.metadata.title, "rdf:li", 0);
      }

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

    // Remove þÿ from creation application.
    if (file_info.metadata.creation_application.startsWith("þÿ")) {
      file_info.metadata.creation_application = file_info.metadata.creation_application.substr(2);
    }

    return file_info;
  }

  /**
   * Extracts meta data and other information from PNG image files.
   *
   * @see http://www.libpng.org/pub/png/spec/1.2/PNG-Chunks.html
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param {String}      file_text    The unicode text of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_png(file_bytes, file_text) {
    var file_info = Static_File_Analyzer.get_default_file_json();

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
        var chunk_length_int = Static_File_Analyzer.get_four_byte_int(chunk_length_bytes);
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

    // Check for RDF Metadata
    let metadata = this.extract_rdf_metadata(file_bytes, file_text);
    if (metadata.found) {
      file_info.metadata.title = metadata.title;
      file_info.metadata.description = metadata.description;
      file_info.metadata.author = metadata.author;
      file_info.metadata.creation_date = metadata.creation_date;
      file_info.metadata.creation_application = metadata.creation_application;
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
    var file_info = Static_File_Analyzer.get_default_file_json();

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

    let header_crc = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(8,12));
    let byte_index = [12];
    let header_size = RAR_Parser.read_vinteger(file_bytes, byte_index);
    let header_type = RAR_Parser.read_vinteger(file_bytes, byte_index);

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

    var file_info = Static_File_Analyzer.get_default_file_json();

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

    // Look for objects
    let open_bracket_count = 0;
    let char_index = 0;
    let emb_objects = [];
    open_bracket_count += 1;

    while (char_index >= 0 && char_index < file_text_ascii.length) {
      let obj_index = file_text_ascii.toLowerCase().indexOf("\object", char_index);

      if (obj_index < 0) break;

      // find object control words
      let control_words = [];
      let found_1x_width = false;
      let found_1x_height = false;

      if (obj_index > 0) {
        let open_bracket = file_text_ascii.indexOf("{", (obj_index+7));
        let close_bracket = file_text_ascii.indexOf("}", (obj_index+7));
        let object_control_txt = "";

        if (open_bracket < close_bracket) {
          object_control_txt = file_text_ascii.substring((obj_index+7), open_bracket);
          char_index = open_bracket+1
          open_bracket_count += 1
        } else {
          object_control_txt = file_text_ascii.substring((obj_index+7), close_bracket);
          char_index = close_bracket+1
          open_bracket_count -= 1
        }

        let control_word_regex = /\\([\d\w]+)/gmi;
        let control_word_match = control_word_regex.exec(object_control_txt);
        while (control_word_match !== null) {
          control_words.push(control_word_match[1]);

          if (control_word_match[1].toLowerCase() == "objh1") found_1x_height = true;
          if (control_word_match[1].toLowerCase() == "objw1") found_1x_width = true;

          control_word_match = control_word_regex.exec(object_control_txt);
        }
      } else {
        break;
      }

      while (open_bracket_count > 0) {
        let open_bracket = file_text_ascii.indexOf("{", char_index);
        let close_bracket = file_text_ascii.indexOf("}", char_index);

        if (open_bracket < 0 || close_bracket < open_bracket) {
          open_bracket_count -= 1
          char_index = close_bracket+1
        } else {
          open_bracket_count += 1

          let control_word_regex = /\\([\d\w]+)/gmi;
          let control_word_match = control_word_regex.exec(file_text_ascii.substring(char_index));

          while (control_word_match !== null) {
            if (control_word_match[1].toLowerCase() == "objdata") {
              close_bracket = file_text_ascii.indexOf("}", char_index+control_word_match.index);
              open_bracket_count -= 1
              let obj_data = file_text_ascii.substring((char_index+control_word_match.index+8), close_bracket)
              obj_data = obj_data.replace(/\s/g,'');

              // Look for encoded StaticDib control word
              if (obj_data.indexOf("537461746963446962") >= 0) {
                file_info.analytic_findings.push("MALICIOUS - CVE-2025-21298 Exploit Found");
              }
            }

            char_index = close_bracket+1
            control_word_match = control_word_regex.exec(file_text_ascii.substring(char_index));
          }

        }
      }

      // Analytics
      if (found_1x_height && found_1x_width) {
        // Found a 1x1 sised object, may be an attempt to hide something malicious.
        file_info.analytic_findings.push("SUSPICIOUS - Found 1x1 Sized OLE Object");
      }
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
        file_info = Static_File_Analyzer.add_ttp("T1203", "Execution", "Exploits CVE-2017-11882 in Microsoft Office’s Equation Editor.", file_info);
      }

      hex_data_match = hex_data_regex.exec(file_text_ascii);
    }

    return file_info;
  }

  /**
   * Extracts meta data and other information from TIFF formatted files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   *
   * @see https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf
   * @see https://dev.exiv2.org/projects/exiv2/wiki/The_Metadata_in_TIFF_files
   */
  analyze_tiff(file_bytes) {
    var file_info = Static_File_Analyzer.get_default_file_json();
    let byte_order = "LITTLE_ENDIAN";

    file_info.file_format = "tiff";
    file_info.file_generic_type = "Image";

    // This format does not support encryption
    file_info.file_encrypted = "false";
    file_info.file_encryption_type = "none";

    // Get Byte Order
    if (file_bytes[0] == 0x49) {
      byte_order = "LITTLE_ENDIAN";
    } else if (file_bytes[0] == 0x4d) {
      byte_order = "BIG_ENDIAN";
    } else {
      // Error / Unknown
      return file_info;
    }

    let first_ifd_offset = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(4,8), byte_order);
    let first_ifd_object = Tiff_Tools.parse_ifd(file_bytes, first_ifd_offset, byte_order);

    return file_info;
  }

  /**
   * Extracts meta data and other information from TNEF formatted files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_tnef(file_bytes) {
    var file_info = Static_File_Analyzer.get_default_file_json();

    file_info.file_format = "tnef";
    file_info.file_generic_type = "Mail Message";

    // This format does not support encryption
    file_info.file_encrypted = "false";
    file_info.file_encryption_type = "none";

    let parse_result = TNEF_Parser.parse_tnef(file_bytes);

    file_info.parsed = parse_result;

    for (let i=0; i<parse_result.attachments.length; i++) {
      let is_valid = Static_File_Analyzer.is_valid_file(parse_result.attachments[i].data);
      let file_type = (is_valid.is_valid) ? is_valid.type : "bin";
      let filename = parse_result.attachments[i].filename;

      file_info.file_components.push({
        'name': filename,
        'type': file_type,
        'directory': false,
        'file_bytes': parse_result.attachments[i].data
      });

    }

    console.log(parse_result);

    return file_info;
  }

  /**
   * Extracts meta data and other information from True Tupe Fonts (TTF) formatted files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_ttf(file_bytes) {
    var file_info = Static_File_Analyzer.get_default_file_json();

    file_info.file_format = "ttf";
    file_info.file_generic_type = "Font";

    // This format does not support encryption
    file_info.file_encrypted = "false";
    file_info.file_encryption_type = "none";

    return file_info;
  }

  /**
   * Extracts meta data and other information from Universal Disk Format (UDF) .iso image files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_udf(file_bytes, file_text="") {
    var file_info = Static_File_Analyzer.get_default_file_json();

    file_info.file_format = "iso";
    file_info.file_generic_type = "Disk Image";

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
      // @see https://wiki.osdev.org/UDF

      // Get sector size
      var anchor_pointer = 0;
      var decr_tag_buffer = []
      var sector_size = 0;
      var sector_start = 0;

      var main_volume_descriptor_sequence_extent = null;
      var reserve_volume_descriptor_sequence_extent = null;

      var sector_sizes = [4096, 2048, 1024, 512];

      for (var i=0; i<sector_sizes.length; i++) {
        // File is not large enough for this sector size, skip it.
        if (file_bytes.length < sector_sizes[i] * 257) continue;

        sector_start = sector_sizes[i] * 256;
        decr_tag_buffer = file_bytes.slice(sector_start, sector_start+16);
        var anchor_descriptor_tag = Universal_Disk_Format_Parser.parse_descriptor_tag(decr_tag_buffer);

        if (anchor_descriptor_tag.valid == false) continue;
        if (anchor_descriptor_tag.tag_identifier != 2) continue; // Skip if this is not Anchor Volume Description Pointer

        sector_size = sector_sizes[i];
        anchor_pointer = anchor_descriptor_tag.tag_location;

        main_volume_descriptor_sequence_extent = {
          'length': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(sector_start+16, sector_start+20), Static_File_Analyzer.LITTLE_ENDIAN),
          'location': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(sector_start+20, sector_start+24), Static_File_Analyzer.LITTLE_ENDIAN)
        }

        reserve_volume_descriptor_sequence_extent = {
          'length': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(sector_start+24, sector_start+28), Static_File_Analyzer.LITTLE_ENDIAN),
          'location': Static_File_Analyzer.get_four_byte_int(file_bytes.slice(sector_start+28, sector_start+32), Static_File_Analyzer.LITTLE_ENDIAN)
        }

        break;
      }

      var descriptors = [];
      var found_anchor_volume_descriptor_pointer = false;

      if (main_volume_descriptor_sequence_extent !== null) {
        // parse descriptors
        var loop_start = sector_size * (main_volume_descriptor_sequence_extent.location);

        for (var i=loop_start; i<=file_bytes.length; i+=sector_size) {
          sector_start = i;
          var udf_sector = Universal_Disk_Format_Parser.parse_sector(file_bytes.slice(sector_start, sector_start+sector_size), sector_size, sector_start);

          if (udf_sector.type == "invalid") continue;

          if (udf_sector.type == "Anchor Volume Descriptor Pointer") {
            if (found_anchor_volume_descriptor_pointer == false) {
              found_anchor_volume_descriptor_pointer = true;
            } else {
              // Assume only one Anchor Volume Descriptor Pointer per ISO UDF file.
              break;
            }
          }

          descriptors.push(udf_sector);

          // Update file metadata
          if (udf_sector.descriptor.hasOwnProperty("attribute_timestamp")) {
            if (file_info.metadata.creation_date == "0000-00-00 00:00:00") {
              file_info.metadata.creation_date = udf_sector.descriptor.attribute_timestamp;
            }
          }

          if (udf_sector.descriptor.hasOwnProperty("creation_timestamp")) {
            if (file_info.metadata.creation_date == "0000-00-00 00:00:00") {
              file_info.metadata.creation_date = udf_sector.descriptor.creation_timestamp;
            }
          }

          if (udf_sector.descriptor.hasOwnProperty("modification_timestamp")) {
            if (file_info.metadata.last_modified_date == "0000-00-00 00:00:00") {
              file_info.metadata.last_modified_date = udf_sector.descriptor.modification_timestamp;
            }
          }

          if (udf_sector.descriptor.hasOwnProperty("implementation_identifier")) {
            if (udf_sector.descriptor.implementation_identifier.hasOwnProperty("identifier")) {
              var identifier_name = udf_sector.descriptor.implementation_identifier.identifier;
              identifier_name = (identifier_name.charAt(0) == "*") ? identifier_name.slice(1) : identifier_name;
              file_info.metadata.creation_application = identifier_name;

              if (identifier_name == "Microsoft IMAPI2 1.0") {
                file_info.metadata.creation_os = "Windows";
              } else if (identifier_name == "UDF Image Creator") {
                file_info.metadata.creation_os = "Windows";
              }
            }
          }

        }

        // Build a list of files
        var current_descriptor_index = 0;
        var current_fid = null;
        var current_fe = null;
        var position_start = 0;
        var file_list = [];

        var file_enrty_index = 0;
        var file_identifiers = [];

        while (current_descriptor_index < descriptors.length) {
          if (descriptors[current_descriptor_index].type == "Partition Descriptor") {
            position_start = descriptors[current_descriptor_index].descriptor.byte_start;
            current_descriptor_index++;
          } else if (descriptors[current_descriptor_index].type == "File Identifier Descriptor") {
            current_fid = descriptors[current_descriptor_index].descriptor;

            for (var i=0; i<current_fid.length; i++) {
              if (current_fid[i].file_characteristics.directory && current_fid[i].file_characteristics.parent) {
                // Skip over root directory.
                continue;
              } else {
                file_identifiers.push({
                  'name': current_fid[i].file_identifier,
                  'directory': current_fid[i].file_characteristics.directory,
                });
              }
            }

            current_descriptor_index++;
          } else if (descriptors[current_descriptor_index].type == "Extended File Entry" ||
                     descriptors[current_descriptor_index].type == "File Entry") {

             if (file_enrty_index >= file_identifiers.length) {
               current_descriptor_index++;
               continue;
             }

             current_fe = descriptors[current_descriptor_index].descriptor;

             var file_length = current_fe.allocation_descriptors[0].extent_length;
             var file_location = current_fe.allocation_descriptors[0].extent_position;
             var file_byte_location = position_start + (file_location * sector_size);
             var c_file_bytes = file_bytes.slice(file_byte_location,file_byte_location+file_length);

             // Check to see if the file has been added, this might be the reserve (duplicate) data.
             var is_duplicate = false;
             for (var fli=0; fli<file_list.length; fli++) {
               if (file_list[fli].name == file_identifiers[file_enrty_index].name) {
                 if (file_list[fli].file_bytes.length == c_file_bytes.length) {
                   is_duplicate = true;
                   break;
                 }
               }
             }

             if (is_duplicate == true) {
               // File already added, assume we have entered the reserve data and break the loop.
               break;
             }

             file_list.push({
               'name': file_identifiers[file_enrty_index].name,
               'directory': file_identifiers[file_enrty_index].directory,
               'file_bytes': c_file_bytes,
               'type': "udf"
             });

             file_enrty_index++;
             current_descriptor_index++;
          } else {
            current_descriptor_index++;
          }
        }

        file_info.parsed = JSON.stringify(descriptors, null, 2);

        // Add parsed files to ISO file components
        file_info.file_components = file_info.file_components.concat(file_list);
      }
    }

    return file_info
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
            var varable_obj = this.get_xls_var_ref(new_object_type[0], document_obj, file_info);

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
   * @see https://inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files
   * @see https://docs.microsoft.com/en-us/previous-versions/office/developer/office-2010/gg615597(v=office.14)
   * @see https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/43684742-8fcd-4fcd-92df-157d8d7241f9
   *
   * @param  {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param  {object}      file_info    An object representing the extracted information from the parent Compound File Binary object.
   * @param  {object}      document_obj A Compound File Binary object
   * @return {Object}      file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_xls(file_bytes, file_info, document_obj) {
    file_info.file_format = "xls";
    file_info.file_generic_type = "Spreadsheet";

    // Variables to load spreadsheet into mem.
    var sheet_index_list = []; // Indexed list of sheet names.
    var spreadsheet_sheet_names = {};
    var string_constants = Array();
    var spreadsheet_defined_vars = {};
    var spreadsheet_var_names = [];
    var downloaded_files = [];
    var document_properties = document_obj.document_properties;

    document_obj['sheets'] = spreadsheet_sheet_names;
    document_obj['string_constants'] = string_constants;
    document_obj['current_sheet_name'] = "";
    document_obj['current_cell'] = "";
    document_obj['indexed_cells'] = {};
    document_obj['varables'] = spreadsheet_defined_vars;
    document_obj['recalc_objs'] = []

    var cmb_obj = document_obj.compound_file_binary;
    var current_byte = 0;

    file_info.file_format_ver = cmb_obj.format_version_major;
    var byte_order = cmb_obj.byte_order; // Byte order LITTLE_ENDIAN or BIG_ENDIAN
    document_obj.byte_order = byte_order;

    var sector_size = cmb_obj.sector_size; // Size in bytes
    var sec_id_1 = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(48,52), byte_order);
    var sec_1_pos = 512 + (sec_id_1 * sector_size); // Should be Root Entry
    var workbook_pos = sec_1_pos + 128;
    var summary_info_pos = workbook_pos + 128;
    var doc_summary_info_pos = summary_info_pos + 128;

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
      var biff_record_length = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(current_byte+2,current_byte+4), byte_order);

      // Byte value of 5 representing BIFF 5/7 and 6 representing BIFF 8.
      var biff_version = file_bytes[current_byte+5];
      var xlm_val = file_bytes.slice(current_byte+6,current_byte+8);

      if (Static_File_Analyzer.array_equals(xlm_val, [40,0])) {
        // Excel 4.0 macro sheet
        file_info.scripts.script_type = "Excel 4.0 Macro";
      }

      current_byte += 8;

      var rup_build = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(current_byte,current_byte+=2), byte_order);
      var rup_year = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(current_byte,current_byte+=2), byte_order);

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
          var stream_pos = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(i+4,i+8), byte_order);

          if (boundsheet_length < 4 || stream_pos > file_bytes.length) continue;

          // 0 - visible, 1 - hidden, 2 - very hidden.
          var sheet_state_val = file_bytes[i+8];

          // Some malicious Excel files will have unused bits set that are part of this byte.
          sheet_state_val = this.get_int_from_bin(Static_File_Analyzer.get_binary_array([sheet_state_val]).slice(-2));
          var sheet_state = (sheet_state_val == 1) ? "hidden" : ((sheet_state_val == 1) ? "very hidden": "visible");

          // 0 - Worksheet or dialog sheet, 1 - Macro sheet, 2 - Chart sheet, 6 - VBA module
          var sheet_type = file_bytes[i+8];
          var sheet_name = Static_File_Analyzer.get_string_from_array(file_bytes.slice(i+12, i+boundsheet_length+4));

          if (sheet_name !== null) {
            spreadsheet_sheet_names[sheet_name] = {
              'name': sheet_name,
              'state': sheet_state,
              'sheet_type': sheet_type,
              'file_pos': stream_pos + stream_start,
              'data': {}
            };
          }

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
          var sst_record_size = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(i+2,i+4), byte_order);

          if (sst_record_size > 0) {
            var cst_total = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(i+4,i+8), byte_order);
            var cst_unique = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(i+8,i+12), byte_order);

            if (cst_unique > cst_total) continue;

            var rgb_bytes = file_bytes.slice(i+12, i+sst_record_size+4);
            var current_unique_offset = 0;

            if (rgb_bytes.length > 0) {
              // See https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/173d9f51-e5d3-43da-8de2-be7f22e119b9
              for (var u=0; u < cst_unique; u++) {
                var char_count = Static_File_Analyzer.get_two_byte_int(rgb_bytes.slice(current_unique_offset, current_unique_offset+2), byte_order);
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
                  c_run = Static_File_Analyzer.get_two_byte_int(rgb_bytes.slice(current_unique_offset, current_unique_offset+2), byte_order);
                  varable_offset += 2;
                }

                if (phonetic_string) {
                  cb_ext_rst = Static_File_Analyzer.get_four_byte_int(rgb_bytes.slice(current_unique_offset+varable_offset, current_unique_offset+varable_offset+2), byte_order);
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
                  file_info = Static_File_Analyzer.search_for_iocs(rgb, file_info);
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
          var record_size = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(i+2,i+4), byte_order);
          //var prop_bits = this.get_bin_from_int(file_bytes[4]).concat(this.get_bin_from_int(file_bytes[5]));
          var prop_bits = Static_File_Analyzer.get_binary_array([file_bytes[4],file_bytes[5]]);
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

          if (is_built_in) {
            // This is not a reliable check as some malicious XLS files don't tag Auto_Open as a built in.
          }

          var name_char_count = file_bytes[i+7];
          var rgce_size = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(i+8,i+10), byte_order);
          var reserved3 = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(i+10,i+12), byte_order);
          if (reserved3 != 0) continue;

          var itab = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(i+12,i+14), byte_order);
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
            var rgce_bytes = file_bytes.slice(string_end, string_end+rgce_size);
            var current_rgce_byte = 0;
            var formula = (rgce_size > 0) ? "" : null;

            while (current_rgce_byte<rgce_size) {
              var formula_type = rgce_bytes[current_rgce_byte];

              // TODO implement all formulas here.
              if (formula_type == 0x1C) {
                // PtgErr - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/4746c46e-8301-4d72-aaa8-742f5404b5db
                var error_code = rgce_bytes[current_rgce_byte+1]
                current_rgce_byte += 2;
              } else if (formula_type == 0x3A) {
                // PtgRef3d - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/1ca817be-8df3-4b80-8d35-46b5eb753577
                var loc_row = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+3,current_rgce_byte+5), byte_order);
                var col_rel = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+5,current_rgce_byte+7), byte_order);
                var col_rel_bits = this.get_bin_from_int(col_rel);
                var loc_col = this.get_int_from_bin(col_rel_bits.slice(0,13));
                var cell_ref = this.convert_xls_column(loc_col) + (loc_row+1);
                var sheet_name = sheet_index_list[itab];

                formula += sheet_name + "!" + cell_ref;
                current_rgce_byte += 7;
              } else {
                break;
              }

            }

            if (string_end-i-19 == 1) {
              // Built in function
              var built_in_names = ["Consolidate_Area","Auto_Open","Auto_Close","Extract","Database","Criteria","Print_Area","Print_Titles","Recorder","Data_Form","Auto_Activate","Auto_Deactivate","Sheet_Title","_FilterDatabase"];
              if (file_bytes[i+19] < 14) {
                string_val = built_in_names[file_bytes[i+19]];
              }
            }

            spreadsheet_var_names.push({
              'name': string_val,
              'formula': formula
            });

          }

        }
      }

      document_obj = {
        'type': "spreadsheet",
        'byte_order': byte_order,
        'document_properties': document_properties,
        'sheets': spreadsheet_sheet_names,
        'sheet_index_list': sheet_index_list,
        'sheet_indexes': Array(sheet_index_list.length),
        'string_constants': string_constants,
        'current_sheet_name': Object.entries(spreadsheet_sheet_names)[0],
        'current_cell': "",
        'indexed_cells': {},
        'defined_names': spreadsheet_var_names,
        'varables': spreadsheet_defined_vars,
        'recalc_objs': document_obj.recalc_objs,
        'unknown_cells_are_blank': false
      };

      var cell_records = this.read_dbcell_records(file_bytes, document_obj, byte_order);

      // Parse the String and Number cells first.
      var cell_data_obj;
      var formula_sheet_name, formula_cell_name;

      for (var i=0; i<cell_records.length; i++) {
        if (cell_records[i].cell_name != "") {
          var full_cell_name = cell_records[i].sheet_name + "!" + cell_records[i].cell_name;
          document_obj.indexed_cells[full_cell_name] = cell_records[i];
        }

        if (cell_records[i].record_type == "Formula") {
          // Don't parse formula records yet, just store it's cell name info.
          formula_sheet_name = cell_records[i].sheet_name;
          formula_cell_name  = cell_records[i].cell_name;
        } else if (cell_records[i].record_type == "LabelSst") {
          cell_data_obj = this.parse_xls_label_set_record(cell_records[i], string_constants, byte_order);
          document_obj.sheets[cell_data_obj.sheet_name].data[cell_data_obj.cell_name] = cell_data_obj.cell_data;
          formula_cell_name  = "";
          //console.log(cell_data_obj.sheet_name + " " + cell_data_obj.cell_name + " - " + cell_data_obj.cell_data.value);
        } else if (cell_records[i].record_type == "MulBlank") {
          var blank_cell_name;
          var row = Static_File_Analyzer.get_two_byte_int(cell_records[i].record_bytes.slice(0, 2), byte_order);
          var col_first = Static_File_Analyzer.get_two_byte_int(cell_records[i].record_bytes.slice(2, 4), byte_order);
          var col_last = Static_File_Analyzer.get_two_byte_int(cell_records[i].record_bytes.slice(-2), byte_order);

          for (var bcell_index=col_first; bcell_index <= col_last; bcell_index++) {
            blank_cell_name = this.convert_xls_column(bcell_index) + row;
            document_obj.sheets[cell_records[i].sheet_name].data[blank_cell_name] = {
              'formula': null,
              'value': ""
            }
            //console.log(cell_records[i].sheet_name + " " + blank_cell_name + " - [blank]");
          }

        } else if (cell_records[i].record_type == "RK") {
          cell_data_obj = this.parse_xls_rk_record(cell_records[i], byte_order);
          document_obj.sheets[cell_data_obj.sheet_name].data[cell_data_obj.cell_name] = cell_data_obj.cell_data;
          formula_cell_name  = "";
          //console.log(cell_data_obj.sheet_name + " " + cell_data_obj.cell_name + " - " + cell_data_obj.cell_data.value);
        } else if (cell_records[i].record_type == "String") {
          // If the last record was a formula this string is the precal value, fill cell with this value.
          if (formula_cell_name != "") {
            var string_size = Static_File_Analyzer.get_two_byte_int(cell_records[i].record_bytes.slice(0, 2), byte_order);
            var byte_option_bits = this.get_bin_from_int(cell_records[i].record_bytes[2]);
            var double_byte_chars = (byte_option_bits[0] == 1) ? true : false;
            var string_end = (double_byte_chars) ? 3 + (string_size * 2) : 3 + string_size;
            var string_val = Static_File_Analyzer.get_string_from_array(cell_records[i].record_bytes.slice(3, string_end));

            document_obj.sheets[formula_sheet_name].data[formula_cell_name] = {
              'formula': null,
              'value': string_val
            }

            formula_cell_name  = "";
          }

          continue;
        } else {
          formula_cell_name  = "";
        }
      }

      // Check for Auto_Open LBL value
      var auto_open_cell = "";
      for (var dn=0; dn<document_obj.defined_names.length; dn++) {
        if (document_obj.defined_names[dn].name == "Auto_Open") {
          auto_open_cell = document_obj.defined_names[dn].formula;
          if (document_obj.indexed_cells.hasOwnProperty(auto_open_cell)) {
            // Put Auto_Open cell as fist cell_record
            cell_records.unshift(document_obj.indexed_cells[auto_open_cell]);
          }
          break;
        }
      }

      // Parse the remaining cells
      var cell_data_obj;
      for (var i=0; i<cell_records.length; i++) {
        if (i > 0 && auto_open_cell != "" && cell_records[i].cell_name == auto_open_cell) {
          // Skip auto_open cell as we should have already done it.
          continue;
        }

        if (cell_records[i].record_type == "String") {
          // String value of a formula.
          var string_size = Static_File_Analyzer.get_two_byte_int(cell_records[i].record_bytes.slice(0, 2), byte_order);
          var byte_option_bits = this.get_bin_from_int(cell_records[i].record_bytes[2]);
          var double_byte_chars = (byte_option_bits[0] == 1) ? true : false;
          var string_end = (double_byte_chars) ? 3 + (string_size * 2) : 3 + string_size;
          var string_val = Static_File_Analyzer.get_string_from_array(cell_records[i].record_bytes.slice(3, string_end));

          // DEBUG
          if (cell_data_obj.cell_data.value != string_val) {
            //console.log(cell_data_obj.sheet_name + " " + cell_data_obj.cell_name + " Cell precalc missmatch - calc: " + cell_data_obj.cell_data.value + " precalc: " + string_val);

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
            //console.log(cell_data_obj.sheet_name + " " + cell_data_obj.cell_name + " - " + cell_data_obj.cell_data.formula + " - "+ cell_data_obj.cell_data.value);
          }

        }
      }

      //console.log("~~Recalc cells") // DEBUG
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
                  //console.log(cell_data_obj.cell_name + " - " + cell_data_obj.cell_data.formula + " - "+ cell_data_obj.cell_data.value);
                } else {
                  var debug45=54;
                }

              }
            }
          }
        }

        if (document_obj.recalc_objs.length == last_recalc_len) {
          document_obj.unknown_cells_are_blank = true;
          //break;
        } else {
          last_recalc_len = document_obj.recalc_objs.length;
        }
      }

      // Read sheet indexes
      // See https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/67c20922-0427-4c2d-96cc-2267d3f09e8c
      // The Index record specifies row information and the file locations for all DBCell records corresponding to each row block in the sheet
      for (const [key, value] of Object.entries(spreadsheet_sheet_names)) {
        var index_start = value.file_pos;

        if (file_bytes[index_start] == 0x0b && file_bytes[index_start+1] == 0x02) {
          var index_record_size = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(index_start+2,index_start+4), byte_order);

          //Skip over reserved 4 bytes
          var reserved_bytes = file_bytes.slice(index_start+4,index_start+8);

          // The first row that has at least one cell with data in current sheet; zero-based index.
          var rw_mic = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(index_start+8,index_start+12), byte_order);

          // The last row that has at least one cell with data in the sheet, MUST be 0 if there are no rows with data.
          var rw_mac = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(index_start+12,index_start+16), byte_order);

          // Specifies the file position of the DefColWidth record, but we don't use this.
          var ib_xf = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(index_start+16,index_start+20), byte_order);

          if (rw_mac > 0) {
            // Read bytes for DBCell file pointers.
            var rgib_rw_bytes = file_bytes.slice(index_start+20,index_start+4+index_record_size);

            if (rgib_rw_bytes.length > 0) {
              // These bytes are an array of FilePointers giving the file position of each referenced DBCell record as specified in [MS-OSHARED] section 2.2.1.5.
              for (var ai=0; ai<rgib_rw_bytes.length;) {
                var file_pointer = Static_File_Analyzer.get_four_byte_int(rgib_rw_bytes.slice(ai,ai+4), byte_order);
                //console.log(file_pointer); // debug

                var first_row_record = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(file_pointer, file_pointer+4), byte_order);
                var first_row_pos = file_pointer + first_row_record;

                var row_block_count = ((rw_mac - rw_mic) % 32 == 0) ? Math.ceil((rw_mac - rw_mic) / 32) : Math.ceil((rw_mac - rw_mic) / 32 + 1);

                // I don't know where the maximum number comes from yet.
                // Open office says it is the number of ROW records in this Row Block
                //The MS doc says it has to be less than 32.
                for (var b=0; b<=row_block_count;) {
                  // Specifies the file offset in bytes to the first record that specifies a CELL in each row that is a part of this row block.
                  var rgdb = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(file_pointer+(b*2)+4, file_pointer+(b*2)+6), byte_order);
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
          var header_bit_array = Static_File_Analyzer.get_binary_array(Uint8Array.from(compressed_header));
          var compressed_chunk_byte_size = this.get_int_from_bin(header_bit_array.slice(4, 16), Static_File_Analyzer.BIG_ENDIAN) + 5;

          var vba_compressed_bytes = file_bytes.slice(i,i+compressed_chunk_byte_size);
          var vba_bytes = this.decompress_vba(vba_compressed_bytes);
          var vba_code = Static_File_Analyzer.get_ascii(vba_bytes);
          vba_code = this.pretty_print_vba(vba_code);

          var sub_match = /\n[a-z\s]?(?:Sub|Function)[^\(]+\([^\)]*\)/gmi.exec(vba_code);

          if (sub_match != null) {
            vba_code = vba_code.substring(sub_match.index).trim();
            this.add_extracted_script("VBA Macro", vba_code, file_info);

            document_obj = {
              'type': "spreadsheet",
              'byte_order': byte_order,
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

    // Check all cells for IoCs
    for (const [sheet_key, sheet_value] of Object.entries(document_obj.sheets)) {
      for (const [data_key, data_value] of Object.entries(sheet_value.data)) {
        file_info = Static_File_Analyzer.search_for_iocs(data_value.value, file_info);
      }
    }

    // Format document object for user output
    delete  document_obj['byte_order'];
    delete  document_obj['current_cell'];
    delete  document_obj['indexed_cells'];
    delete  document_obj['recalc_objs'];
    delete  document_obj['unknown_cells_are_blank'];
    file_info.parsed = JSON.stringify(document_obj, null, 2);

    return file_info;
  }

  /**
   * Extracts meta data and other information from XML files.
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info    A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_xml(file_bytes) {
    var file_info = Static_File_Analyzer.get_default_file_json();

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
   * @param {Uint8Array}  file_bytes    Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param {String}      file_password [optional] Decrypt password for this file.
   * @return {Object}     file_info     A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  async analyze_zip(file_bytes, file_password=undefined) {
    var zip_os_list  = ["MS-DOS", "Amiga", "OpenVMS", "UNIX", "VM/CMS", "Atari ST", "OS/2 H.P.F.S.", "Macintosh", "Z-System", "CP/M", "Windows NTFS", "MVS", "VSE", "Acorn Risc", "VFAT", "alternate MVS", "BeOS", "Tandem", "OS/400", "OS X (Darwin)"];
    var file_info = Static_File_Analyzer.get_default_file_json();

    file_info.file_format = "zip";
    file_info.file_generic_type = "File Archive";

    if (file_password !== null && file_password !== undefined) {
      file_info.file_password = file_password;
    }

    // For OOXML Documents
    var has_content_types_xml = false;
    var has_rels_dir = false;

    var archive_files = [];
    var current_file_start = 0;

    var new_zip = new zip.ZipReader(new zip.Uint8ArrayReader(new Uint8Array(file_bytes)), {useWebWorkers: false});
    var new_zip_entries = await new_zip.getEntries({});

    for (var i=0; i<new_zip_entries.length; i++) {
      var file_entry = new_zip_entries[i];

      file_entry.file_name = file_entry.filename;
      file_entry.file_encrypted = file_entry.encrypted;
      file_info.file_encrypted = file_entry.encrypted.toString();

      if (file_info.metadata.last_modified_date < file_entry.lastModDate.toISOString()) {
        file_info.metadata.last_modified_date = file_entry.lastModDate.toISOString();
      }

      if (file_entry.file_name.toLowerCase() == "[content_types].xml") {
        has_content_types_xml = true;
      }

      if (file_entry.file_name.toLowerCase().substring(0, 6) == "_rels/") {
        has_rels_dir = true;
      }
      let component_bytes = [];

      // Decompress zip bytes
      try {
        if (file_password === undefined) {
          component_bytes = Array.from(await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i));
        } else {
          try {
            component_bytes = Array.from(await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i, file_password));
          } catch (err) {
            file_password = undefined;
            file_info.file_password = "unknown";
          }
        }

      } catch (err) {
        // Probably password protected
        let common_passwords = ['infected','abc123','abc321','malware','virus','decreto','mise'];

        for (let p=0; p<common_passwords.length; p++) {
          try {
            component_bytes = Array.from(await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i, common_passwords[p]));
            file_password = common_passwords[p];
            file_info.file_password = file_password;
            break;
          } catch (err) {}
        }
      }

      archive_files.push(file_entry);
      file_info.file_components.push({
        'name': file_entry.file_name,
        'type': "zip",
        'directory': file_entry.directory,
        'file_bytes': component_bytes,
        'file_password': file_password,
        'last_modified_date': file_entry.lastModDate.toISOString(),
        'uncompressed_size': file_entry.uncompressedSize
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
            file_info = Static_File_Analyzer.search_for_iocs(xml_target_match[1], file_info);
            xml_target_match = xml_target_regex.exec(xml_text);
          }

          // Look for external targets
          var xml_target_regex2 = /\<[a-zA-Z0-9\=\.\:\\\/\"\'\s]+Target\s*\=\s*[\"\'](https?\:[^\"\']+)/gmi;
          var xml_target_match2 = xml_target_regex2.exec(xml_text);

          while (xml_target_match2 !== null) {
            // Check if the relation is a hyperlink
            let relationship_type_regex = /Type\s*\=\s*[\"\']([^\"\']+)[\"\']/gmi;
            let relationship_type_match = relationship_type_regex.exec(xml_target_match2[0]);

            if (relationship_type_match !== null && !relationship_type_match[1].toLowerCase().endsWith("hyperlink")) {
              // If this is a hyperlink don't report it as an External XML Schema Target.
              file_info.analytic_findings.push("SUSPICIOUS - External XML Schema Target: " + xml_target_match2[1]);
            }

            file_info = Static_File_Analyzer.search_for_iocs(xml_target_match2[1], file_info);
            xml_target_match2 = xml_target_regex2.exec(xml_text);
          }

          // Look for suspicious XML domains
          var xml_type_regex = /[^\:\w]Type\s*\=\s*[\"\']([a-zA-Z]+\:\/?\/?([^\/\>\<\"\']+)\/[^\"\']+)/gmi;
          var xml_type_match = xml_type_regex.exec(xml_text);

          while (xml_type_match !== null) {
            if (!Static_File_Analyzer.XML_DOMAINS.includes(xml_type_match[2])) {
              file_info.analytic_findings.push("SUSPICIOUS - Unusual XML Schema Domain: " + xml_type_match[2]);
              console.log(xml_text); // DEBUG
            }

            xml_type_match = xml_type_regex.exec(xml_text);
          }
        } else if (/embeddings\//gmi.test(archive_files[i].file_name)) {
          // embedded OLE objects
          var arc_file_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i);

          if (Static_File_Analyzer.array_equals(arc_file_bytes.slice(0,4), [0xD0,0xCF,0x11,0xE0])) {
            var cmb_obj = this.parse_compound_file_binary(arc_file_bytes);

            var root_guid = cmb_obj.entries[0].enrty_guid;
            if (root_guid === undefined) root_guid = cmb_obj.root_entry.guid;

            for (var ci=0; ci<cmb_obj.entries.length; ci++) {
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
                    file_info = Static_File_Analyzer.add_ttp("T1203", "Execution", "Exploits CVE-2017-11882 in Microsoft Office’s Equation Editor.", file_info);
                  }
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

          if (archive_files[i].file_name.toLowerCase() == "word/_rels/document.xml.rels" ||
              archive_files[i].file_name.toLowerCase() == "word/_rels/document.bin.rels") {

              //TODO: Refactor this into the MS_Document_Parser class.

              // If this is a binary file convert it to text
              if (archive_files[i].file_name.indexOf(".bin") > 0) {
                var workbook_xml_bytes = await Static_File_Analyzer.get_zipped_file_bytes(file_bytes, i);
                xml_text = Static_File_Analyzer.get_string_from_array(workbook_xml_bytes);
              }

              let document_relations = MS_Document_Parser.parse_document_relations(file_info, xml_text);
              spreadsheet_sheet_relations = Object.assign({}, spreadsheet_sheet_relations, document_relations);

              // This will build the relationships for this document
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

                  // Find the VBA projec file.
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
                        this.add_extracted_script("VBA Macro", vba_code, file_info);
                      }
                    }
                  }

                }

                relationship_matches = relationship_regex.exec(xml_text);
              }
          }
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

                var string_size = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(current_byte2, current_byte2+4), Static_File_Analyzer.LITTLE_ENDIAN) * 2;
                var string_bytes = (current_record_bytes.slice(current_byte2+4, current_byte2+4+string_size));
                var string_text = Static_File_Analyzer.get_string_from_array(string_bytes.filter(i => i !== 0));
                current_byte2 = current_byte2 + 4 + string_size;

                string_constants.push(string_text);
                file_info = Static_File_Analyzer.search_for_iocs(string_text, file_info);
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
                var product_version = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(0,4), Static_File_Analyzer.LITTLE_ENDIAN);
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
                var sheet_state_val = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(0,4), Static_File_Analyzer.LITTLE_ENDIAN);
                var sheet_state = (sheet_state_val == 1) ? "hidden" : ((sheet_state_val == 1) ? "very hidden": "visible");

                var sheet_id = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(4,8), Static_File_Analyzer.LITTLE_ENDIAN);
                var sheet_type_size = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(8,12), Static_File_Analyzer.LITTLE_ENDIAN) * 2;
                var sheet_type_bytes = (current_record_bytes.slice(12,12+sheet_type_size));
                var sheet_name_size = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(sheet_type_size+12,sheet_type_size+16), Static_File_Analyzer.LITTLE_ENDIAN) * 2;
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
                      this.add_extracted_script("VBA Macro", vba_code, file_info);
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
                    current_row = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(0,4), Static_File_Analyzer.LITTLE_ENDIAN) + 1;
                  } else if (current_record_info.record_number == 1) {
                    // BrtCellBlank - Blank cell
                  } else if (current_record_info.record_number == 7) {
                    // BrtCellIsst - A cell record that contains a string.
                    var col = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(0,4), Static_File_Analyzer.LITTLE_ENDIAN);
                    var sst_index = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(8,12), Static_File_Analyzer.LITTLE_ENDIAN);
                    var cell_value = string_constants[sst_index];

                    if (current_row > -1) {
                      var cell_id = this.convert_xls_column(col) + current_row

                      spreadsheet_sheet_names[key]['data'][cell_id] = {
                        'formula': null,
                        'value': cell_value
                      }
                    }
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
                    var pane = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(0,4), Static_File_Analyzer.LITTLE_ENDIAN);
                    var row = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(4,8), Static_File_Analyzer.LITTLE_ENDIAN);
                    var col = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(8,12), Static_File_Analyzer.LITTLE_ENDIAN);
                    var rfx_index = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(12,16), Static_File_Analyzer.LITTLE_ENDIAN);
                    var rfx_count = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(16,20), Static_File_Analyzer.LITTLE_ENDIAN);
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
                    var row_start = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(0,4), Static_File_Analyzer.LITTLE_ENDIAN);
                    var row_end = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(4,8), Static_File_Analyzer.LITTLE_ENDIAN);
                    var col_start = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(8,12), Static_File_Analyzer.LITTLE_ENDIAN);
                    var col_end = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(12,16), Static_File_Analyzer.LITTLE_ENDIAN);

                    var rid_size = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(16,20), Static_File_Analyzer.LITTLE_ENDIAN) * 2;
                    var rid_bytes = (current_record_bytes.slice(20, 20+rid_size));
                    var rid = Static_File_Analyzer.get_string_from_array(rid_bytes.filter(i => i !== 0));
                    var current_byte2 = 20+rid_size;

                    var location_size = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(current_byte2, current_byte2+4), Static_File_Analyzer.LITTLE_ENDIAN) * 2;
                    var location_bytes = (current_record_bytes.slice(current_byte2+4, current_byte2+4+location_size));
                    var location = Static_File_Analyzer.get_string_from_array(location_bytes.filter(i => i !== 0));
                    current_byte2 = current_byte2 + 4 + location_size;

                    var tool_tip_size = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(current_byte2, current_byte2+4), Static_File_Analyzer.LITTLE_ENDIAN) * 2;
                    var tool_tip_bytes = (current_record_bytes.slice(current_byte2+4, current_byte2+4+tool_tip_size));
                    var tool_tip = Static_File_Analyzer.get_string_from_array(tool_tip_bytes.filter(i => i !== 0));
                    current_byte2 = current_byte2 + 4 + tool_tip_size;

                    var display_size = Static_File_Analyzer.get_four_byte_int(current_record_bytes.slice(current_byte2, current_byte2+4), Static_File_Analyzer.LITTLE_ENDIAN) * 2;
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
          'byte_order': Static_File_Analyzer.LITTLE_ENDIAN,
          'document_properties': {},
          'sheets': spreadsheet_sheet_names,
          'string_constants': string_constants,
          'current_sheet_name': "",
          'current_cell': "",
          'varables': spreadsheet_defined_names
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
   * Analyze zlib format files.
   *
   * @param {Uint8Array}  file_bytes    Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {Object}     file_info     A Javascript object representing the extracted information from this file. See get_default_file_json() for the format.
   */
  analyze_zlib(file_bytes) {
    var file_info = Static_File_Analyzer.get_default_file_json();

    file_info.file_format = "zlib";
    file_info.file_generic_type = "File Archive";

    return file_info;
  }

  /**
   * Encodes the given byte array into a Base64 string.
   * This function is from Mozilla's Base64 library.
   *
   * @see https://developer.mozilla.org/en-US/docs/Glossary/Base64
   *
   * @param {array}   arr_bytes The array of bytes to convert.
   * @return {String} The Base64 encoded string.
   */
  static base64_encode_array(arr_bytes) {
    var nMod3 = 2, sB64Enc = "";

    for (var nLen = arr_bytes.length, nUint24 = 0, nIdx = 0; nIdx < nLen; nIdx++) {
      nMod3 = nIdx % 3;
      if (nIdx > 0 && (nIdx * 4 / 3) % 76 === 0) { sB64Enc += "\r\n"; }
      nUint24 |= arr_bytes[nIdx] << (16 >>> nMod3 & 24);
      if (nMod3 === 2 || arr_bytes.length - nIdx === 1) {
        sB64Enc += String.fromCharCode(Static_File_Analyzer.uint6ToB64(nUint24 >>> 18 & 63), Static_File_Analyzer.uint6ToB64(nUint24 >>> 12 & 63), Static_File_Analyzer.uint6ToB64(nUint24 >>> 6 & 63), Static_File_Analyzer.uint6ToB64(nUint24 & 63));
        nUint24 = 0;
      }
    }

    return sB64Enc.substr(0, sB64Enc.length - 2 + nMod3) + (nMod3 === 2 ? '' : nMod3 === 1 ? '=' : '==');
  }

  /**
   * Base64 encoder helper function
   * This function is from Mozilla's Base64 library.
   *
   * @see https://developer.mozilla.org/en-US/docs/Glossary/Base64
   *
   * @param {int}  nUint6
   * @return {int}
   */
  static uint6ToB64 (nUint6) {
		return (
			nUint6 < 26   ? nUint6 + 65 :
			nUint6 < 52   ? nUint6 + 71 :
			nUint6 < 62   ? nUint6 - 4  :
			nUint6 === 62 ? 43          :
			nUint6 === 63 ? 47          :
			                65);
	}

  /**
   * Calculates the checksum of an aray of bytes.
   *
   * @param {Uint8Array} file_bytes Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {integer}   The checksum value of the given bytes.
   */
  static calculate_checksum(bytes) {
    let sum = 0;

    for (var i=0; i<bytes.length; i++) {
      sum += bytes[i];
    }

    sum = sum % 65535;
    return sum;
  }

  /**
   * Converts a base64 encoded string to a byte array.
   *
   * @param  {String} base64 The base64 to convert.
   * @return {array}  The coverted base64 in byte array form.
   */
  static convert_base64_to_array(base64) {
    var byte_array, char_code;
    var array_length = 0;
    var string_length = base64.length;

    for (var map_index = 0; map_index < string_length; map_index++) {
      char_code = base64.charCodeAt(map_index);
      array_length += char_code < 0x80 ? 1 : char_code < 0x800 ? 2 : char_code < 0x10000 ? 3 : char_code < 0x200000 ? 4 : char_code < 0x4000000 ? 5 : 6;
    }

    byte_array = new Uint8Array(array_length);

    for (var i = 0, ci = 0; i < array_length; ci++) {
      char_code = base64.charCodeAt(ci);
      if (char_code < 128) {
        /* one byte */
        byte_array[i++] = char_code;
      } else if (char_code < 0x800) {
        /* two bytes */
        byte_array[i++] = 192 + (char_code >>> 6);
        byte_array[i++] = 128 + (char_code & 63);
      } else if (char_code < 0x10000) {
        /* three bytes */
        byte_array[i++] = 224 + (char_code >>> 12);
        byte_array[i++] = 128 + (char_code >>> 6 & 63);
        byte_array[i++] = 128 + (char_code & 63);
      } else if (char_code < 0x200000) {
        /* four bytes */
        byte_array[i++] = 240 + (char_code >>> 18);
        byte_array[i++] = 128 + (char_code >>> 12 & 63);
        byte_array[i++] = 128 + (char_code >>> 6 & 63);
        byte_array[i++] = 128 + (char_code & 63);
      } else if (char_code < 0x4000000) {
        /* five bytes */
        byte_array[i++] = 248 + (char_code >>> 24);
        byte_array[i++] = 128 + (char_code >>> 18 & 63);
        byte_array[i++] = 128 + (char_code >>> 12 & 63);
        byte_array[i++] = 128 + (char_code >>> 6 & 63);
        byte_array[i++] = 128 + (char_code & 63);
      } else {
        /* six bytes */
        byte_array[i++] = 252 + (char_code >>> 30);
        byte_array[i++] = 128 + (char_code >>> 24 & 63);
        byte_array[i++] = 128 + (char_code >>> 18 & 63);
        byte_array[i++] = 128 + (char_code >>> 12 & 63);
        byte_array[i++] = 128 + (char_code >>> 6 & 63);
        byte_array[i++] = 128 + (char_code & 63);
      }
    }

    return byte_array;
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
      var header_bit_array = Static_File_Analyzer.get_binary_array(Uint8Array.from(compressed_header));
      var compressed_chunk_byte_size = this.get_int_from_bin(header_bit_array.slice(4, 16), Static_File_Analyzer.BIG_ENDIAN) + 3;
      var compressed_chunk_signature = this.get_int_from_bin(header_bit_array.slice(1, 4), Static_File_Analyzer.BIG_ENDIAN);
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
      while (current_byte < compressed_data.length) {
        compression_flags = Static_File_Analyzer.get_binary_array(Uint8Array.from([compressed_data[current_byte]])).reverse();
        current_byte++;

        for (var i=0; i<8; i++) {
          if (compression_flags[i] == 0) {
            // Non-compressed byte
            decompressed_buffer.push(compressed_data[current_byte]);
            current_byte++;
          } else {
            // copy token
            var copy_token_bytes = [compressed_data[current_byte+1], compressed_data[current_byte]];
            var copy_token_bits = Static_File_Analyzer.get_binary_array(Uint8Array.from(copy_token_bytes));

            var number_of_bits = Math.ceil(Math.log2(decompressed_buffer.length));
            var number_of_offset_bits = (number_of_bits < 4) ? 4 : ((number_of_bits > 12) ? 12 : number_of_bits);

            var offset_bytes = this.get_int_from_bin(copy_token_bits.slice(0, number_of_offset_bits), Static_File_Analyzer.BIG_ENDIAN) + 1;
            var byte_length = this.get_int_from_bin(copy_token_bits.slice(number_of_offset_bits), Static_File_Analyzer.BIG_ENDIAN) + 3;
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

      this.add_extracted_script("Excel 4.0 Macro", macro_formula, file_info);
    } else if (formula_name.toUpperCase() == "CHAR") {
      //String.fromCharCode(stack_result)
    } else if (formula_name.toUpperCase() == "EXEC") {
      if (!file_info.analytic_findings.includes("SUSPICIOUS - Use of EXEC function")) {
        file_info.analytic_findings.push("SUSPICIOUS - Use of EXEC function");
      }

      this.add_extracted_script("Excel 4.0 Macro", formula_matches.input, file_info);
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
      var formula_p1, formula_p2;

      if (c_index >= 2) {
        formula_p1 = stack[c_index-2];
        formula_p2 = stack[c_index-1];

        formula_p1 = (formula_p1.hasOwnProperty("ref_name")) ? formula_p1.ref_name : formula_p1.value;
        formula_p2 = (formula_p2.hasOwnProperty("ref_name")) ? formula_p2.ref_name : formula_p2.value;
      }

      if (stack[c_index].type == "operator") {
        if (stack[c_index].value == "-") {
          var param1 = stack[c_index-2];
          var param2 = stack[c_index-1];
          var sub_result = 0;

          var formula = formula_p1 + " - " + formula_p2;

          if (param1.type == "number" && param2.type == "number") {
            sub_result = param1.value - param2.value;
          } else if (param1.type == "string" && param2.type == "number") {
            sub_result = parseInt(param1.value) - param2.value;
          } else if (param1.type == "number" && param2.type == "string") {
            sub_result = param1.value - parseInt(param2.value);
          } else if (param1.type == "reference" || param2.type == "reference") {
            sub_result = param1.value + " - " + param2.value;
          }

          stack.splice(c_index-2, 3, {
            'value': sub_result,
            'type': "number",
            'formula': formula
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
            var form1 = "";
            var form2 = "";
            var val1 = "";
            var val2 = "";

            if (stack[c_index-2] !== null && stack[c_index-2] !== undefined) {
              val1 = stack[c_index-2].value;

              if (stack[c_index-2].hasOwnProperty("formula")) {
                form1 = stack[c_index-2].formula;
              } else if (stack[c_index-2].hasOwnProperty("ref_name")) {
                form1 = stack[c_index-2].ref_name;
              } else {
                form1 = val1;
              }
            }

            if (stack[c_index-1] !== null && stack[c_index-1] !== undefined) {
              val2 = stack[c_index-1].value;

              if (stack[c_index-1].hasOwnProperty("formula")) {
                form2 = stack[c_index-1].formula;
              } else if (stack[c_index-1].hasOwnProperty("ref_name")) {
                form2 = stack[c_index-1].ref_name;
              } else {
                form2 = val2;
              }
            }

            var sub_result = String(val1) + String(val2);
            var form_result = form1 + "&" + form2;

            stack.splice(c_index-2, 3, {
              'value': sub_result,
              'formula': form_result,
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
              var param1 = stack[c_index-2];
              var param2 = stack[c_index-1];
              var param1_val = param1.value;
              var param2_val = param2.value;

              var formula = param1_val + " != " + param2_val;
              var sub_result = (String(stack[c_index-2].value) != String(stack[c_index-1].value));

              stack.splice(c_index-2, 3, {
                'value': sub_result,
                'formula': formula,
                'type': "boolean"
              });
            }

            c_index++;
          }
        } else if (stack[c_index].value == "[]") {
          // TODO: Implement this more fully.
          if (stack[c_index-1].value.charAt(0) == "=") {
            var code_script = stack[c_index-1].value.replaceAll(/\\?[\"\']&\\?[\"\']/gm, "");
            this.add_extracted_script("Excel 4.0 Macro", code_script, file_info);

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
         // Assigment, this works the same way as SET.NAME but the rest of stack needs to be resolved
         if (stack.length > 3 && (stack.length - c_index > 1)) {
           // Skip for now
         } else {
           if (c_index == 0) {
             if (stack.length >= 3) {
               var param1 = stack[c_index+1];
               var param2 = stack[c_index+2];
               var param2_val = param2.value;
               var formula = "";
               var var_name = "";

               if (param2.type == "string") {
                 param2_val = (param2.value.length > 0) ? param2.value : "\"\"";
               }

               if (param1.type == "reference") {
                 if (param1.hasOwnProperty('ref_name')) {
                   var_name = param1.ref_name;
                 } else {
                   var_name = param1.value;
                 }
               } else if (param1.type == "string") {
                 var_name = param1.value;
               }

               var param2_form = (param2.hasOwnProperty("formula")) ? param2.formula: param2_val;

               if (param1.type == "string" || param1.type == "reference") {
                 workbook.varables[var_name] = param2.value;
                 formula = "=SET.NAME(" + var_name + ", " + param2_form + ")";
                 stack.splice(c_index, 3, {
                   'value': param2.value,
                   'formula': formula,
                   'type': param2.type
                 });

                 if (c_index+1 < stack.length && stack[c_index+1].value == "_xlfn.SET.NAME") {
                   stack.splice(c_index+1, 1);
                 }
                 // TODO check for references in param2
               }
             } else if (stack.length == 2) {
               workbook.sheets[workbook.current_sheet_name].data[workbook.current_cell] = stack[c_index+1];
               stack.shift();
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
                // Execute an Excel formula.
                var formula_full;
                var function_name = stack[c_index].value.substring(6);
                var param_array = stack.slice(c_index-stack[c_index].params, c_index);
                var param_string = "";

                // Create a string containing the human readable formula name and parameters.
                for (var pi=0; pi<param_array.length; pi++) {
                  if (param_array[pi].type == "boolean") {
                    if (param_array[pi].hasOwnProperty("formula") && param_array[pi].formula !== null && param_array[pi].formula !== undefined) {
                      param_string += param_array[pi].formula + ",";
                    } else {
                      param_string += param_array[pi].value + ",";
                    }

                  } else if (param_array[pi].type == "number") {
                    param_string += param_array[pi].value + ",";
                  } else if (param_array[pi].type == "reference") {
                    param_string += param_array[pi].value + ",";
                  } else if (param_array[pi].type == "string") {
                    param_string += "\"" + param_array[pi].value + "\",";
                  }
                }

                param_string = param_string.slice(0,-1);
                formula_full = "=" + function_name + "(" + param_string + ")";

                if (function_name == "ABSREF") {
                  var param1 = stack[c_index-2];
                  var param2 = stack[c_index-1];
                  var ref_cell = (param2.hasOwnProperty("ref_name")) ? param2.ref_name : param2.value;

                  var base_match = /\@?([^\r\n\!]+)\!([a-zA-Z]+\d+)/gmi.exec(ref_cell);
                  if (base_match === null) {
                    if (workbook.varables.hasOwnProperty(ref_cell)) {
                      base_match = /\@?([^\r\n\!]+)\!([a-zA-Z]+\d+)/gmi.exec(workbook.varables[ref_cell]);
                    }
                  }

                  if (base_match !== null) {
                    var ref_match = /R\[?(\-?\d+)?\]?C\[?(\-?\d+)?\]?/gmi.exec(param1.value);
                    if (ref_match !== null) {
                      var row_shift = (ref_match[1] !== undefined) ? parseInt(ref_match[1]) : 0;
                      var col_shift = (ref_match[2] !== undefined) ? parseInt(ref_match[2]) : 0;

                      var new_cell_ref = this.get_shifted_cell_name(base_match[2], row_shift, col_shift);
                      var new_cell_ref_full = workbook.current_sheet_name + "!" + new_cell_ref;

                      var formula = "=ABSREF(\"" + param1.value + "\"," + base_match[2] + ")";
                      var cell_ref_value;

                      if (workbook.sheets[workbook.current_sheet_name].data.hasOwnProperty(new_cell_ref)) {
                        cell_ref_value = workbook.sheets[workbook.current_sheet_name].data[new_cell_ref];
                      } else {
                        cell_ref_value = "@" + new_cell_ref_full;
                      }

                      stack.splice(c_index-2, 3, {
                        'value': cell_ref_value.value,
                        'type': "reference",
                        'formula': formula,
                        'ref_name': new_cell_ref_full,
                      });

                      c_index--;
                    }
                  } else {
                    // Value is not a base cell reference.
                    var recalc_cell = workbook.current_sheet_name + "!" + workbook.current_cell;
                    if (!workbook.recalc_objs.includes(recalc_cell)) {
                      workbook.recalc_objs.push(recalc_cell);
                    }

                    c_index++;
                  }
                } else if (function_name == "ARABIC") {
                  var sub_result = Static_File_Analyzer.convert_roman_numeral_to_int(stack[c_index+1].value);
                  stack.splice(c_index, 2);
                  stack.unshift({
                    'value': sub_result,
                    'type': "number",
                    'formula': formula_full
                  });
                  c_index++;
                } else if (function_name == "CHAR") {
                  if (c_index > 0) {
                    var sub_result = String.fromCharCode(stack[c_index-1].value);
                    var param_function = stack[c_index-1].hasOwnProperty("formula") ? stack[c_index-1].formula : stack[c_index-1].value;
                    var formula = "=CHAR(" + param_function + ")";

                    stack.splice(c_index-1, 2, {
                      'value': sub_result,
                      'type': "string",
                      'formula': formula
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
                } else if (function_name == "IF") {
                  var sub_result = false;
                  var formula = "=IF(";

                  if (stack[c_index-1].type == "operator") {
                    var op_param1 = stack[c_index-3];
                    var op_param2 = stack[c_index-2];

                    var op_param1_form;
                    var op_param1_val;

                    if (op_param1.hasOwnProperty("xname") && op_param1.xname == "PtgName") {
                      op_param1_form = op_param1.ref_name;
                      op_param1_val = this.get_xls_var_ref(op_param1.ref_name, workbook, {});
                    } else {
                      op_param1_val = op_param1.value;

                      if (op_param1.hasOwnProperty("formula") && op_param1.formula !== null) {
                        op_param1_form = op_param1.formula;
                      } else {
                        op_param1_form = op_param1.value;
                      }
                    }

                    if (stack[c_index-1].value == "==") {
                      formula += op_param1_form + " == " + op_param2.value;
                      sub_result = (op_param1_val == op_param2);
                    } else if (stack[c_index-1].value == "!=") {
                      formula += op_param1_form + " != " + op_param2.value;
                      sub_result = (op_param1_val != op_param2);
                    } else if (stack[c_index-1].value == "<") {
                      formula += op_param1_form + " < " + op_param2.value;
                      sub_result = (op_param1_val < op_param2);
                    } else if (stack[c_index-1].value == ">") {
                      formula += op_param1_form + " > " + op_param2.value;
                      sub_result = (op_param1_val > op_param2);
                    }
                  } if (stack[c_index-1].type == "boolean") {
                    if (stack[c_index-1].hasOwnProperty("formula") && stack[c_index-1].formula !== null && stack[c_index-1].formula != "") {
                      formula += stack[c_index-1].formula;
                    } else {
                      formula += stack[c_index-1].value;
                    }

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
                  var reg_params = stack.slice(c_index-7,c_index);

                  var store_val = "=CALL(\"";
                  for (var rpi=0; rpi<3; rpi++) {
                    store_val += reg_params[rpi].value + "\",\""
                  }
                  workbook.varables[reg_params[3].value] = store_val.slice(0,-2);

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
                  var sub_value = "";
                  var sub_formula = "=RETURN(";
                  var reg_params = stack.slice(0,c_index);

                  for (var rpi=0; rpi<reg_params.length; rpi++) {
                    var param_formula = reg_params[rpi].hasOwnProperty("formula") ? reg_params[rpi].formula : reg_params[rpi].value;
                    sub_formula += param_formula + ",";
                    sub_value += reg_params[rpi].value;
                  }

                  sub_formula = sub_formula.slice(0,-1) + ")";
                  stack.splice(0, c_index+1);
                  stack.unshift({
                    'value': sub_value,
                    'type': "string",
                    'formula': sub_formula
                  });
                  c_index++;
                } else if (function_name == "SET.NAME") {
                  var param1 = {'value': null, 'type': "string"};
                  var param2 = {'value': null, 'type': "string"};
                  var op_stack_length = 1;
                  var set_var_name;

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

                  // TODO - store references to cells as references and recalc when used.
                  var param1_val = param1.value;

                  if (param1.type == "reference" || (param1.hasOwnProperty("xname") && param1.xname == "PtgRef")) {
                    if (param1.hasOwnProperty("ref_name")) {
                      if (param1.ref_name.charAt(0) != "@") {
                        param1_val = "@" + param1.ref_name;
                      } else {
                        param1_val = param1.ref_name;
                      }
                    }
                  }

                  if (param2.type == "reference") {
                    if (param2.hasOwnProperty('ref_name')) {
                      set_var_name = param2.ref_name;
                    } else {
                      set_var_name = param2.value;
                    }
                  } else if (param2.type == "string") {
                    set_var_name = param2.value;
                  }

                  var double_set_name = false;

                  if (set_var_name !== null) {
                    workbook.varables[set_var_name] = param1_val;
                  } else {
                    if (param1.hasOwnProperty("formula") && param1.formula.startsWith("=SET.NAME")) {
                      // TODO this is a bad fix, need to fix stack operation.
                      double_set_name = true;
                    } else {
                      if (!workbook.recalc_objs.includes(workbook.current_cell)) {
                        workbook.recalc_objs.push(workbook.current_cell);
                      }
                    }
                  }

                  if (double_set_name == false) {
                    var param1_form = (param1.hasOwnProperty("formula") && param1.formula !== null) ? param1.formula : param1_val;
                    var formula = "=SET.NAME(" + set_var_name + ", " + param1_form + ")";
                    stack.splice(c_index-op_stack_length+1, c_index+1, {
                      'value':   param1_val,
                      'type':    param1.type,
                      'formula': formula
                    });
                    c_index++;
                  } else {
                    stack.splice(c_index, 1);
                  }
                } else if (function_name == "SIGN") {
                  // Determines the sign of a number. Returns 1 if the number is positive, zero (0) if the number is 0, and -1 if the number is negative.
                  c_index++;
                } else if (function_name == "USERFUNCTION") {
                  // TODO finish implementation of user defined functions
                  if (stack.length > stack[c_index].params) {
                    var params = stack.slice(c_index - stack[c_index].params, c_index);
                    var params2 = [];
                    var user_func_name;
                    var function_value;
                    var ref_name = "";

                    if (params.length > 0 && ((typeof params[0].value) == "string") && params[0].value.startsWith("=CALL(")) {
                      user_func_name = "CALL";
                      var formula_str = params[0].value;

                      for (var fi2=1; fi2<params.length; fi2++) {
                        if (params[fi2].type == "string") {
                          formula_str += ",\"" + params[fi2].value + "\"";
                        } else {
                          formula_str += "," + params[fi2].value;
                        }

                      }
                      formula_str = formula_str + ")";

                      stack.splice(c_index-params.length, params.length+1, {
                        'value': formula_str,
                        'type': "string",
                        'formula': formula_str
                      });

                    } else {
                      user_func_name = params[0].value;
                      function_value = params[0].value;
                      ref_name = "";

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

                        stack.splice(c_index-params.length, params.length+1, {
                          'value': function_value,
                          'type': "string",
                          'formula': sub_result,
                          'ref_name': ref_name,
                          'subroutine': true
                        });
                      } else {
                        stack.splice(c_index-params.length, params.length+1, {
                          'value': sub_result,
                          'type': "string"
                        });
                      }
                    }

                  }
                } else if (function_name == "WHILE") {
                  stack.splice(c_index-param_array.length, param_array.length+1, {
                    'value':   stack[c_index-1].value,
                    'type':    "string",
                    'formula': formula_full
                  });

                  c_index++;
                } else {
                  // Default for formulas where we are not emulating their functionality.
                  stack.splice(c_index-param_array.length, param_array.length+1, {
                    'value':   "",
                    'type':    "string",
                    'formula': formula_full
                  });

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
      if (stack[0].value == "=" && stack[0].type == "operator") {
        // Stack result is an assignment, re-runstack.
        c_index = 0;

        // Check to see if the end of the stack is all strings and concat if they are.
        var str_concat_val = "";
        var str_concat_funct = "";
        var stack_end_is_strings = false;

        for (var i2=2; i2<stack.length; i2++) {
          if (stack[i2].type == "string") {
            stack_end_is_strings = true;
            str_concat_val += (stack[i2].value != "\x00") ? stack[i2].value : "";

            if (stack[i2].hasOwnProperty('formula')) {
              str_concat_funct += stack[i2].formula;
              str_concat_funct += (stack[i2].formula.length > 0) ? "&" : "";
            } else if (stack[i2].hasOwnProperty('ref_name')) {
              str_concat_funct += stack[i2].ref_name;
              str_concat_funct += (stack[i2].ref_name.length > 0) ? "&" : "";
            } else {
              str_concat_funct += (stack[i2].value != "\x00") ? stack[i2].value : "";
            }
          } else {
            stack_end_is_strings = false;
            break;
          }
        }

        if (stack_end_is_strings == true) {
          str_concat_funct = (str_concat_funct.at(-1) == "&") ? str_concat_funct.slice(0,-1) : str_concat_funct;
          str_concat_funct = (str_concat_funct.at(0) == "&") ? str_concat_funct.slice(1) : str_concat_funct;
          stack.splice(2, stack.length, {
            'value': str_concat_val,
            'type': "string",
            'formula': str_concat_funct
          });
        }

        return this.execute_excel_stack(stack, workbook);
      } else {
        // If the stack still has multiple items, something is wrong.
      }
    }

    return stack[0];
  }

  /**
   * Extracts RDF Metadata from a given file.
   *
   * @see https://www.w3.org/TR/1999/REC-rdf-syntax-19990222/
   * @see https://en.wikipedia.org/wiki/Extensible_Metadata_Platform
   *
   * @param {Uint8Array}  file_bytes   Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param {String}      file_text    The unicode text of the file to be analyzed.
   * @return {Object}     metadata     A Javascript object representing the extracted information from this file.
   */
  extract_rdf_metadata(file_bytes, file_text) {
    let metadata = {
      'found': false,
      'title': "unknown",
      'description': "unknown",
      'author': "unknown",
      'creation_date': "0000-00-00 00:00:00",
      'last_modified_date': "0000-00-00 00:00:00",
      'creation_application': "unknown",
      'creation_os': "unknown",
      'last_saved_location': "unknown",
      'ext_id': "",
      'fb_id': ""
    }

    let rdf_match = /<rdf:rdf/gmi.exec(file_text);

    if (rdf_match) {
      metadata.found = true;
      let rdf_start = rdf_match.index;
      let rdf_end = file_text.length;

      let rdf_match2 = /<\/rdf:rdf/gmi.exec(file_text);
      if (rdf_match2) {
        rdf_end = rdf_match2.index;
      }

      let rdf_text = file_text.substr(rdf_start, rdf_end);

      let author_match = /:author\s*>([^<]+)/gmi.exec(rdf_text);
      if (author_match !== null) {
        metadata.author = author_match[1];
      } else {
        author_match = /dc:creator\>(?:\<[^\>]+\>)*([^\<]+)/gmi.exec(rdf_text);
        if (author_match !== null) {
          metadata.author = author_match[1];
        }
      }

      let created_match = /:created\s*>([^<]+)/gmi.exec(rdf_text);
      if (created_match !== null) {
        metadata.creation_date = created_match[1];
      } else {
        created_match = /xmp:CreateDate\>([^\<]+)/gmi.exec(rdf_text);
        if (created_match !== null) {
          metadata.creation_date = created_match[1];
        }
      }

      let creator_tool_match = /:creatortool\s*[=>\'\"]+([^<\"\']+)/gmi.exec(rdf_text);
      if (creator_tool_match !== null) {
        metadata.creation_application = creator_tool_match[1];
      }

      let ext_id_match = /:extid\s*>([^<]+)/gmi.exec(rdf_text);
      if (ext_id_match !== null) {
        metadata.ext_id = ext_id_match[1];
      }

      let fb_id_match = /:fbid\s*>([^<]+)/gmi.exec(rdf_text);
      if (fb_id_match !== null) {
        metadata.fb_id = fb_id_match[1];
      }
    }

    return metadata;
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
      if (Static_File_Analyzer.array_equals(file_bytes.slice(i,i+19), [82,0,111,0,111,0,116,0,32,0,69,0,110,0,116,0,114,0,121])) {
        root_entry_start = i;
      } else if (Static_File_Analyzer.array_equals(file_bytes.slice(i,i+5), [73,68,61,34,123])) {
        // ID="{
        var project_stream_start = i;
        var project_stream_end = project_stream_start + 639;
        var project_stream_str = Static_File_Analyzer.get_ascii(file_bytes.slice(project_stream_start,project_stream_end));

        // End any open attributes
        var decompressed_vba_attribute_bytes = this.decompress_vba(file_bytes.slice(attribute_start, i));
        vba_data.attributes.push(Static_File_Analyzer.get_ascii(decompressed_vba_attribute_bytes));
      } else if (Static_File_Analyzer.array_equals(file_bytes.slice(i,i+8), [65,116,116,114,105,98,117,116])) {
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
  static array_equals(a, b) {
    if ((Static_File_Analyzer.is_typed_array(a) || Array.isArray(a)) && (Static_File_Analyzer.is_typed_array(b) || Array.isArray(b))) {
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
  static get_binary_array(u8int_array) {
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
   * Converts an integer to an array with int values 0-255.
   *
   * @param {integer} int_val An integer to covert.
   * @return {array}  An array with int values 0-255 representing the value of the given integer.
   */
  static get_bytes_from_int(int_val, endianness = "BIG_ENDIAN") {
    let is_litte_endian = (endianness == "BIG_ENDIAN") ? false : true;
    let return_arr = new ArrayBuffer(4); // Allocate 4 bytes
    let data_view = new DataView(return_arr);

    data_view.setUint32(0, int_val, is_litte_endian); // byteOffset = 0

    return Array.from(new Uint8Array(return_arr));
  }

  /**
   * Created the default object structure for the output of this class.
   *
   * @return {object} The defaut object structure for the analyzed file.
   */
  static get_default_file_json() {
    return {
      file_format: "unknown",
      file_generic_type: "unknown",
      file_format_ver: "unknown",
      file_encrypted: "unknown",
      file_encryption_type: "unknown",
      file_password: "unknown",
      file_components: [],
      file_hashes: {
        md5: "",
        sha256: ""
      },
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
      parsed: "Parsed File Not Available",
      analytic_findings: [],
      iocs: [],
      ttps: []
    };
  }

  /**
   * Converts an array with twelve int values 0-255 to a timestamp.
   *
   * @see https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf
   *
   * @param {array}   bytes Array with twelve int values 0-255 representing byte values.
   * @return {String} The timestamp converted from the four byte array.
   */
  get_ecma_timestamp(bytes) {
    var type_and_timezone = Static_File_Analyzer.get_two_byte_int(bytes.slice(0,2), Static_File_Analyzer.LITTLE_ENDIAN);
    var year = Static_File_Analyzer.get_two_byte_int(bytes.slice(2,4), Static_File_Analyzer.LITTLE_ENDIAN);
    year = (year == 0) ? "0000" : year;

    var month = (bytes[4] < 10) ? "0"+bytes[4] : bytes[4];
    var day = (bytes[5] < 10) ? "0"+bytes[5] : bytes[5];
    var hour = (bytes[6] < 10) ? "0"+bytes[6] : bytes[6];
    var minute = (bytes[7] < 10) ? "0"+bytes[7] : bytes[7];
    var second = (bytes[8] < 10) ? "0"+bytes[8] : bytes[8];

    var timestamp = year + "-" + month + "-" + day + " " + hour + ":" + minute + ":" + second;
    return timestamp;
  }

  /**
   * Converts an array with eight int values 0-255 to a date.
   * Bytes must be a 64 bit integer representing the number of 100-nanosecond intervals since January 1, 1601
   *
   * @param {array}    bytes Array with eight int values 0-255 representing byte values.
   * @param {String}   endianness Value indicating how to interperate the bit order of the byte array. Default is BIG_ENDIAN.
   * @return {integer} The integer value of the given bit array.
   */
  get_eight_byte_date(bytes, endianness = Static_File_Analyzer.BIG_ENDIAN) {
    var int_bits = "";

    if (endianness == Static_File_Analyzer.LITTLE_ENDIAN) {
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
   * Converts an array with eight int values 0-255 to an integer.
   *
   * @param {array}    bytes Array with eight int values 0-255 representing byte values.
   * @param {String}   endianness Value indicating how to interperate the bit order of the byte array. Default is BIG_ENDIAN.
   * @return {long} The integer value of the given bit array.
   */
  get_eight_byte_int(bytes, endianness = Static_File_Analyzer.BIG_ENDIAN) {
    var int_bits = "";

    if (endianness == Static_File_Analyzer.LITTLE_ENDIAN) {
      for (var byte_index = 7; byte_index >= 0; byte_index--) {
        int_bits += ("00000000" + (bytes[byte_index]).toString(2)).slice(-8);
      }
    } else {
      for (var byte_index = 0; byte_index < 8; byte_index++) {
        int_bits += ("00000000" + (bytes[byte_index]).toString(2)).slice(-8);
      }
    }

    return parseInt(int_bits, 2);
  }

  /**
   * Converts an array of int values 0-255 to a hex string.
   *
   * @param {array}    bytes Array with int values 0-255 representing byte values.
   * @return {String}  The hex representation of the byte integers in the given array
   */
  static get_hex_string_from_byte_array(int_array) {
    var byte_hex;
    var hex_string = "";

    for (var i=0; i<int_array.length; i++) {
      byte_hex = int_array[i].toString(16);
      byte_hex = (byte_hex.length < 2) ? "0" + byte_hex : byte_hex;
      hex_string += byte_hex;
    }

    return hex_string;
  }

  /**
   * Converts an array with int values 0 or 1 to unsined integer.
   *
   * @param {array}    binary_array Array with int values 0 or 1 representing binary values.
   * @param {String}   endianness Value indicating how to interperate the bit order of the binary array. Default is BIG_ENDIAN.
   * @return {integer} The integer value of the given bit array.
   */
  get_int_from_bin(binary_array, endianness = Static_File_Analyzer.BIG_ENDIAN) {
    var int_val = 0;

    if (endianness == Static_File_Analyzer.LITTLE_ENDIAN) {
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
   * Converts an array of bytes (integer values 0-255) to an integer based on a number of bits.
   *
   * @param {array}    bytes An array containing byte values.
   * @param {integer}  bit_start The bit to start converting to integer from.
   * @param {integer}  bit_end The bit to end the integer conversion at.
   * @param {String}   endianness Value indicating how to interperate the bit order of the binary array. Default is BIG_ENDIAN.
   * @return {integer} The integer value parsed from the byte array.
   */
  static get_int_from_bits(bytes, bit_start, bit_end, endianness="BIG_ENDIAN") {
    let int_val = 0;
    let bits = Static_File_Analyzer.get_binary_array(bytes).slice(bit_start, bit_end);

    if (endianness == "LITTLE_ENDIAN") {
      for (var i=0; i<bits.length; i++) {
        int_val += bits[i] * Math.pow(2, i);
      }
    } else {
      var bit_pos = 0;
      for (var i=bits.length-1; i>=0; i--) {
        int_val += bits[i] * Math.pow(2, bit_pos);
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
  static get_four_byte_int(bytes, endianness = Static_File_Analyzer.BIG_ENDIAN) {
    var int_bits = "";

    if (endianness == Static_File_Analyzer.LITTLE_ENDIAN) {
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
   * Converts an array with sixteen int values 0-255 to a Microsoft GUID.
   *
   * @param {array}    bytes Array with two int values 0-255 representing byte values.
   * @return {integer} The GUID value.
   */
  get_guid(bytes) {
    var guid = [
      Static_File_Analyzer.get_hex_string_from_byte_array(bytes.slice(0,4).reverse()),
      Static_File_Analyzer.get_hex_string_from_byte_array(bytes.slice(4,6).reverse()),
      Static_File_Analyzer.get_hex_string_from_byte_array(bytes.slice(6,8).reverse()),
      Static_File_Analyzer.get_hex_string_from_byte_array(bytes.slice(8,10)),
      Static_File_Analyzer.get_hex_string_from_byte_array(bytes.slice(10,16))
    ].join('-').toUpperCase();

    return guid;
  }

  /**
   * Converts an array of int values 0-255 to an integer.
   *
   * @param {array}    bytes Array with int values 0-255 representing byte values.
   * @param {String}   endianness Value indicating how to interperate the bit order of the byte array. Default is BIG_ENDIAN.
   * @return {integer} The integer value of the given bit array.
   */
  static get_int_from_bytes(bytes, endianness = "BIG_ENDIAN") {
    var int_bits = "";

    if (endianness == "LITTLE_ENDIAN") {
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
  static get_two_byte_int(bytes, endianness = Static_File_Analyzer.BIG_ENDIAN) {
    var int_bits = "";

    if (endianness == Static_File_Analyzer.LITTLE_ENDIAN) {
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
   * Returns an array of bytes starting with the givven array byte 0 and ending with the next null terminator.
   * If there is no null terminator, the whole array will be returned.
   *
   * @param {array}  bytes       An array of integer values from 0 to 255.
   * @param {boolam} double_byte If the null terminator should be two bytes, default i one byte.
   * @return {array} The array of bytes with the null terminator.
   */
  get_null_terminated_bytes(bytes, double_byte=false) {
    var return_array = [];

    if (double_byte == false) {
      for (var i=0; i<bytes.length-1; i++) {
        return_array.push(bytes[i]);
        if (bytes[i] == 0 && bytes[i+1] < 32) break;
      }
    } else {
      for (var i=0; i<bytes.length-1; i++) {
        return_array.push(bytes[i]);

        if (bytes[i] == 0 && bytes[i+1] == 0) {
          return_array.push(bytes[i+1]);
          break;
        }
      }
    }

    return return_array;
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
   * Gets the content an XLS cell.
   *
   * @param {string}  cell_ref        A string in the form of ColumnRow
   * @param {string}  sheet           The sheet containing the cell_ref
   * @param {object}  document_obj    The object containing all the spreadsheet info.
   * @param {object}  parent_cell_obj Optional reference if the cell has a parent reference.
   * @param {object}  file_info    The object for collecting output of static file analysis.
   * @return {Object} The found cell object.
   */
  get_xls_cell_ref(cell_ref, sheet, document_obj, parent_cell_obj, file_info) {
    var byte_order = document_obj.byte_order;
    var ref_cell_full_name = sheet + "!" + cell_ref;
    var return_obj;
    var xname = "PtgRef3d";

    if (document_obj.current_sheet_name == sheet) xname = "PtgRef";

    if (document_obj.unknown_cells_are_blank == true) {
      return_obj = {
        'value': "",
        'formula': null,
        'type':  "reference",
        'ref_name': ref_cell_full_name,
        'xname': xname
      };
    } else {
      return_obj = {
        'value': "@"+ref_cell_full_name,
        'formula': ref_cell_full_name,
        'type':  "reference",
        'ref_name': ref_cell_full_name,
        'xname': xname
      };
    }

    if (document_obj.sheets[sheet].data.hasOwnProperty(cell_ref)) {
      // Cell reference found
      if (document_obj.sheets[sheet].data[cell_ref].formula !== null) {
        if (document_obj.sheets[sheet].data[cell_ref].formula.toUpperCase().startsWith("=")) {
          // recalculate cell
          var ref_cell_raw = document_obj.indexed_cells[ref_cell_full_name];
          var cell_data_obj = this.parse_xls_formula_record(ref_cell_raw, document_obj, file_info, byte_order);
          document_obj.sheets[cell_data_obj.sheet_name].data[cell_data_obj.cell_name] = cell_data_obj.cell_data;
        }
      }

      if (document_obj.sheets[sheet].data[cell_ref].value !== null || document_obj.sheets[sheet].data[cell_ref].value !== undefined) {
        // Cell has a value we can use this.
        return_obj.formula = document_obj.sheets[sheet].data[cell_ref].formula;
        return_obj.value = document_obj.sheets[sheet].data[cell_ref].value;
        return_obj.type = typeof document_obj.sheets[sheet].data[cell_ref].value;
      } else {
        // No cell value, calculate formula
        // TODO: not yet implemented
        return_obj.formula = document_obj.sheets[sheet].data[cell_ref].formula;
      }
    } else {
      // Cell reference was not found or hasn't been loaded yet.
      // This may mean that cells are stored in the file in a different order than need to be calculated.
      var recalc_cell = true;

      if (document_obj.indexed_cells.hasOwnProperty(ref_cell_full_name)) {
        var ref_cell_raw = document_obj.indexed_cells[ref_cell_full_name];

        if (ref_cell_raw.record_type == "Formula") {
          var ref_cell_data_obj = this.parse_xls_formula_record(ref_cell_raw, document_obj, file_info, byte_order);
          document_obj.sheets[ref_cell_data_obj.sheet_name].data[ref_cell_data_obj.cell_name] = ref_cell_data_obj.cell_data;
          return_obj.value = ref_cell_data_obj.cell_data.value;
          return_obj.formula = ref_cell_data_obj.cell_data.formula;
          recalc_cell = false;
        }
      }

      if (parent_cell_obj !== null && recalc_cell == true && document_obj.unknown_cells_are_blank == false) {
        var parent_cell_name_full = parent_cell_obj.sheet_name + "!" + parent_cell_obj.cell_name;
        if (!document_obj.recalc_objs.includes(parent_cell_name_full)) document_obj.recalc_objs.push(parent_cell_name_full);
      }
    }

    return return_obj;
  }

  /**
   * Gets the variable value or resolved reference of a stored varable name.
   *
   * @param {string}  var_name     The varable name to get the value of
   * @param {object}  document_obj The object containing all the spreadsheet info.
   * @param {object}  file_info    The object for collecting output of static file analysis.
   * @return {Object} The found cell object.
   */
  get_xls_var_ref(var_name, document_obj, file_info={}) {
    var var_value = document_obj.varables[var_name];

    if (var_value !== null && var_value !== undefined) {
      if (!Array.isArray(var_value)) {
        if (var_value.length > 0 && var_value.charAt(0) == "@") {
          // This is a reference to a cell, we should re-calculate this are return the value.
          if (document_obj.indexed_cells.hasOwnProperty(var_value.substring(1))) {
            // The raw cell was found in the document pre-parse.
            var raw_cell = document_obj.indexed_cells[var_value.substring(1)];
            var parsed_cell;

            if (raw_cell.record_type == "Formula") {
              parsed_cell = this.parse_xls_formula_record(raw_cell, document_obj, file_info, document_obj.byte_order);
            } else if (raw_cell.record_type == "LabelSst") {
              parsed_cell = this.parse_xls_label_set_record(raw_cell, document_obj.string_constants, document_obj.byte_order);
            } else if (raw_cell.record_type == "RK") {
              parsed_cell = this.parse_xls_rk_record(raw_cell, document_obj.byte_order);
            }

            var_value = parsed_cell.cell_data.value;
          }

        } else {
          // Just return the value;
        }
      }
    } else{
      var_value = "";
    }

    return var_value;
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

  async identify_threat(file_info) {
    let filled_file_info = await file_info;

    // Check to see if the threat identification data struction is loaded.
    if (threat_identification !== undefined && threat_identification !== null) {
      if (filled_file_info.file_generic_type != "File Archive") {
        let file_format = await filled_file_info.file_format;
        let file_format_threats = threat_identification[file_format];

        if (file_format_threats !== undefined && file_format_threats !== null) {
          for (let i=0; i<file_format_threats.length; i++) {
            let is_match = true;

            for (const [key, value] of Object.entries(file_format_threats[i])) {
              if (key != "file_format" && key != "identification" && key != "probability") {
                if (filled_file_info.metadata.hasOwnProperty(key)) {
                  if (filled_file_info.metadata[key] != value) {
                    is_match = false;
                    break;
                  }
                } else {
                  if (filled_file_info[key] != value) {
                    is_match = false;
                    break;
                  }
                }
              }
            }

            if (is_match === true) {
              let finding_str;

              if (file_format_threats[i].probability == 100) {
                finding_str = "MALICIOUS - " + file_format_threats[i].identification;
              } else {
                finding_str = "SUSPICIOUS - " + file_format_threats[i].identification;
              }

              filled_file_info.analytic_findings.push(finding_str);
              break;
            }
          }
        }
      }

    }

    return filled_file_info;
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
  static is_typed_array(array) {
    return !!(array.buffer instanceof ArrayBuffer && array.BYTES_PER_ELEMENT);
  }

  /**
   * Parses compound file binary files and streams.
   *
   * @see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b
   * @see https://msdn.microsoft.com/en-us/library/dd942421.aspx
   *
   * @param {array}   file_bytes The bytes representing the compound file binary.
   * @return {Object} An object representing the parsed compound file binary.
   */
  parse_compound_file_binary(file_bytes) {
    var cmb_obj2 = CFB_Parser.parse(file_bytes);

    // Temp solution to parse summary information. TODO: move this to CFB_Parse class.
    for (let i=0; i<cmb_obj2.entries.length; i++) {
      if (cmb_obj2.entries[i].entry_name == "SummaryInformation") {
        // See: http://sedna-soft.de/articles/summary-information-stream/
        cmb_obj2.entries[i].entry_properties = this.parse_cfb_summary_information(cmb_obj2.entries[i].entry_bytes, cmb_obj2);
        break;
      }
    }

    return cmb_obj2;
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

    if (Static_File_Analyzer.array_equals(stream_bytes.slice(0,4), [0xFE,0xFF,0x00,0x00])) {
      stream_properties['os_version'] = stream_bytes[4] + "." + stream_bytes[5];
      stream_properties['os'] = (stream_bytes[6] == 2) ? "Windows" : (stream_bytes[6] == 1) ? "MacOS" : "Other OS";

      var section_count = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(18, 22), cmb_obj.byte_order);
      var section_ofset = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(44, 48), cmb_obj.byte_order);
      var section_length = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_ofset, section_ofset+4), cmb_obj.byte_order);
      var section_prop_count = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_ofset+4, section_ofset+8), cmb_obj.byte_order);

      var section_prop_info = [];
      var current_offset = section_ofset+8;
      for (var pi=0; pi<section_prop_count; pi++) {
        current_offset += 8;
        var prop_offset = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(current_offset+4, current_offset+8), cmb_obj.byte_order) + 52;

        if (prop_offset < stream_bytes.length) {
          section_prop_info.push({
            'id': Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(current_offset, current_offset+4), cmb_obj.byte_order),
            'offset': prop_offset
          });
        }
      }

      for (var pi=0; pi<section_prop_info.length; pi++) {
        switch (section_prop_info[pi].id) {
          case 1:
            // Code page (02)
            stream_properties['code_page'] = Static_File_Analyzer.get_two_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+2), cmb_obj.byte_order);
            break;
          case 2:
            // Title (1e)
            var string_len = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['title'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 3:
            // Subject (1e)
            var string_len = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['subject'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 4:
            // Author (1e)
            var string_len = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['author'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 5:
            // Keywords (1e)
            var string_len = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['keywords'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 6:
            // Comments (1e)
            var string_len = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['comments'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 7:
            // Template (1e)
            var string_len = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['template'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 8:
            // Last Saved By (1e)
            var string_len = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['last_saved_by'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 9:
            // Revision Number (1e)
            var string_len = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
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
            stream_properties['page_count'] = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            break;
          case 15:
            // Number of Words (03)
            stream_properties['word_count'] = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            break;
          case 16:
            // Number of Characters (03)
            stream_properties['charater_count'] = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            break;
          case 17:
            // Thumbnail (47)
            break;
          case 18:
            // Name of Creating Application (1e)
            var string_len = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
            stream_properties['creating_application'] = Static_File_Analyzer.get_string_from_array(stream_bytes.slice(section_prop_info[pi].offset+4,section_prop_info[pi].offset+4+string_len).filter(i => i !== 0));
            break;
          case 19:
            // Security (03)
            stream_properties['security'] = Static_File_Analyzer.get_four_byte_int(stream_bytes.slice(section_prop_info[pi].offset,section_prop_info[pi].offset+4), cmb_obj.byte_order);
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
   * Parses the descriptor tag for a Universal Disk Format file.
   *
   * @see https://wiki.osdev.org/UDF
   *
   * @param {object}   decr_tag_buffer Byte buffer with the 16 bytes that make up the descriptor tag.
   * @return {Object}  An object with the parsed descriptor tag.
   */
  parse_udf_descriptor_tag(decr_tag_buffer) {
    var tag_identifiers = [0x0001,0x0002,0x0003,0x0004,0x0005,0x0006,0x0007,0x0008,0x0009,0x0100,0x0101,0x0102,0x0103,0x0104,0x0105,0x0106,0x0107,0x0108,0x0109,0x010a];

    var descriptor_tag = {
      'tag_identifier': 0,
      'descriptor_version': 0,
      'tag_checksum': 0,
      'tag_serial_number': 0,
      'descriptor_crc': 0,
      'descriptor_crc_length': 0,
      'tag_location': 0,
      'valid': false
    };

    descriptor_tag.tag_identifier = Static_File_Analyzer.get_two_byte_int(decr_tag_buffer.slice(0,2), Static_File_Analyzer.LITTLE_ENDIAN);
    if (tag_identifiers.includes(descriptor_tag.tag_identifier)) {
      descriptor_tag.descriptor_version = Static_File_Analyzer.get_two_byte_int(decr_tag_buffer.slice(2,4), Static_File_Analyzer.LITTLE_ENDIAN);
      descriptor_tag.tag_checksum = decr_tag_buffer[4];
      descriptor_tag.tag_serial_number = Static_File_Analyzer.get_two_byte_int(decr_tag_buffer.slice(6,8), Static_File_Analyzer.LITTLE_ENDIAN);
      descriptor_tag.descriptor_crc = Static_File_Analyzer.get_two_byte_int(decr_tag_buffer.slice(8,10), Static_File_Analyzer.LITTLE_ENDIAN);
      descriptor_tag.descriptor_crc_length = Static_File_Analyzer.get_two_byte_int(decr_tag_buffer.slice(10,12), Static_File_Analyzer.LITTLE_ENDIAN);
      descriptor_tag.tag_location = Static_File_Analyzer.get_four_byte_int(decr_tag_buffer.slice(12,16), Static_File_Analyzer.LITTLE_ENDIAN);
    }

    // Verify checksum
    var checksum = 0;
    for (var i2=0; i2<decr_tag_buffer.length; i2++) {
      if (i2==4) continue;
      checksum += decr_tag_buffer[i2];
    }

    while (checksum > 256) checksum -= 256; // Truncate to byte

    if (descriptor_tag.tag_checksum == checksum) {
      descriptor_tag.valid = true;
    } else {
      descriptor_tag.valid = false;
    }

    return descriptor_tag;
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
  parse_xls_formula_record(cell_record_obj, document_obj, file_info, byte_order=Static_File_Analyzer.LITTLE_ENDIAN) {
    document_obj.current_sheet_name = cell_record_obj.sheet_name;
    document_obj.current_cell = cell_record_obj.cell_name;

    var file_bytes = cell_record_obj.record_bytes;
    var cell_ref = cell_record_obj.cell_name;

    var cell_value = null;
    var cell_ref_full;
    var cell_recalc = false;
    var downloaded_files = [];

    var cell_ixfe = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(4, 6), byte_order);

    // FormulaValue - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/39a0757a-c7bb-4e85-b144-3e7837b059d7
    var formula_byte1 = file_bytes[6];
    var formula_byte2 = file_bytes[7];
    var formula_byte3 = file_bytes[8];
    var formula_byte4 = file_bytes[9];
    var formula_byte5 = file_bytes[10];
    var formula_byte6 = file_bytes[11];
    var formula_expr  = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(12, 14), byte_order);

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
    var rgce_byte_size = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(20, 22), byte_order);
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
          'type':  "operator",
          'xname': "PtgAdd"
        });
        var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x04) {
        // PtgSub - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/ee15a1fa-77bb-45e1-8c8c-0e7bef7f7552
        formula_calc_stack.push({
          'value': "-",
          'type':  "operator",
          'xname': "PtgSub"
        });
        var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x05) {
        // PtgMul - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/52863fc5-3d3c-4874-90e6-a7961902849f
        formula_calc_stack.push({
          'value': "*",
          'type':  "operator",
          'xname': "PtgMul"
        });
        var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x06) {
        // PtgDiv - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/10585b24-618d-47f4-8ffa-65811d18ad13
        formula_calc_stack.push({
          'value': "/",
          'type':  "operator",
          'xname': "PtgDiv"
        });
        var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x07) {
        // PtgPower - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/e115b216-5dda-4a5b-95d2-cadf0ada9a82
        formula_calc_stack.push({
          'value': "^",
          'type':  "operator",
          'xname': "PtgPower"
        });
        var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x08) {
        // PtgConcat - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/054d699a-4383-4bbf-9df2-6a4020119c1e
        formula_calc_stack.push({
          'value': "&",
          'type':  "operator",
          'xname': "PtgConcat"
        });

        // Stack is implemented as Poish notation, if there is no concat already insert one.
        if (cell_formula.indexOf("&") < 0) {
          if (formula_calc_stack.length > 2) {
            if (formula_calc_stack.at(-2).hasOwnProperty('ref_name')) {
              var ref_name = formula_calc_stack.at(-2).ref_name;
              var insert_index = cell_formula.indexOf(ref_name);
              if (insert_index > 0) {
                cell_formula = cell_formula.slice(0,insert_index) + "&" + cell_formula.slice(insert_index);
              }
            } else if (formula_calc_stack.at(-2).formula !== null) {
              var formula_text = formula_calc_stack.at(-2).formula;
              var insert_index = cell_formula.indexOf(formula_text);
              if (insert_index > 0) {
                cell_formula = cell_formula.slice(0,insert_index) + "&" + cell_formula.slice(insert_index);
              }
            }
          }
        }
        cell_formula += "&";
        var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x0B) {
        // PtgEq - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/d197275e-cb7f-455c-b9b5-7e968412d470
        formula_calc_stack.push({
          'value': "==",
          'type':  "operator",
          'xname': "PtgEq"
        });
        cell_formula += "==";
        //var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
      } else if (formula_type == 0x0E) {
        // PtgNe - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/0e49033d-5dc7-40f1-8fca-eb3b8b1c2c91
        formula_calc_stack.push({
          'value': "!=",
          'type':  "operator",
          'xname': "PtgNe"
        });
        var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;
        //cell_formula += "!=";
      } else if (formula_type == 0x16) {
        // PtgMissArg - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/69352e6c-e712-48d7-92d1-0bf7c1f61f69
        formula_calc_stack.push({
          'value': "",
          'type':  "string",
          'xname': "PtgMissArg"
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


        var ref_match = /R\[?(\-?\d+)?\]?C\[?(\-?\d+)?\]?/gmi.exec(string_val);
        ref_match = null; // DEBUG
        if (ref_match !== null) {
          var row_shift = (ref_match[1] !== undefined) ? parseInt(ref_match[1]) : 0;
          var col_shift = (ref_match[2] !== undefined) ? parseInt(ref_match[2]) : 0;
          var new_cell_ref = this.get_shifted_cell_name(cell_record_obj.cell_name, row_shift,col_shift);
          var new_cell_ref_full = cell_record_obj.sheet_name + "!" + new_cell_ref;
          var cell_value2;

          if (document_obj.sheets[cell_record_obj.sheet_name].data.hasOwnProperty(new_cell_ref)) {
            cell_value2 = document_obj.sheets[cell_record_obj.sheet_name].data[new_cell_ref].value;
          } else {
            cell_value2 = "@" + cell_record_obj.sheet_name + "!" + new_cell_ref;
            cell_recalc = true;
            document_obj.recalc_objs.push(new_cell_ref_full);
          }

          formula_calc_stack.push({
            'value': cell_value2,
            'type':  "reference",
            'ref_name': new_cell_ref_full,
            'xname': "PtgString"
          });
        } else {
          if (string_val.length > 0 && document_obj.varables.hasOwnProperty(string_val)) {
            // Reference to a document variable
            var var_val = this.get_xls_var_ref(string_val, document_obj, file_info);

            formula_calc_stack.push({
              'value': var_val,
              'type':  "reference",
              'ref_name': string_val,
              'xname': "PtgString"
            });
          } else {
            formula_calc_stack.push({
              'value': string_val,
              'type':  "string",
              'xname': "PtgString"
            });
          }
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
          // PtgAttrSemi - Specifies that this Rgce is volatile.
          // See https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/615c5518-010a-4268-b71b-b60074bdb11b
          // next two bytes unused, should be zero
          current_rgce_byte += 3;
        } else if (rgce_bytes[current_rgce_byte] == 0x02) {
          // PtgAttrIf - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/d81e5fb4-3004-409a-9a31-1a60662d9e59
          var offset = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+1,current_rgce_byte+3), byte_order);
          current_rgce_byte += 3;
        } else if (rgce_bytes[current_rgce_byte] == 0x04) {
          // PtgAttrChoose - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/24fb579c-c65d-4771-94a8-4380cecdc8c8
          var c_offset = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+1,current_rgce_byte+3), byte_order) + 1;
          var rgOffset_bytes = rgce_bytes.slice(current_rgce_byte+3,current_rgce_byte+3+c_offset);
          current_rgce_byte += 3 + c_offset;
        } else if (rgce_bytes[current_rgce_byte] == 0x08) {
          // PtgAttrGoto - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/081e17b9-02a6-4e78-ad28-09538f35a312
          var offset = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+1,current_rgce_byte+3), byte_order);
          current_rgce_byte += 3;
        } else if (rgce_bytes[current_rgce_byte] == 0x10) {
          // PtgAttrSum - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/79ef57f6-27ab-4fec-b893-7dd727e771d1
          // next two bytes unused, should be zero
          current_rgce_byte += 3;
        } else if (rgce_bytes[current_rgce_byte] == 0x20 || rgce_bytes[current_rgce_byte] == 0x21) {
          // PtgAttrBaxcel - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/fcd76e10-6072-4dcf-b591-47edc8822792
          // This is my implementaiton, not based on MS / Excel.
          var baxcel_bits = this.get_bin_from_int(rgce_bytes[current_rgce_byte+1]);
          var is_volatile = (baxcel_bits[0] == 1) ? true : false;

          formula_calc_stack.push({
            'value': "=",
            'type':  "operator",
            'volatile': is_volatile,
            'xname': "PtgAttrBaxcel"
          });
          // next two bytes unused, should be zero
          current_rgce_byte += 3;
        } else if (rgce_bytes[current_rgce_byte] == 0x40) {
          // PtgAttrSpace - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/38a4d7be-040b-4206-b078-62f5aeec72f3
          var ptg_attr_space_type = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+1,current_rgce_byte+3), byte_order);
          current_rgce_byte += 3;
        } else if (rgce_bytes[current_rgce_byte] == 0x41) {
          // PtgAttrSpaceSemi - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/5d8c3df5-9be5-46d9-8105-a1a19ceca3d4
          var type = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+1,current_rgce_byte+3), byte_order);
          current_rgce_byte += 3;
        } else {
          // error
          current_rgce_byte += 1;
        }
      } else if (formula_type == 0x1D) {
        // Selection - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/00131ced-fe32-403b-9be4-d9c234fde7d4
        //TODO this is incomplete.
        var pane_type = rgce_bytes[current_rgce_byte];
        var ac_row = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+1,current_rgce_byte+3), byte_order);
        var ac_col = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+3,current_rgce_byte+5), byte_order);
        var ref_u_index = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+5,current_rgce_byte+7), byte_order);
        var cref = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+7,current_rgce_byte+9), byte_order);

        current_rgce_byte += 9;
      } else if (formula_type == 0x1E) {
        // PtgInt - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/508ecf18-3b81-4628-95b3-7a9d2a295bca
        var ptg_int_val = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte,current_rgce_byte+2), byte_order);
        formula_calc_stack.push({
          'value': ptg_int_val,
          'type':  "number",
          'xname': "PtgInt"
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
          'type':  "number",
          'xname': "PtgNum"
        });

        current_rgce_byte += 8;
      } else if (formula_type == 0x23) {
        // PtgName - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/5f05c166-dfe3-4bbf-85aa-31c09c0258c0
        // reference to a defined name
        var var_index = Static_File_Analyzer.get_four_byte_int(rgce_bytes.slice(current_rgce_byte,current_rgce_byte+4), byte_order);

        if (var_index-1 < document_obj.defined_names.length) {
          var var_name = document_obj.defined_names[var_index-1];

          if (document_obj.varables.hasOwnProperty(var_name.name)) {
            var var_value = this.get_xls_var_ref(var_name.name, document_obj, file_info);
            var var_type = typeof var_value;

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
              'ref_name': var_name.name,
              'xname': "PtgName"
            });
          } else {
            formula_calc_stack.push({
              'value': var_name.name,
              'type':  "string",
              'xname': "PtgName"
            });
          }

          current_rgce_byte += 4;
        } else {
          current_rgce_byte += 1;
        }
      } else if (formula_type == 0x24 || formula_type == 0x44) {
        // PtgRef - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/fc7c380b-d793-4219-a897-e47e13c4e055
        // The PtgRef operand specifies a reference to a single cell in this sheet.
        var loc_row = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte,current_rgce_byte+2), byte_order);
        var col_rel = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+2,current_rgce_byte+4), byte_order);
        var col_rel_bits = this.get_bin_from_int(col_rel);
        var loc_col = this.get_int_from_bin(col_rel_bits.slice(0,13));
        var is_col_relative = (col_rel_bits[14] == 1) ? true : false;
        var is_row_relative = (col_rel_bits[15] == 1) ? true : false;

        var cell_ref = this.convert_xls_column(loc_col) + (loc_row+1);
        var spreadsheet_obj = document_obj.sheets[cell_record_obj.sheet_name];
        var full_cell_name = cell_record_obj.sheet_name + "!" + cell_ref;

        var ref_cell_obj = this.get_xls_cell_ref(cell_ref, cell_record_obj.sheet_name, document_obj, cell_record_obj, file_info, byte_order);
        cell_formula += cell_record_obj.sheet_name + "!" + cell_ref;

        // Check to what the next rgce_byte is, as that will affect what action is taken.
        if (rgce_bytes[current_rgce_byte+6] == 0x60) {
          // Put reference
          // Calculate the stack.
          var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;

          if (stack_result !== null && stack_result !== undefined && (typeof stack_result) == "string") {
            stack_result = stack_result.replaceAll(/\\?[\"\']&\\?[\"\']/gm, "");

            if (stack_result.charAt(0) == "=") {
              // This is an Excel formula or macro
              var c_formula_name = stack_result.split("(")[0].toUpperCase();

              if (c_formula_name == "=CALL" || c_formula_name == "=EXEC" || c_formula_name == "=IF") {
                file_info.scripts.script_type = "Excel 4.0 Macro";

                var at_ref_match = /@([a-zA-Z0-9]+\![a-zA-Z]+[0-9]+)/gmi.exec(stack_result);

                if (at_ref_match === null) {
                  if (stack_result != c_formula_name) {
                    this.add_extracted_script("Excel 4.0 Macro", stack_result, file_info);
                  }
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
                file_info = Static_File_Analyzer.search_for_iocs(stack_result, file_info);
              }
            }
          }

          cell_value = (cell_value === null) ? stack_result : cell_value + stack_result;

          spreadsheet_obj.data[cell_ref] = {
            'value': cell_value,
            'formula': cell_formula,
            'xname': "PtgRef"
          }

          formula_calc_stack.shift();
          current_rgce_byte += 8;
        } else {
          // Get reference
          formula_calc_stack.push(ref_cell_obj);
          current_rgce_byte += 4;
        }
      } else if (formula_type == 0x41 || formula_type == 0x21) {
        // PtgFunc - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/87ce512d-273a-4da0-a9f8-26cf1d93508d
        var ptg_bits = this.get_bin_from_int(rgce_bytes[current_rgce_byte-1]);
        var iftab = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte,current_rgce_byte+2), byte_order);

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
          // See - https://xlladdins.github.io/Excel4Macros/absref.html
          formula_calc_stack.push({
            'value':  "_xlfn.ABSREF",
            'type':   "string",
            'params': 2
          });
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

          var cell_formula_prov = "=CHAR(" + formula_calc_stack.at(-2).value + ")";
          var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);

          if (formula_calc_stack.at(-1).hasOwnProperty("formula")) {
            cell_formula += formula_calc_stack.at(-1).formula;
          } else {
            cell_formula += cell_formula_prov;
          }

          cell_value = (cell_value === null) ? "" : cell_value;
          cell_value += formula_calc_stack.at(-1).value;
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
        } else if (iftab == 0x00A7) {
          // IPMT - https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/ipmt-function
          console.log("IPMT function not implemented.");
        } else if (iftab == 0x00AC) {
          // WHILE
          formula_calc_stack.push({
            'value': "_xlfn.WHILE",
            'type':  "string",
            'params': 1
          });
        } else if (iftab == 0x00AE) {
          // NEXT
          formula_calc_stack.push({
            'value': "_xlfn.NEXT",
            'type':  "string",
            'params': 0
          });

          var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
          cell_formula = stack_result.formula;
          cell_value = (cell_value === null) ? stack_result.value : cell_value + stack_result.value;
        } else if (iftab == 0x00E1) {
          // End IF
          formula_calc_stack.push({
            'value': "_xlfn.END.IF",
            'type':  "string",
            'params': 0
          });

          var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
          cell_formula = stack_result.value;
          cell_value = (cell_value === null) ? stack_result.value : cell_value + stack_result.value;
        } else {
          // Non implemented function
          console.log("Unknown function " + iftab); // DEBUG
        }

        current_rgce_byte += 2;
      } else if (formula_type == 0x42) {
        // PtgFuncVar - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/5d105171-6b73-4f40-a7cd-6bf2aae15e83
        var param_count = rgce_bytes[current_rgce_byte];
        var tab_bits = Static_File_Analyzer.get_binary_array(rgce_bytes.slice(current_rgce_byte+1,current_rgce_byte+3));
        var tab_int = rgce_bytes[current_rgce_byte+1];
        var tab_int2 = this.get_int_from_bin(tab_bits.slice(0,15), document_obj.byte_order);
        var exec_stack = true;
        current_rgce_byte += 3;

        if (tab_bits[8] == 0) {
          // Ftab value - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/00b5dd7d-51ca-4938-b7b7-483fe0e5933b
          if (tab_int == 0x00) {
            // COUNT
            formula_calc_stack.push({
              'value':  "_xlfn.COUNT",
              'type':   "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });
          } else if (tab_int == 0x01) {
            // IF
            formula_calc_stack.push({
              'value':  "_xlfn.IF",
              'type':   "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });
          } else if (tab_int == 0x1A) {
            // SIGN - https://support.microsoft.com/en-us/office/sign-function-109c932d-fcdc-4023-91f1-2dd0e916a1d8
            formula_calc_stack.push({
              'value':  "_xlfn.SIGN",
              'type':   "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });
          } else if (tab_int == 0x36) {
            // HALT
            formula_calc_stack.push({
              'value':  "_xlfn.HALT",
              'type':   "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });

            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
            cell_formula = stack_result.formula;
            cell_value = stack_result.value;
          } else if (tab_int == 0x37) {
            // RETURN
            formula_calc_stack.push({
              'value':  "_xlfn.RETURN",
              'type':   "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });

            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
            cell_formula = stack_result.formula;
            cell_value = stack_result.value;
          } else if (tab_int == 0x58) {
            // SET.NAME
            formula_calc_stack.push({
              'value':  "_xlfn.SET.NAME",
              'type':   "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });

            if (cell_formula.length > 0) {
              for (var ci=0; ci<formula_calc_stack.length; ci++) {
                if (formula_calc_stack[ci].hasOwnProperty("ref_name")) {
                   if (cell_formula.indexOf(formula_calc_stack[ci].ref_name) >= 0) {
                     cell_formula = cell_formula.replaceAll(formula_calc_stack[ci].ref_name, "");
                   }
                }
              }
            }

            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
            cell_formula += stack_result.formula;
            cell_value = (cell_value === null) ? stack_result.value : cell_value + stack_result.value;
          } else if (tab_int == 0x6C) {
            // STDEVPA - Calculates standard deviation
          } else if (tab_int == 0x6E) {
            // EXEC
            formula_calc_stack.push({
              'value':  "_xlfn.EXEC",
              'type':   "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });

            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
            file_info.scripts.script_type = "Excel 4.0 Macro";
            file_info = this.analyze_excel_macro(file_info, document_obj.sheets, stack_result.value);
          } else if (tab_int == 0x6F) {
            // CHAR
            formula_calc_stack.push({
              'value':  "_xlfn.CHAR",
              'type':   "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });

            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
          } else if (tab_int == 0x80) {
            // ISNUMBER
            formula_calc_stack.push({
              'value':  "_xlfn.ISNUMBER",
              'type':   "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });
          } else if (tab_int == 0x95) {
            // REGISTER
            formula_calc_stack.push({
              'value':  "_xlfn.REGISTER",
              'type':   "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });

            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
            this.add_extracted_script("Excel 4.0 Macro", stack_result.value, file_info);
            cell_formula = stack_result.formula;
          } else if (tab_int == 0xA7) {
            // IPMT - https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/ipmt-function
            formula_calc_stack.push({
              'value':  "_xlfn.IPMT",
              'type':   "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });

            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
            cell_formula = stack_result.formula;
          } else if (tab_int == 0xA9) {
            // COUNTA - counts the number of cells that are not empty in a range.
            // https://support.microsoft.com/en-us/office/counta-function-7dc98875-d5c1-46f1-9a82-53f3219e2509
            formula_calc_stack.push({
              'value':  "_xlfn.COUNTA",
              'type':   "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });
          } else if (tab_int == 0xE1) {
            // END.IF
            formula_calc_stack.push({
              'value': "_xlfn.END.IF",
              'type':  "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });

            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
            cell_formula = stack_result.value;
            cell_value = (cell_value === null) ? stack_result.value : cell_value + stack_result.value;
          } else if (tab_int == 0xFF) {
            // User Defined Function
            formula_calc_stack.push({
              'value': "_xlfn.USERFUNCTION",
              'type':  "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });

            exec_stack = false;
          } else {
            console.log("Unknown PtgFuncVar: " + tab_int); // DEBUG
          }
        } else {
          // Cetab value - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/0b8acba5-86d2-4854-836e-0afaee743d44
          if (tab_int2 == 0x01C3) {
            formula_calc_stack.push({
              'value': "_xlfn.ADD.LIST.ITEM",
              'type':  "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });
          } else if (tab_int == 0x00A7) {
            // Calculates only the active worksheet. - https://xlladdins.github.io/Excel4Macros/calculate.document.html
            formula_calc_stack.push({
              'value': "_xlfn.CALCULATE.DOCUMENT",
              'type':  "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });

            var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
            cell_formula = stack_result.formula;
            cell_value = (cell_value === null) ? stack_result.value : cell_value + stack_result.value;
          } else if (tab_int == 0x0000) {
            formula_calc_stack.push({
              'value': "_xlfn.BEEP",
              'type':  "string",
              'params': param_count,
              'xname': "PtgFuncVar"
            });
          } else {
            console.log("Unknown PtgFuncVar - Cetab: " + tab_int); // DEBUG
          }
        }

        if (exec_stack == true) {
          // Execute formula_calc_stack
          for (var c=0; c<formula_calc_stack.length; c++) {
            if (param_count == 1 && formula_calc_stack.length > 1) {
              function_name = "";
              var stack_result = {};
              // Execute the stack, if it's length is greater than 1.
              if (formula_calc_stack.length > 1) {
                stack_result = this.execute_excel_stack(formula_calc_stack, document_obj);
                cell_value = (cell_value === null) ? stack_result.value : cell_value + stack_result.value;
              }

              if (stack_result.hasOwnProperty("formula") && stack_result.formula != "") {
                cell_formula += stack_result.formula;
              } else {
                cell_formula += function_name + "(" + cell_formula + ")";
              }

              break;
            } else if (param_count >= 2) {
              if (formula_calc_stack[c].value !== null && formula_calc_stack[c].value !== undefined && formula_calc_stack[c].value.length > 0) {
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
        }

      } else if (formula_type == 0x43) {
        // PtgName - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/5f05c166-dfe3-4bbf-85aa-31c09c0258c0
        var ptg_bits = this.get_bin_from_int(rgce_bytes[current_rgce_byte-1]);

        // PtgDataType - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/80d504ba-eb5d-4a0f-a5da-3dcc792dd78e
        var data_type_int = this.get_int_from_bin(ptg_bits.slice(5,7));
        var name_index = Static_File_Analyzer.get_four_byte_int(rgce_bytes.slice(current_rgce_byte,current_rgce_byte+4), byte_order);

        if (name_index <= document_obj.defined_names.length) {
          var ref_var_name = document_obj.defined_names[name_index-1];

          if (document_obj.varables.hasOwnProperty(ref_var_name.name)) {
            var var_val = this.get_xls_var_ref(ref_var_name.name, document_obj, file_info);

            formula_calc_stack.push({
              'value': var_val,
              'type':  "string",
              'ref_name': ref_var_name.name,
              'xname': "PtgName"
            });

          } else {
            // Probably definning the variable
            formula_calc_stack.push({
              'value': ref_var_name.name,
              'type':  "reference",
              'ref_name': ref_var_name.name,
              'xname': "PtgName"
            });
          }
        } else {
          // error looking up varable.
        }

        current_rgce_byte += 4;
      } else if (formula_type == 0x5A) {
        // PtgRef3d - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/1ca817be-8df3-4b80-8d35-46b5eb753577
        // The PtgRef3d operand specifies a reference to a single cell on one or more sheets.
        var ixti = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte,current_rgce_byte+2), byte_order);
        var loc_row = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+2,current_rgce_byte+4), byte_order);
        var col_rel = Static_File_Analyzer.get_two_byte_int(rgce_bytes.slice(current_rgce_byte+4,current_rgce_byte+6), byte_order);
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

        if (ref_sheet_name !== null && ref_sheet_name !== undefined && ref_sheet_name != "") {
          var ref_cell_obj = this.get_xls_cell_ref(cell_ref, ref_sheet_name, document_obj, cell_record_obj, file_info, byte_order);
          formula_calc_stack.push(ref_cell_obj);
          cell_formula += ref_sheet_name + "!" + cell_ref;
        } else {
          var this_cell_name_full = cell_record_obj.sheet_name + "!" + cell_record_obj.cell_name;
          if (!document_obj.recalc_objs.includes(this_cell_name_full)) document_obj.recalc_objs.push(this_cell_name_full);
        }

        current_rgce_byte += 6;
      } else if (formula_type == 0x60) {
        // PtgArray - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/61167ac8-b0ca-42e5-b82c-41a25d12324c
        var data_type = this.get_bin_from_int(formula_type).slice(5,7);

        formula_calc_stack.push({
          'value': "[]",
          'type':  "operator",
          'xname': "PtgArray"
        });

        current_rgce_byte += 1;
      } else {
        // Non implemented formula_type
        console.log("Unknown formula_type " + formula_type); // DEBUG
      }
    }

    if (formula_calc_stack.length > 0 && cell_value === null) {
      if (formula_calc_stack.length > 1) {
        var stack_result = this.execute_excel_stack(formula_calc_stack, document_obj).value;

        if (((typeof stack_result) == "string") && stack_result.indexOf("=CALL") >= 0) {
          this.add_extracted_script("Excel 4.0 Macro", stack_result, file_info);
          let analyzed_results = this.analyze_embedded_script(stack_result);

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
      }

      cell_value = formula_calc_stack[0].value;
      cell_formula = (formula_calc_stack[0].hasOwnProperty("formula")) ? formula_calc_stack[0].formula : cell_formula;
    }

    if (formula_calc_stack.length > 0 && formula_calc_stack[0].hasOwnProperty("subroutine") && formula_calc_stack[0].subroutine == true) {
      // This is a user function / subroutine.
      // Execute cell functions one by one until a REUTRN or HALT funciton is found.
      if (formula_calc_stack[0].hasOwnProperty("ref_name")) {
        var cell_skip_count = 0;
        var function_complete = false;
        var loop_stack = [];
        var next_cell_name = formula_calc_stack[0].ref_name;
        var ref_cell_raw;
        var ref_cell_data_obj;
        var skip_formula = false;


        while (next_cell_name != null) {
          if (document_obj.indexed_cells.hasOwnProperty(next_cell_name)) {
            ref_cell_raw = document_obj.indexed_cells[next_cell_name];

            if (ref_cell_raw.record_type == "Formula") {
              if (skip_formula == false) {
                ref_cell_data_obj = this.parse_xls_formula_record(ref_cell_raw, document_obj, file_info, byte_order);

                if (ref_cell_data_obj.cell_data.formula.startsWith("=WHILE")) {
                  if (ref_cell_data_obj.cell_data.value == true) {
                    loop_stack.push(ref_cell_raw);
                  } else {
                    // We need to skip code until a =NEXT() is found.
                    skip_formula = true;
                  }

                } else if (ref_cell_data_obj.cell_data.formula.startsWith("=NEXT")) {
                  var loop_start_cell = loop_stack.pop();
                  var loop_start_cell_obj = this.parse_xls_formula_record(loop_start_cell, document_obj, file_info, byte_order);

                  if (loop_start_cell_obj.cell_data.value == true) {
                    loop_stack.push(loop_start_cell);
                    ref_cell_raw = loop_start_cell;
                    ref_cell_data_obj = loop_start_cell_obj;
                  }
                }

              } else {
                // Look for END.IF
                var next_formula = ref_cell_raw.record_bytes[22];

                if (next_formula == 0x41 || next_formula== 0x21) {
                  var iftab = Static_File_Analyzer.get_two_byte_int(ref_cell_raw.record_bytes.slice(23,24), byte_order);
                  // TODO: This won't work if there is an IF inside of a loop.

                  if (iftab == 0x00AE) {
                    // Next()
                    skip_formula = false;
                    ref_cell_data_obj = {'cell_data': {'formula': "=NEXT()"}};
                  } else if (iftab == 0x00E1) {
                    // END.IF found
                    skip_formula = false;
                    ref_cell_data_obj = {'cell_data': {'formula': "=END.IF()"}};
                  }
                } else if (next_formula == 0x42) {
                  var tab_int = rgce_bytes[23];

                  if (tab_int == 0xE1) {
                    // END.IF found
                    skip_formula = false;
                    ref_cell_data_obj = {'cell_data': {'formula': "=END.IF()"}};
                  }
                }
              }

              if (ref_cell_data_obj.cell_data.formula == "=HALT()" || ref_cell_data_obj.function_complete) {
                function_complete = true;
                break; // User function is complete.
              } else {
                // Get the next cell down
                next_cell_name = ref_cell_raw.sheet_name + "!" + this.get_shifted_cell_name(ref_cell_raw.cell_name, 1, 0);

                if (ref_cell_data_obj.cell_data.formula.startsWith("=IF") && ref_cell_data_obj.cell_data.value == false) {
                  skip_formula = true;
                } else if (skip_formula == true && ref_cell_data_obj.cell_data.formula == "=END.IF()") {
                  skip_formula = false;
                }

              }
            } else {
              cell_formula = "=HALT()";
              function_complete = true;
              break;
            }
          } else {
            var cell_name_parts = next_cell_name.split("!");
            next_cell_name = cell_name_parts[0] + "!" + this.get_shifted_cell_name(cell_name_parts[1], 1, 0);
            cell_skip_count++;

            // A count of 99 is arbitrary to prevent an infinite loop.
            if (cell_skip_count > 99) {
              cell_formula = "=HALT()";
              function_complete = true;
              break;
            }
          }
        }

      }
    }

    return {
      'sheet_name': cell_record_obj.sheet_name,
      'cell_name': cell_record_obj.cell_name,
      'cell_recalc': cell_recalc,
      'function_complete': function_complete,
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
  parse_xls_label_set_record(cell_record_obj, string_constants, byte_order=Static_File_Analyzer.LITTLE_ENDIAN) {
    var bytes = cell_record_obj.record_bytes;

    var cell_row  = Static_File_Analyzer.get_two_byte_int(bytes.slice(0, 2), byte_order) + 1;
    var cell_col  = Static_File_Analyzer.get_two_byte_int(bytes.slice(2, 4), byte_order);
    var cell_ref  = this.convert_xls_column(cell_col) + cell_row;

    var cell_ixfe = Static_File_Analyzer.get_two_byte_int(bytes.slice(4, 6), byte_order);

    var isst = Static_File_Analyzer.get_four_byte_int(bytes.slice(6, 10), byte_order);
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
  parse_xls_rk_record(cell_record_obj, byte_order=Static_File_Analyzer.LITTLE_ENDIAN) {
    var bytes = cell_record_obj.record_bytes;

    var cell_row  = Static_File_Analyzer.get_two_byte_int(bytes.slice(0, 2), byte_order) + 1;
    var cell_col  = Static_File_Analyzer.get_two_byte_int(bytes.slice(2, 4), byte_order);
    var cell_ref  = this.convert_xls_column(cell_col) + cell_row;

    var cell_ixfe = Static_File_Analyzer.get_two_byte_int(bytes.slice(4, 6), byte_order);
    var rk_number_bits = Static_File_Analyzer.get_binary_array(bytes.slice(6, 10), byte_order);
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
  read_dbcell_records(file_bytes, document_obj, byte_order=Static_File_Analyzer.LITTLE_ENDIAN) {
    // Find workbook entry
    var cell_records = [];
    var sheet_name = "";

    for (var i=512; i<file_bytes.length; i++) {
      if (file_bytes[i] == 0xD7 && file_bytes[i+1] == 0x00 && file_bytes[i+3] == 0x00) {
        var record_size1 = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(i+2,i+4), byte_order);
        var first_row_record = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(i+4, i+8), byte_order);
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

            var record_size = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(cell_record_pos, cell_record_pos+2), byte_order);
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
              cell_row = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(cell_record_pos, cell_record_pos+2), byte_order) + 1;
              cell_col = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(cell_record_pos+2, cell_record_pos+4), byte_order);
              cell_record_pos += record_size;
            } else if (record_type_bytes[0] == 0x07 && record_type_bytes[1] == 0x02) {
              // String - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/504b6cfc-d57b-4296-92f4-ceefc0a2ca9b
              // This is probably the pre-calculated cell vaue of the previous cell.
              record_type_str = "String";
              cell_record_pos += record_size;
            } else if (record_type_bytes[0] == 0x06 && record_type_bytes[1] == 0x00) {
              // Cell Formula - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/8e3c6978-6c9f-4915-a826-07613204b244
              record_type_str = "Formula";
              cell_row = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(cell_record_pos, cell_record_pos+2), byte_order) + 1;
              cell_col = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(cell_record_pos+2, cell_record_pos+4), byte_order);
              cell_record_pos += record_size;
            } else if (record_type_bytes[0] == 0x7E && record_type_bytes[1] == 0x02) {
              // RK - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/656e0e79-8b9d-4854-803f-23ec62080678
              // The RK record specifies the numeric data contained in a single cell.
              record_type_str = "RK";
              cell_row = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(cell_record_pos, cell_record_pos+2), byte_order) + 1;
              cell_col = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(cell_record_pos+2, cell_record_pos+4), byte_order);
              cell_record_pos += record_size;
            } else if (record_type_bytes[0] == 0xBE && record_type_bytes[1] == 0x00) {
              // MulBlank - https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/a9ab7fa1-183a-487c-a506-6b4a19e770be
              // These are blank cells
              record_type_str = "MulBlank";
              cell_record_pos += record_size;
            } else {
              // Unknown record
              var u_rec_int = Static_File_Analyzer.get_two_byte_int([record_type_bytes[0],record_type_bytes[1]], byte_order);
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
  static search_for_iocs(search_text, file_json) {
    var found_urls = Static_File_Analyzer.search_for_url(search_text);

    for (var i=0; i<found_urls.urls.length; i++) {
      if (!file_json.iocs.includes(found_urls.urls[i]) && found_urls.urls[i] != "\\\\.") {
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
  static search_for_url(search_text) {
    var found_urls = [];
    var findings = [];

    var url_regex = /((?:https?\:\/\/|\\\\)[a-zA-Z0-9\.\/\-\:\_\~\?\#\[\]\@\!\$\&\(\)\*\+\%\=]+(?:(?<=\&amp)\;[a-zA-Z0-9\.\/\-\:\_\~\?\#\[\]\@\!\$\&\(\)\*\+\%\=]*)*)/gmi;
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

// Compound File Binary a.k.a. Old Office Document format.
class CFB_Parser {

  /**
   * Parses a Compound File Binary CFB file.
   *
   * @param  {String} bytes An array of integers representing bytes.
   * @return {Object} The parsed CDB as a JSON object.
   */
  static parse(file_bytes) {
    let cmb_obj = {
      byte_order: "LITTLE_ENDIAN",
      format_version_major: 0,
      format_version_minor: 0,
      sector_size: 512,
      entries: [],
      root_entry: {
        guid: "00000000-0000-0000-0000-000000000000",
        start_block: 0
      }
    };

    if (Static_File_Analyzer.array_equals(file_bytes.slice(0,4), [0xD0,0xCF,0x11,0xE0])) {
      var current_byte = 0;
      var compound_file_binary_minor_ver_bytes = file_bytes.slice(24,26);
      var compound_file_binary_major_ver_bytes = file_bytes.slice(26,28);

      if (Static_File_Analyzer.array_equals(compound_file_binary_major_ver_bytes, [3,0])) {
        cmb_obj.format_version_major = "3";
      } else if (Static_File_Analyzer.array_equals(compound_file_binary_major_ver_bytes, [4,0])) {
        cmb_obj.format_version_major = "4";
      }

      if (compound_file_binary_minor_ver_bytes[0] == 62) cmb_obj.format_version_minor = "3E";

      // Byte order LITTLE_ENDIAN or BIG_ENDIAN
      var byte_order_bytes = file_bytes.slice(28,30);
      cmb_obj.byte_order = (byte_order_bytes[1] == 255) ? "LITTLE_ENDIAN" : "BIG_ENDIAN";

      //Sector size will indicate where the beginning of file record starts.
      var sector_size_bytes = file_bytes.slice(30,32);
      if (Static_File_Analyzer.array_equals(sector_size_bytes, [9,0])) {
        cmb_obj.sector_size = 512;
      } else if (Static_File_Analyzer.array_equals(sector_size_bytes, [12,0])) {
        cmb_obj.sector_size = 4096;
      } else {
        cmb_obj.sector_size = 512;
      }

      var number_of_directory_sectors = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(40,44), cmb_obj.byte_order);
      var number_of_sectors = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(44,48), cmb_obj.byte_order);
      var sec_id_1 = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(48,52), cmb_obj.byte_order);
      var min_stream_size = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(56,60), cmb_obj.byte_order);
      var short_sec_id_1 = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(60,64), cmb_obj.byte_order);
      var number_of_short_sectors = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(64,68), cmb_obj.byte_order);
      var master_sector_id_1 = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(68,72), cmb_obj.byte_order);
      var number_of_master_sectors = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(72,76), cmb_obj.byte_order);
      var difat_bytes = file_bytes.slice(76,512);
      var difat_index = Array();
      var difat_loc = Array();

      // Index file byte locations of objects
      for (var di=0; di<difat_bytes.length; di+=4) {
        var di_index = Static_File_Analyzer.get_int_from_bytes(difat_bytes.slice(di,di+4), cmb_obj.byte_order);
        if (di_index != 4294967295) {
          difat_index.push(di_index);

          var di_location = (di_index + 1) * cmb_obj.sector_size;
          difat_loc.push(di_location);
        }
      }

      // Read short sectors chain.
      let last_offset_int = 0;
      let short_sectors = [];
      let offset_ints = [];
      let start_index = short_sec_id_1;
      let short_sec_length = (cmb_obj.sector_size / 4);

      for (let i2=0; i2<number_of_short_sectors; i2++) {
        short_sectors.push(start_index);

        let current_block = Math.floor(start_index / short_sec_length);
        let current_block_index = start_index % short_sec_length;
        let start_block_offset = difat_index[current_block];

        let start_offset = (start_block_offset + 1) * cmb_obj.sector_size;

        // Read 32-bit integers
        for (let o=start_offset; o<(start_offset+(short_sec_length*4)); o+=4) {
          offset_ints.push(Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(o,o+4), cmb_obj.byte_order));
        }

        start_index = offset_ints[start_index];
      }

      // Proccess DIFAT Array?
      for (var di=0; di<difat_loc.length; di++) {
        var next_sector = file_bytes.slice(difat_loc[di], difat_loc[di]+4);

        if (Static_File_Analyzer.array_equals(next_sector, [0xFA,0xFF,0xFF,0xFF])) {
          // MAXREGSECT
        } else if (Static_File_Analyzer.array_equals(next_sector, [0xFB,0xFF,0xFF,0xFF])) {
          // Reserved for future use
        } else if (Static_File_Analyzer.array_equals(next_sector, [0xFC,0xFF,0xFF,0xFF])) {
          // DIFSECT
        } else if (Static_File_Analyzer.array_equals(next_sector, [0xFD,0xFF,0xFF,0xFF])) {
          // FATSECT
        } else if (Static_File_Analyzer.array_equals(next_sector, [0xFE,0xFF,0xFF,0xFF])) {
          // ENDOFCHAIN
        } else if (Static_File_Analyzer.array_equals(next_sector, [0xFF,0xFF,0xFF,0xFF])) {
          // FREESECT
        }
      }

      // Sector #1 - The Directory Sector, four entries.
      var sec_1_pos = 512 + (sec_id_1 * cmb_obj.sector_size); // Should be Root Entry
      var next_directory_entry = sec_1_pos;

      for (let i=0; i<4; i++) {
        let enrty_obj = CFB_Parser.parse_stream_entry(file_bytes.slice(next_directory_entry, next_directory_entry+128), cmb_obj.byte_order);

        switch (enrty_obj.entry_type) {
          case 0:
            enrty_obj.sector_type = "Empty Sector";
            break;
          case 1:
            enrty_obj.sector_type = "Directory Sector";
            break;
          case 2:
            enrty_obj.sector_type = "User Stream Sector";
            break;
          case 3:
            enrty_obj.sector_type = "Locked Sector";
            break;
          case 4:
            enrty_obj.sector_type = "Property Sector";
            break;
          case 4:
            enrty_obj.sector_type = "Root Sector";
            break;
        }

        if (enrty_obj.entry_name == "Root Entry") {
          cmb_obj.root_entry.guid = enrty_obj.entry_guid;
          cmb_obj.root_entry.start_block = enrty_obj.start_block;
          cmb_obj.root_entry.obj = enrty_obj;
        }

        if (offset_ints[last_offset_int] < 0xFFFFFFA0) {
          last_offset_int = offset_ints[last_offset_int];
        } else {
          last_offset_int++;
        }

        if (enrty_obj !== null) cmb_obj.entries.push(enrty_obj);

        next_directory_entry += 128;
      }

      last_offset_int = 4; // Four entries already read.

      // Sector #2 - The MiniFAT Sector
      let current_sec_byte = next_directory_entry;
      let sectors = [];
      for (let i=0; i<128; i++) {
        let sector_block = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(current_sec_byte,  current_sec_byte+=4), cmb_obj.byte_order);
        sectors.push(sector_block);
      }

      let next_offset = 2048 + (last_offset_int * 128);
      let mini_stream_Start = current_sec_byte;
      next_directory_entry = current_sec_byte;

      // Sector #3 - The Mini Stream Sector
      while (Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(next_directory_entry, next_directory_entry+4)) <  0xfaffffff && next_directory_entry < file_bytes.length) {
        let enrty_obj = CFB_Parser.parse_stream_entry(file_bytes.slice(next_directory_entry, next_directory_entry+128), cmb_obj.byte_order);

        if (enrty_obj !== null) {
          enrty_obj.sector_type = "Mini Stream";
          cmb_obj.entries.push(enrty_obj);
        }

        next_directory_entry += 128;

        if (Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(next_directory_entry, next_directory_entry+4)) >= 0xfaffffff) {
          next_directory_entry += 128;

          while (Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(next_directory_entry, next_directory_entry+4)) != 0x5f005f00 && next_directory_entry < file_bytes.length) {
            next_directory_entry += 128;
          }
        }
      }

      // Create Property Hierarchy
      CFB_Parser.create_property_hierarchy(cmb_obj.entries, cmb_obj.root_entry.obj);

      for (let i=0; i<cmb_obj.entries.length; i++) {
        let entry_byte_start = 0;
        if (cmb_obj.entries[i].stream_size < 4096) {
          let chain = CFB_Parser.get_chain_by_block(file_bytes, cmb_obj.entries[i].start_block, difat_index, cmb_obj.sector_size, cmb_obj.byte_order);

          if (chain.length == 1) {
            entry_byte_start = CFB_Parser.get_block_byte_start(file_bytes, cmb_obj.entries, difat_index, cmb_obj.entries[i].start_block, cmb_obj.sector_size, cmb_obj.byte_order);
            cmb_obj.entries[i].entry_start = entry_byte_start;
            cmb_obj.entries[i].entry_bytes = file_bytes.slice(cmb_obj.entries[i].entry_start, cmb_obj.entries[i].entry_start + cmb_obj.entries[i].stream_size);
          } else {
            if (cmb_obj.entries[i].stream_size > 0) {
              let result_data = new Int8Array(cmb_obj.entries[i].stream_size);
              let copied_byte_count = 0;
              let idx = 0;

              for (let i2 = 0; i2 < chain.length; i2++) {
                entry_byte_start = CFB_Parser.get_block_byte_start(file_bytes, cmb_obj.entries, difat_index, chain[i2], cmb_obj.sector_size, cmb_obj.byte_order);
                let data = file_bytes.slice(entry_byte_start, entry_byte_start+64);

                for (let j = 0; j < data.length; j++) {
                  result_data[idx++] = data[j];
                  copied_byte_count++;
                }
              }

              if (copied_byte_count < cmb_obj.entries[i].stream_size) {
                entry_byte_start += 64;
                let bytes_to_copy = cmb_obj.entries[i].stream_size - copied_byte_count;
                let data = file_bytes.slice(entry_byte_start, entry_byte_start+bytes_to_copy);

                for (let j = 0; j < data.length; j++) {
                  result_data[idx++] = data[j];
                  copied_byte_count++;
                }

              }

              cmb_obj.entries[i].entry_bytes = Array.from(result_data).slice(0,cmb_obj.entries[i].stream_size);
            } else {
              cmb_obj.entries[i].entry_bytes = [];
            }


          }
        } else {
          entry_byte_start = (cmb_obj.entries[i].start_block + 1) * cmb_obj.sector_size;
          cmb_obj.entries[i].entry_start = entry_byte_start;
          cmb_obj.entries[i].entry_bytes = file_bytes.slice(cmb_obj.entries[i].entry_start, cmb_obj.entries[i].entry_start + cmb_obj.entries[i].stream_size);
        }
      }

    } else {
      throw "File Magic Number is not a CFB file.";
    }

    return cmb_obj;
  }

  /**
   * A quick, low resourse way to read the names of the first four directory sectors in a CFB file.
   *
   * @param {array}  file_bytes
   * @return {array} A String array of the first four directory sector names.
   */
  static parse_directory_sector_names(file_bytes) {
    let sector_names = [];

    // Byte order LITTLE_ENDIAN or BIG_ENDIAN
    let byte_order = (file_bytes[29] == 255) ? "LITTLE_ENDIAN" : "BIG_ENDIAN";

    //Sector size will indicate where the beginning of file record starts.
    let sector_size = (file_bytes[30] == 12) ? 4096 : 512;

    let sec_id_1 = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(48,52), byte_order);
    let sec_pos = 512 + (sec_id_1 * sector_size); // Should be Root Entry

    for (let i=0; i<4; i++) {
      sec_pos += (128 * i);
      let directory_name_bytes = file_bytes.slice(sec_pos, sec_pos+64);
      let directory_name_buf_size = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(sec_pos+64, sec_pos+66), byte_order);

      directory_name_bytes = directory_name_bytes.slice(0,directory_name_buf_size); //trim bytes to name length
      let directory_name = Static_File_Analyzer.get_string_from_array(directory_name_bytes.filter(i => i > 6));

      sector_names.push(directory_name);
    }

    return sector_names;
  }

  /**
   * A quick, low resourse way to parse the rood object GUID of a CFB file.
   *
   * @param {array}   file_bytes
   * @return {String} The root GUID.
   */
  static parse_root_guid(file_bytes) {
    // Byte order LITTLE_ENDIAN or BIG_ENDIAN
    let byte_order = (file_bytes[29] == 255) ? "LITTLE_ENDIAN" : "BIG_ENDIAN";

    //Sector size will indicate where the beginning of file record starts.
    let sector_size = (file_bytes[30] == 12) ? 4096 : 512;

    let sec_id_1 = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(48,52), byte_order);
    let root_pos = 512 + (sec_id_1 * sector_size); // Should be Root Entry
    let guid_bytes = file_bytes.slice(root_pos+80, root_pos+96);
    let guid = CFB_Parser.parse_guid(guid_bytes, byte_order);

    return guid;
  }

  /**
   * Returns a flat array of all children for and incliding a given child_id
   *
   * @param {array}   entries The list of entries for the CFB object.
   * @param {integer} child_id The child_id to start building the hierarchy from.
   * @return {array}  The array of children starting at the given child_id
   */
  static create_property_hierarchy(entries, prop_obj) {
    if (prop_obj === undefined || prop_obj === null) return;
    if (prop_obj.child_id >= 0xFFFFFFA0) return;

    prop_obj.children = [];
    let children = [prop_obj.child_id];

    while (children.length != 0) {
      let current_index = children.shift();
      let current = entries[current_index];

      if (current == null) continue;

      prop_obj.children.push(current_index);

      if (current.entry_type == 1) {
        CFB_Parser.create_property_hierarchy(entries, current);
      }

      if (current.left_sibling < 0xFFFFFFA0) {
        children.push(current.left_sibling);
      }

      if (current.right_sibling < 0xFFFFFFA0) {
        children.push(current.right_sibling);
      }
    }
  }

  /**
   * Returns the byte start within the file for a given byte offset.
   *
   * @param  {array} entries
   * @param  {array} block_offset_arr
   * @param  {integer} start_block
   * @param  {integer} block_size
   * @param  {String} byte_order
   * @return {integer} The byte offset
   */
  static get_block_byte_start(file_bytes, entries, block_offset_arr, start_block, block_size=512, byte_order="LITTLE_ENDIAN") {
    let small_block_size = block_size / 8;
    let byte_offset = start_block * small_block_size;
    let big_block_number = Math.floor(byte_offset / block_size);
    let big_block_offset = byte_offset % block_size;
    let root_prop = entries[0];
    let next_block = root_prop.start_block;

    for (var i = 0; i < big_block_number; i++) {
      let next_block_val = CFB_Parser.get_next_inner_block(file_bytes, next_block, block_offset_arr, false, block_size, byte_order);
      next_block = next_block_val;
    }

    let block_start = (next_block + 1) * block_size;
    let entry_start = block_start + big_block_offset;

    return entry_start;
  }

  /**
   * Chreates a chain of small blocks used to construct the full stream binary.
   *
   * @param  {integer} start_block      The starting block for the stream.
   * @param  {array}   block_offset_arr The array of block offsets parsed from the header.
   * @param  {integer} block_size       The block size of the CFB, default is 512.
   * @param  {String}  byte_order       The byte order for the CFB file, defaut is LITTLE_ENDIAN.
   * @return {array}   The chain of block offsets.
   */
  static get_chain_by_block(file_bytes, start_block, block_offset_arr, block_size=512, byte_order="LITTLE_ENDIAN") {
    var block_chain = [];
    var next_small_block = start_block;

    while (next_small_block < 0xFFFFFFA0) {
      block_chain.push(next_small_block);
      next_small_block = CFB_Parser.get_next_inner_block(file_bytes, next_small_block, block_offset_arr, true, block_size, byte_order);
    }

    return block_chain;
  }

  /**
   * Returns the next inner block offset
   *
   * @param  {integer} offset           Offset withing the block.
   * @param  {integer} block_offset_arr The array of block offsets parsed from the header.
   * @param  {boolean} build_chain      Flag to indicate if this being called to build a chain.
   * @param  {integer} block_size       The block size of the CFB, default is 512.
   * @param  {String}  byte_order       The byte order for the CFB file, defaut is LITTLE_ENDIAN.
   * @return {integer} The next block offset.
   */
  static get_next_inner_block(file_bytes, offset, block_offset_arr, build_chain=false, block_size=512, byte_order="LITTLE_ENDIAN") {
    let block_len = block_size / 4;
    let current_block = Math.floor(offset / block_len);
    let current_block_index = offset % block_len;
    let start_block_offset = block_offset_arr[current_block];

    let block_offset_byte = (start_block_offset + 1) * block_size;

    // Read 32-bit integers
    let offset_ints = [];
    for (let o=block_offset_byte; o<(block_offset_byte+(block_len*4)); o+=4) {
      offset_ints.push(Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(o,o+4), byte_order));
    }

    return offset_ints[current_block_index];
  }

  /**
   * Identifies the file type using a given CFB file.
   *
   * @param {array}  file_bytes
   * @return {String} A String indicating the file type.
   */
  static identify_file_type(file_bytes) {
    let file_type = "cfb";
    let sector_names = CFB_Parser.parse_directory_sector_names(file_bytes);

    if (sector_names[1].toLowerCase() == "__nameid_version1.0") {
      file_type = "msg";
    } else if (sector_names[1].toLowerCase() == "__properties_version1.0") {
      file_type = "msg";
    } else if (sector_names.indexOf("__substg1.0_001A001E") >= 0) {
      file_type = "msg";
    } else if (sector_names[1].toLowerCase() == "1table") {
      file_type = "doc";
    } else if (sector_names[2].toLowerCase() == "projectwm") {
      file_type = "ppt";
    } else if (sector_names[1].toLowerCase() == "workbook") {
      file_type = "xls";
    }

    return file_type;
  }

  /**
   * Parses a stream entry header.
   *
   * @param  {String} bytes An array of integers representing bytes.
   * @param {String}  endianness Value indicating how to interperate the bit order of the binary array. Default is LITTLE_ENDIAN.
   * @return {Object} The parsed stream entry header as a JSON object.
   */
  static parse_stream_entry(bytes, endianness = "LITTLE_ENDIAN") {
    let directory_name_bytes = bytes.slice(0, 64);
    let directory_name_buf_size = Static_File_Analyzer.get_int_from_bytes(bytes.slice(64,66), endianness);

    if (directory_name_buf_size == 0xFFFF) return null;

    //trim bytes to name length
    directory_name_bytes = directory_name_bytes.slice(0,directory_name_buf_size);
    let directory_name = Static_File_Analyzer.get_string_from_array(directory_name_bytes.filter(i => i > 6));

    if (directory_name === null) {
      return null;
    } else {
      directory_name = directory_name.trim();
    }

    // 0 - Empty, 1 - User storage, 2 - User Stream, 3 - LockBytes, 4 - Property, 5 - Root storage
    let entry_type = bytes[66];

    if (entry_type > 5) return null;

    let color_flag_int = bytes[67];
    let color_flag_str = color_flag_int == 0 ? "red" : "black";

    // < 0xFFFFFFF9 = Regular stream ID
    // 0xFFFFFFFA = MAXREGSID - Maximum regular stream ID.
    // 0xFFFFFFFF = NOSTREAM - No value
    let left_sibling_id = Static_File_Analyzer.get_int_from_bytes(bytes.slice(68, 72), endianness);
    let right_sibling_id = Static_File_Analyzer.get_int_from_bytes(bytes.slice(72, 76), endianness);
    let child_id = Static_File_Analyzer.get_int_from_bytes(bytes.slice(76, 80), endianness);
    if (child_id == 0xFFFFFFFF) child_id = -1;

    if (left_sibling_id == right_sibling_id && right_sibling_id == child_id) return null;

    // First four bytes of unique id are flipped?
    let guid = CFB_Parser.parse_guid(bytes.slice(80, 96), endianness);
    let state_bits = bytes.slice(96, 100);

    if (entry_type != 5 && Static_File_Analyzer.get_int_from_bytes(state_bits) != 0) {
      return null;
    }

    var creation_time = TNEF_Parser.get_eight_byte_date(bytes.slice(100, 108), endianness);
    var modification_time = TNEF_Parser.get_eight_byte_date(bytes.slice(108, 116), endianness);

    let starting_sector_location = Static_File_Analyzer.get_int_from_bytes(bytes.slice(116, 120), endianness);
    let stream_size = Static_File_Analyzer.get_int_from_bytes(bytes.slice(120, 124), endianness);

    return {
      entry_name: directory_name,
      entry_type: entry_type,
      color_flag: color_flag_str,
      left_sibling: left_sibling_id,
      right_sibling: right_sibling_id,
      child_id: child_id,
      entry_guid: guid,
      state_bits: state_bits,
      start_block: starting_sector_location,
      entry_bytes: [],
      stream_size: stream_size,
      entry_properties: {
        creation_time: creation_time,
        modification_time: modification_time
      }
    };

  }

  /**
   * Parse a GUID from bytes.
   *
   * @param  {String} bytes An array of integers representing bytes.
   * @param {String}  endianness Value indicating how to interperate the bit order of the binary array. Default is LITTLE_ENDIAN.
   * @return {Sring}  The parsed GUID as a string.
   */
  static parse_guid(bytes, endianness = "LITTLE_ENDIAN") {
    // First four bytes of GUID id are flipped?
    let unique_id1 = bytes.slice(0, 4).reverse();
    let unique_id2 = bytes.slice(4, 16);

    let guid = "";
    for (var k=0; k<unique_id1.length; k++) {
      let hex_code = unique_id1[k].toString(16).toUpperCase();
      guid += (hex_code.length == 1) ? "0" + hex_code : hex_code;
    }

    guid += "-";

    for (var k=0; k<unique_id2.length; k++) {
      let hex_code = unique_id2[k].toString(16).toUpperCase();
      guid += (hex_code.length == 1) ? "0" + hex_code : hex_code;
      if (guid.length==8 || guid.length==13 || guid.length==18 || guid.length==23) {
        guid += "-";
      }
    }

    return guid;
  }
}

class Encoding_Tools {

  /**
   * Encodes a byte array into a Base64 string.
   *
   * This code is based off Mozilla Base64 tools.
   * See: https://developer.mozilla.org/en-US/docs/Glossary/Base64
   *
   * @param  {String}   byte_array An array containing only ints 0-255.
   * @param  {boolean}  teletype_line_len Limit the line length to 76 + 2 chars.
   * @return {String}   The encoded Base64 string.
   */
  static base64_encode_array(byte_array, teletype_line_len=true) {
    let mod3 = 2;
    let base64 = "";

    for (let unit24 = 0, index = 0; index < byte_array.length; index++) {
      mod3 = index % 3;

      if (teletype_line_len === true) {
        if (index > 0 && (index * 4 / 3) % 76 === 0) base64 += "\r\n";
      }

      unit24 |= byte_array[index] << (16 >>> mod3 & 24);

      if (mod3 === 2 || byte_array.length - index === 1) {
        base64 += String.fromCharCode(Encoding_Tools.uint6_to_b64(unit24 >>> 18 & 63), Encoding_Tools.uint6_to_b64(unit24 >>> 12 & 63), Encoding_Tools.uint6_to_b64(unit24 >>> 6 & 63), Encoding_Tools.uint6_to_b64(unit24 & 63));
        unit24 = 0;
      }
    }

    return base64.substr(0, base64.length - 2 + mod3) + (mod3 === 2 ? '' : mod3 === 1 ? '=' : '==');
  }

  /**
   * Support function for Base64 encoding.
   *
   * This code is based off Mozilla Base64 tools.
   * See: https://developer.mozilla.org/en-US/docs/Glossary/Base64
   *
   * @param  {integer}   uint6
   * @return {integer}
   */
  static uint6_to_b64(uint6) {
    return uint6 < 26
      ? uint6 + 65
      : uint6 < 52
      ? uint6 + 71
      : uint6 < 62
      ? uint6 - 4
      : uint6 === 62
      ? 43
      : uint6 === 63
      ? 47
      : 65;
  }
}

class Hash_Tools {

  /**
   * Creates a MD5 hash of the given bytes.
   *
   * @param  {Uint8Array} file_bytes Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {String}     The MD5 Hash of the given bytes
   */
  static async get_md5(file_bytes) {

    return "";
  }

  /**
   * Creates a SHA256 hash of the given bytes.
   *
   * @param  {Uint8Array} file_bytes Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @return {String}     The SHAR256 Hash of the given bytes
   */
  static async get_sha256(file_bytes) {
    if (file_bytes instanceof Array) {
      file_bytes = new Uint8Array(file_bytes);
    }

    const hash_buffer = await crypto.subtle.digest('SHA-256', file_bytes.buffer);   // hash the message
    const hash_array = Array.from(new Uint8Array(hash_buffer));                     // convert buffer to byte array
    const hash_hex = hash_array.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
    return hash_hex;
  }
}

class HTML_Parser {
  /**
   * Call to initiate the parsing of an HTML file.
   *
   * @param {Uint8Array} file_bytes Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param {String}     file_text  [Optional] The text version of the file, it can be provided to save compute time, otherwise it will be generated in this constructor.
   * @return {object}    An object with analyzed, parsed HTML file.
   */
  constructor(file_bytes, file_text="") {
    if (file_text == "") file_text = Static_File_Analyzer.get_ascii(file_bytes);

    let return_val = {
      'analytic_findings': [],
      'file_components': [],
      'file_format': "html",
      'file_generic_type': "Document"
    };

    // Check to see if this is an HTA file (HTML Application)
    if (/\<\s*hta\s*\:/gi.test(file_text)) {
      return_val.file_format = "hta";
    }

    // Try to detect HTML Smuggling
    let detect_smuggling_result = HTML_Parser.detect_html_smuggling(file_bytes, file_text);

    return_val.analytic_findings = return_val.analytic_findings.concat(detect_smuggling_result.analytic_findings);
    return_val.file_components = return_val.file_components.concat(detect_smuggling_result.file_components);

    return return_val;
  }

  /**
   * Decode a Base64 encoded string.
   *
   * @param  {String}   base64_string The Base64 encoded string of the smuggled file.
   * @param  {integer}  slice_size    [options] The decoding slice size.
   * @return {array}    The decoded file in byte array form.
   */
  static decode_smuggled_file(base64_string, slice_size=512) {
    let byte_arrays = [];

    try {
      const byte_characters = atob(base64_string);

      for (let offset = 0; offset < byte_characters.length; offset += slice_size) {
        let slice = byte_characters.slice(offset, offset + slice_size);
        let byte_codes = new Array(slice.length);

        for (let i = 0; i < slice.length; i++) {
          byte_codes[i] = slice.charCodeAt(i);
        }

        byte_arrays = byte_arrays.concat(byte_codes);
      }
    } catch(err) {}

    return byte_arrays;
  }

  /**
   * Decode a Base64 encoded string.
   *
   * @param  {String}   str       The Base64 encoded string.
   * @param  {String}   encoding  [Optional] The string encoding type.
   * @return {String}   The decoded string.
   */
  static decode_base64(str, encoding="utf-8") {
    try {
      let decoded = window.atob(str);
      return decoded;
    } catch(err) {
      return str;
    }

    // Fail
    return str;
  }

  /**
   * Attempts to find and extract any smuggled / encoded file within the document.
   *
   * @param {Uint8Array} file_bytes Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param {String}     file_text  [Optional] The text version of the file, it can be provided to save compute time, otherwise it will be generated in this constructor.
   * @return {object}    An object with analyzed, parsed HTML file.
   */
  static detect_html_smuggling(file_bytes, file_text) {
    let return_val = {
      'analytic_findings': [],
      'file_components': []
    };

    // Try to detect HTML Smuggling
    let possible_b64_literals = HTML_Parser.find_base64_literals(file_text);
    let base64_text;
    var decoded_base64;
    var is_valid;

    for (let i=0; i<possible_b64_literals.length; i++) {
      base64_text = possible_b64_literals[i];
      decoded_base64 = HTML_Parser.decode_base64(possible_b64_literals[i]);

      if (decoded_base64 != possible_b64_literals[i]) {
        // This is a valid base64 encoded literal, might still be a false positive.
        let decoded_b64_bytes = HTML_Parser.decode_smuggled_file(possible_b64_literals[i]);
        is_valid = Static_File_Analyzer.is_valid_file(decoded_b64_bytes);

        // Try to reverse encoded string
        if (!is_valid.is_valid) {
          base64_text = possible_b64_literals[i].split("").reverse().join("");
          decoded_base64 = HTML_Parser.decode_base64(base64_text);

          if (decoded_base64 != possible_b64_literals[i]) {
            let decoded_b64_bytes = HTML_Parser.decode_smuggled_file(base64_text);
            is_valid = Static_File_Analyzer.is_valid_file(decoded_b64_bytes);
          }
        }

        if (is_valid.is_valid) {
          // default name, try to find the real name.
          let file_name = "Smuggled." + is_valid.type;
          let file_name_match = /(?:file\_?name\s*\=\s*[\"\']([^\"\']+)|new\s+File\s*\([^,]+\,\s*[\"\']([^\"\']+)[\"\'])/gmi.exec(file_text);

          if (file_name_match !== null) {
            file_name = (file_name_match[1] !== undefined) ? file_name_match[1] : file_name_match[2];
          } else {
            file_name_match = /(?:file\_?name\s*\=\s*[\"\']([^\"\']+)|new\s+File\s*\([^,]+\,\s*[\"\']([^\"\']+)[\"\'])/gmi.exec(decoded_base64);
            if (file_name_match !== null) file_name = (file_name_match[1] !== undefined) ? file_name_match[1] : file_name_match[2];
          }

          file_name = (file_name !== undefined) ? file_name : "Smuggled." + is_valid.type;

          if (is_valid.type == "html" && file_name.split(".").at(-1).toLowerCase() !== "html") {
            // This could be multi layed smuggling.
            let possible_b64_literals2 = HTML_Parser.find_base64_literals(decoded_base64);
            for (let i2=0; i2<possible_b64_literals2.length; i2++) {
              let decoded_base64_2 = HTML_Parser.decode_base64(possible_b64_literals2[i2]);

              if (decoded_base64_2 != possible_b64_literals2[i2]) {
                let decoded_b64_bytes2 = HTML_Parser.decode_smuggled_file(possible_b64_literals2[i2]);
                let is_valid2 = Static_File_Analyzer.is_valid_file(decoded_b64_bytes2);

                if (is_valid2.is_valid) {
                  return_val.file_components.push({
                    'name': file_name,
                    'type': is_valid2.type,
                    'directory': false,
                    'file_bytes': decoded_b64_bytes2
                  });
                }
              }
            }
          } else {
            return_val.file_components.push({
              'name': file_name,
              'type': is_valid.type,
              'directory': false,
              'file_bytes': decoded_b64_bytes
            });
          }

          return_val.analytic_findings.push("SUSPICIOUS - Detected HTML Smuggling");
        }

      }
    }

    // Check to see if file contains a password.
    let password_match = /password[\s\:\n\r]*(?:\<(?:span|div)\>\s*)?([a-zA-Z0-9\-\_]+)/gmi.exec(file_text);
    if (password_match !== null) {
      let password_text = (password_match[1] !== undefined) ? password_match[1] : "";
      if (password_text.length > 1) {
        return_val.analytic_findings.push("SUSPICIOUS - HTML Document Contains a Password: " + password_text);
      }

    }

    return return_val;
  }

  /**
   * Attempts to extract embedded scripts within an HTML file.
   *
   * @param  {String}   file_text The string text of an HTML file.
   * @return {array}    An array of object containing the script type and extracted sctipt.
   */
  static extract_embedded_scripts(file_text) {
    let extracted_scripts = [];
    let script_regex = /\<\s*script\s+(?:type|language)\s*\=\s*[\"\'](?:text\s*\/\s*)?([^\"\']+)[\"\']\s*\>\s*([\s\S]+)\<\s*\/script\s*>/gmi;
    let script_matches = script_regex.exec(file_text);

    while (script_matches != null) {
      extracted_scripts.push({
        'script_type': script_matches[1],
        'script_code': script_matches[2]
      });

      script_matches = script_regex.exec(file_text);
    }

    return extracted_scripts;
  }

  /**
   * Finds possible Base64 encoded string literals within a given string.
   *
   * @param  {String}   str The string to search for Base64 leterals in.
   * @return {array}    An array of possible Base64 encoded string literals.
   */
  static find_base64_literals(str) {
    let base64_regex = /[\"\']([a-z0-9\+\/\=]{16,})[\"\']/gmi;
    let base64_match = base64_regex.exec(str);
    let return_val = [];

    while (base64_match !== null) {
      return_val.push(base64_match[1]);
      base64_match = base64_regex.exec(str);
    }

    return return_val;
  }

}

class ISO_9660_Parser {
  /**
   * Call to initiate the parsing of the ISO 9660 file.
   *
   * @param {Uint8Array} file_bytes Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param {String}     file_text  [Optional] The text version of the file, it can be provided to save compute time, otherwise it will be generated in this constructor.
   * @return {object}    An object with analyzed parsed ISO_9660.
   */
  constructor(file_bytes, file_text="") {
    var descriptor_tag;
    var sector_bytes = [];
    var sector_size = 2048;

    var parsed_file = {
      'descriptors': [],
      'files': [],
      'file_format_ver': "ISO 9660",
      'metadata': {
        author: "unknown",
        creation_application: "unknown",
        creation_os: "unknown",
        creation_date: "0000-00-00 00:00:00",
        description: "unknown",
        last_modified_date: "0000-00-00 00:00:00",
        last_saved_location: "unknown",
        title: "unknown"
      }
    };

    // An ISO 9660 filesystem begins begins at byte 32768
    for (var i=32768; i<file_bytes.length; i+=sector_size) {
      sector_bytes = file_bytes.slice(i,i+sector_size);
      descriptor_tag = ISO_9660_Parser.parse_descriptor_tag(sector_bytes);

      if (descriptor_tag.valid) {
        parsed_file.descriptors.push(descriptor_tag);

        if (descriptor_tag.type_code == 1) {
          // Primary Volume Descriptor

          // Gather metadata
          parsed_file.metadata.creation_application = descriptor_tag.parsed_data.application_identifier;
          parsed_file.metadata.creation_os = descriptor_tag.parsed_data.system_identifier
          parsed_file.metadata.creation_date = descriptor_tag.parsed_data.volume_creation_timestamp;
          parsed_file.metadata.last_modified_date = descriptor_tag.parsed_data.volume_modification_timestamp;
          parsed_file.metadata.title = descriptor_tag.parsed_data.volume_identifier;

          // Path Table, we don't use this.
          var path_table_size = descriptor_tag.parsed_data.path_table_size;
          var l_path_table_location = descriptor_tag.parsed_data.l_path_table_location * descriptor_tag.parsed_data.logical_block_size;
          var m_path_table_location = descriptor_tag.parsed_data.m_path_table_location * descriptor_tag.parsed_data.logical_block_size;
          var l_path_table_bytes = file_bytes.slice(l_path_table_location, l_path_table_location+path_table_size);
          var m_path_table_bytes = file_bytes.slice(m_path_table_location, m_path_table_location+path_table_size);
          var l_path_table = ISO_9660_Parser.parse_path_table(l_path_table_bytes, "LITTLE_ENDIAN");
          var m_path_table = ISO_9660_Parser.parse_path_table(m_path_table_bytes, "BIG_ENDIAN");

          var root_directory_record = ISO_9660_Parser.parse_directory_record(descriptor_tag.parsed_data.root_directory_entry);
          parsed_file.files = ISO_9660_Parser.parse_directory_files(file_bytes, root_directory_record, sector_size);
        } else if (descriptor_tag.type_code == 2) {
          // Supplementary Volume Descriptor

          // Gather metadata
          parsed_file.file_format_ver = "ISO 9660 Joliet";
          parsed_file.metadata.creation_application = descriptor_tag.parsed_data.application_identifier;
          parsed_file.metadata.creation_os = descriptor_tag.parsed_data.system_identifier
          parsed_file.metadata.creation_date = descriptor_tag.parsed_data.volume_creation_timestamp;
          parsed_file.metadata.last_modified_date = descriptor_tag.parsed_data.volume_modification_timestamp;
          parsed_file.metadata.title = descriptor_tag.parsed_data.volume_identifier;

          // Path Table, we don't use this.
          var path_table_size = descriptor_tag.parsed_data.path_table_size;
          var l_path_table_location = descriptor_tag.parsed_data.l_path_table_location * descriptor_tag.parsed_data.logical_block_size;
          var m_path_table_location = descriptor_tag.parsed_data.m_path_table_location * descriptor_tag.parsed_data.logical_block_size;
          var l_path_table_bytes = file_bytes.slice(l_path_table_location, l_path_table_location+path_table_size);
          var m_path_table_bytes = file_bytes.slice(m_path_table_location, m_path_table_location+path_table_size);
          var l_path_table = ISO_9660_Parser.parse_path_table(l_path_table_bytes, "LITTLE_ENDIAN");
          var m_path_table = ISO_9660_Parser.parse_path_table(m_path_table_bytes, "BIG_ENDIAN");

          var root_directory_record = ISO_9660_Parser.parse_directory_record(descriptor_tag.parsed_data.root_directory_entry);
          parsed_file.files = ISO_9660_Parser.parse_directory_files(file_bytes, root_directory_record, sector_size);
        } else if (descriptor_tag.type_code == 255) {
          // Volume Descriptor Set Terminator
          break;
        }
      }
    }

    return parsed_file;
  }

  /**
   * Converts an array with twelve int values 0-255 to a timestamp.
   *
   * @see https://wiki.osdev.org/ISO_9660#Date.2Ftime_format
   *
   * @param {array}   bytes Array with twelve int values 0-255 representing byte values.
   * @return {String} The timestamp converted from the four byte array.
   */
  static get_timestamp(bytes) {
    var year = Static_File_Analyzer.get_ascii(bytes.slice(0,4).filter(i => i > 31));
    var month = Static_File_Analyzer.get_ascii(bytes.slice(4,6).filter(i => i > 31));
    var day = Static_File_Analyzer.get_ascii(bytes.slice(6,8).filter(i => i > 31));
    var hour = Static_File_Analyzer.get_ascii(bytes.slice(8,10).filter(i => i > 31));
    var minute = Static_File_Analyzer.get_ascii(bytes.slice(10,12).filter(i => i > 31));
    var second = Static_File_Analyzer.get_ascii(bytes.slice(12,14).filter(i => i > 31));

    var timestamp = year + "-" + month + "-" + day + " " + hour + ":" + minute + ":" + second;
    return timestamp;
  }

  /**
   * Parses the descriptor tag for a ISO_9660.
   *
   * @see https://wiki.osdev.org/ISO_9660
   *
   * @param {array}   decr_tag_buffer Byte buffer with the 16 bytes that make up the descriptor tag.
   * @return {Object}  An object with the parsed descriptor tag.
   */
  static parse_descriptor_tag(decr_tag_buffer) {
    var tag_identifiers = [0x0000,0x0001,0x0002,0x0003,0x0004,0xFF];

    var descriptor_tag = {
      'type_code': -1,
      'type_name': "",
      'identifier': "",
      'version': "",
      'data:': [],
      'parsed_data': {},
      'valid': false
    };

    descriptor_tag.type_code = decr_tag_buffer[0];
    descriptor_tag.identifier = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(1,6).filter(i => i > 31));
    descriptor_tag.version = decr_tag_buffer[6];
    descriptor_tag.data = decr_tag_buffer.slice(7, 2048);

    if (tag_identifiers.includes(descriptor_tag.type_code) && descriptor_tag.identifier.length > 0) {
      descriptor_tag.valid = true;

      if (descriptor_tag.type_code == 0) {
        // Boot Record
        descriptor_tag.type_name = "Boot Record";
        descriptor_tag.parsed_data['boot_system_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(7,39).filter(i => i > 31));
        descriptor_tag.parsed_data['boot_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(39,71).filter(i => i > 31));
      } else if (descriptor_tag.type_code == 1) {
        // Primary Volume Descriptor
        descriptor_tag.type_name = "Primary Volume Descriptor";
        descriptor_tag.parsed_data['system_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(8,40).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['volume_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(40,72).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['volume_space_size'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(80,84), "LITTLE_ENDIAN");
        descriptor_tag.parsed_data['volume_set_size'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(120,122), "LITTLE_ENDIAN");
        descriptor_tag.parsed_data['volume_sequence_number'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(124,126), "LITTLE_ENDIAN");
        descriptor_tag.parsed_data['logical_block_size'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(128,130), "LITTLE_ENDIAN");
        descriptor_tag.parsed_data['path_table_size'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(132,136), "LITTLE_ENDIAN");
        descriptor_tag.parsed_data['l_path_table_location'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(140,144), "LITTLE_ENDIAN");
        descriptor_tag.parsed_data['optional_l_path_table_location'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(144,148), "LITTLE_ENDIAN");
        descriptor_tag.parsed_data['m_path_table_location'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(148,152), "BIG_ENDIAN");
        descriptor_tag.parsed_data['optional_m_path_table_location'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(152,156), "BIG_ENDIAN");
        descriptor_tag.parsed_data['root_directory_entry'] = decr_tag_buffer.slice(156,190);
        descriptor_tag.parsed_data['volume_set_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(190,318).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['publisher_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(318,446).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['data_preparer_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(446,574).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['application_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(574,702).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['copyright_file_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(702,739).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['abstract_file_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(739,776).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['bibliographic_file_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(776,813).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['volume_creation_timestamp'] = ISO_9660_Parser.get_timestamp(decr_tag_buffer.slice(813,830));
        descriptor_tag.parsed_data['volume_modification_timestamp'] = ISO_9660_Parser.get_timestamp(decr_tag_buffer.slice(830,847));
        descriptor_tag.parsed_data['volume_expiration_timestamp'] = ISO_9660_Parser.get_timestamp(decr_tag_buffer.slice(847,864));
        descriptor_tag.parsed_data['volume_effective_timestamp'] = ISO_9660_Parser.get_timestamp(decr_tag_buffer.slice(864,881));
        descriptor_tag.parsed_data['file_structure_version'] = decr_tag_buffer[881];
        descriptor_tag.parsed_data['application_used'] = decr_tag_buffer.slice(883,1395);
      } else if (descriptor_tag.type_code == 2) {
        // Supplementary Volume Descriptor
        descriptor_tag.type_name = "Supplementary Volume Descriptor";
        descriptor_tag.parsed_data['system_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(8,40).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['volume_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(40,72).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['volume_space_size'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(80,84), "LITTLE_ENDIAN");
        descriptor_tag.parsed_data['volume_set_size'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(120,122), "LITTLE_ENDIAN");
        descriptor_tag.parsed_data['volume_sequence_number'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(124,126), "LITTLE_ENDIAN");
        descriptor_tag.parsed_data['logical_block_size'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(128,130), "LITTLE_ENDIAN");
        descriptor_tag.parsed_data['path_table_size'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(132,136), "LITTLE_ENDIAN");
        descriptor_tag.parsed_data['l_path_table_location'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(140,144), "LITTLE_ENDIAN");
        descriptor_tag.parsed_data['optional_l_path_table_location'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(144,148), "LITTLE_ENDIAN");
        descriptor_tag.parsed_data['m_path_table_location'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(148,152), "BIG_ENDIAN");
        descriptor_tag.parsed_data['optional_m_path_table_location'] = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(152,156), "BIG_ENDIAN");
        descriptor_tag.parsed_data['root_directory_entry'] = decr_tag_buffer.slice(156,190);
        descriptor_tag.parsed_data['volume_set_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(190,318).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['publisher_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(318,446).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['data_preparer_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(446,574).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['application_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(574,702).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['copyright_file_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(702,739).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['abstract_file_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(739,776).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['bibliographic_file_identifier'] = Static_File_Analyzer.get_ascii(decr_tag_buffer.slice(776,813).filter(i => i > 31)).trim();
        descriptor_tag.parsed_data['volume_creation_timestamp'] = ISO_9660_Parser.get_timestamp(decr_tag_buffer.slice(813,830));
        descriptor_tag.parsed_data['volume_modification_timestamp'] = ISO_9660_Parser.get_timestamp(decr_tag_buffer.slice(830,847));
        descriptor_tag.parsed_data['volume_expiration_timestamp'] = ISO_9660_Parser.get_timestamp(decr_tag_buffer.slice(847,864));
        descriptor_tag.parsed_data['volume_effective_timestamp'] = ISO_9660_Parser.get_timestamp(decr_tag_buffer.slice(864,881));
        descriptor_tag.parsed_data['file_structure_version'] = decr_tag_buffer[881];
        descriptor_tag.parsed_data['application_used'] = decr_tag_buffer.slice(883,1395);
      } else if (descriptor_tag.type_code == 3) {
        // Volume Partition Descriptor
        descriptor_tag.type_name = "Volume Partition Descriptor";
      } else if (descriptor_tag.type_code == 255) {
        // Volume Descriptor Set Terminator
        descriptor_tag.type_name = "Volume Descriptor Set Terminator";
      }
    }

    return descriptor_tag;
  }

  /**
   * Uses a directory record for a ISO_9660 to parse the files in that directory.
   *
   * @param {Uint8Array} file_bytes       Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param {object}     directory_record Parsed directory object .
   * @param {integer}    sector_size      The size of sectors in the ISO file.
   * @return {array}     The list of file objects.
   */
  static parse_directory_files(file_bytes, directory_record, sector_size) {
    var files = [];
    var directory_files_location = directory_record.location_of_extent * sector_size;
    var directory_files_bytes = file_bytes.slice(directory_files_location, directory_files_location+directory_record.data_length);

    var dir;
    var i2=0;

    while (i2<directory_files_bytes.length) {
      dir = ISO_9660_Parser.parse_directory_record(directory_files_bytes.slice(i2), true);

      if (dir.length_of_file_identifier > 1) {
        var file_byte_start = dir.location_of_extent * sector_size;
        var c_file_bytes = file_bytes.slice(file_byte_start, file_byte_start+dir.data_length);

        files.push({
          'name': dir.file_identifier,
          'directory': dir.file_flags.directory,
          'file_bytes': c_file_bytes,
          'type': "iso"
        });

        if (dir.file_flags.directory === true) {
          let sub_dir = ISO_9660_Parser.parse_directory_record(c_file_bytes, true);
          let sub_dir_files = ISO_9660_Parser.parse_directory_files(file_bytes, sub_dir, sector_size);
          files = files.concat(sub_dir_files);
        }
      }

      if (dir.directory_record_length > 0) {
        i2 += dir.directory_record_length;
      } else {
        break;
      }
    }

    return files;
  }

  /**
   * Parses a directory record for a ISO_9660.
   *
   * @see https://wiki.osdev.org/ISO_9660#Directories
   *
   * @param {array}    bytes   Byte buffer
   * @param {boolean}  unicode If Strings are in unicode, defualt is false.
   * @return {Object}  An object with the parsed descriptor tag.
   */
  static parse_directory_record(bytes, unicode=false) {
    var file_flags = Universal_Disk_Format_Parser.get_binary_array([bytes[25]]).reverse();

    var directory_record = {
      'directory_record_length': bytes[0],
      'extended_attribute_record_length': bytes[1],
      'location_of_extent': Static_File_Analyzer.get_int_from_bytes(bytes.slice(2,6), "LITTLE_ENDIAN"),
      'data_length': Static_File_Analyzer.get_int_from_bytes(bytes.slice(10,14), "LITTLE_ENDIAN"),
      'recording_timestamp': bytes.slice(18,25),
      'file_flags': {
        'hidden': (file_flags[0] == 1) ? true : false,
        'directory': (file_flags[1] == 1) ? true : false,
        'associated_file': (file_flags[2] == 1) ? true : false
      },
      'file_unit_size': bytes[26],
      'interleave_gap_size': bytes[27],
      'volume_sequence_number': Static_File_Analyzer.get_int_from_bytes(bytes.slice(28,30), "LITTLE_ENDIAN"),
      'length_of_file_identifier': bytes[32],
      'file_identifier': ""
    };

    var file_identifier = "";

    if (unicode === true) {
      file_identifier = Static_File_Analyzer.get_string_from_array(bytes.slice(33,33+directory_record.length_of_file_identifier).filter(i => i !== 0)).split(";");
    } else {
      file_identifier = Static_File_Analyzer.get_ascii(bytes.slice(33,33+directory_record.length_of_file_identifier)).split(";");
    }

    directory_record.file_identifier = file_identifier[0];
    directory_record['file_id'] = file_identifier[1];

    return directory_record;
  }

  /**
   * Parses the path table
   *
   * @see https://wiki.osdev.org/ISO_9660#The_Path_Table
   *
   * @param {array}    bytes Byte buffer with the 16 bytes that make up the descriptor tag.
   * @return {Object}  An object with the parsed path table.
   */
  static parse_path_table(bytes, byte_format) {
    var path_table = {
      'directory_identifier_length': bytes[0],
      'extended_attribute_record_length': bytes[1],
      'location_of_extent': Static_File_Analyzer.get_int_from_bytes(bytes.slice(2,6), byte_format),
      'parent_directory_number': Static_File_Analyzer.get_int_from_bytes(bytes.slice(6,8), byte_format),
      'directory_identifier': ""
    };

    path_table.directory_identifier = bytes.slice(8,8+path_table.directory_identifier_length);

    return path_table;
  }
}

class MS_Document_Parser {
  static one_note = {
    'file_node_struct': {
      0x004: "ObjectSpaceManifestRootFND",
      0x008: "ObjectSpaceManifestListReferenceFND",
      0x00C: "ObjectSpaceManifestListStartFND",
      0x010: "RevisionManifestListReferenceFND",
      0x014: "RevisionManifestListStartFND",
      0x01B: "RevisionManifestStart4FND",
      0x01C: "RevisionManifestEndFND",
      0x01E: "RevisionManifestStart6FND",
      0x01F: "RevisionManifestStart7FND",
      0x021: "GlobalIdTableStartFNDX",
      0x022: "GlobalIdTableStart2FND",
      0x024: "GlobalIdTableEntryFNDX",
      0x025: "GlobalIdTableEntry2FNDX",
      0x026: "GlobalIdTableEntry3FNDX",
      0x028: "GlobalIdTableEndFNDX",
      0x02D: "ObjectDeclarationWithRefCountFNDX",
      0x02E: "ObjectDeclarationWithRefCount2FNDX",
      0x041: "ObjectRevisionWithRefCountFNDX",
      0x042: "ObjectRevisionWithRefCount2FNDX",
      0x059: "RootObjectReference2FNDX",
      0x05C: "RevisionRoleDeclarationFND",
      0x05D: "RevisionRoleAndContextDeclarationFND",
      0x072: "ObjectDeclarationFileData3RefCountFND",
      0x073: "ObjectDeclarationFileData3LargeRefCountFND",
      0x07C: "ObjectDataEncryptionKeyV2FNDX",
      0x084: "ObjectInfoDependencyOverridesFND",
      0x08C: "DataSignatureGroupDefinitionFND",
      0x090: "FileDataStoreListReferenceFND",
      0x094: "FileDataStoreObjectReferenceFND",
      0x0A4: "ObjectDeclaration2RefCountFND",
      0x0A5: "ObjectDeclaration2LargeRefCountFND",
      0x0B0: "ObjectGroupListReferenceFND",
      0x0B4: "ObjectGroupStartFND",
      0x0B8: "ObjectGroupEndFND",
      0x0C2: "HashedChunkDescriptor2FND",
      0x0C4: "ReadOnlyObjectDeclaration2RefCountFND",
      0x0C5: "ReadOnlyObjectDeclaration2LargeRefCountFND",
      0x0FF: "ChunkTerminatorFND"
    }
  };

  /**
   * Parses the FileNodeHeader of a One Note file.
   *
   * @see https://interoperability.blob.core.windows.net/files/MS-ONESTORE/%5bMS-ONESTORE%5d.pdf
   *
   * @param  {array} file_bytes An array of integers 0-255 that represent the bytes of the FileNodeHeader.
   * @return {array} An array of found embedded files.
   */
  static extract_embedded_file_from_one_note(file_bytes) {
    let embedded_file_header = [0xe7,0x16,0xe3,0xbd,0x65,0x26,0x11,0x45,0xa4,0xc4,0x8d,0x4d,0x0b,0x7a,0x9e,0xac];
    let embedded_meta_header = [0xf3,0x1c,0x00,0x1c,0x30,0x1c,0x00,0x1c,0xff,0x1d,0x00,0x14,0x82,0x1d,0x00,0x14];
    let embedded_files = [];
    let embedded_files_meta = [];

    // Search for and extract file metadata
    for (let i=0; i<file_bytes.length; i++) {
      if (Static_File_Analyzer.array_equals(file_bytes.slice(i,i+16), embedded_meta_header)) {
        let meta_index = i;
        let adjust = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(i-2,i), "LITTLE_ENDIAN");

        /* TODO: Implement this later
        let ent_count = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(i+=24,i+=4), "LITTLE_ENDIAN");
        if (ent_count == 0x88003462) ent_count = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(i,i+=4), "LITTLE_ENDIAN");

        let ent_bytes = file_bytes.slice(i,i+=ent_count);
        let ent2_count = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(i,i+=4), "LITTLE_ENDIAN");
        let ent2_bytes = file_bytes.slice(i,i+=ent2_count);

        let ent3_count = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(i+=20,i+=4), "LITTLE_ENDIAN");
        if (ent3_count == 0) ent3_count = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(i,i+=4), "LITTLE_ENDIAN");

        i += 50;
        */

        i+=132;
        while (file_bytes[i] != 0xD4 && i < file_bytes.length) i+=4;
        i+=20;

        let size = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(i,i+=4), "LITTLE_ENDIAN");
        let name_bytes = file_bytes.slice(i,i+=size);
        let file_name = Static_File_Analyzer.get_string_from_array(name_bytes);

        if (i < file_bytes.length) {
          embedded_files_meta.push({
            'name': file_name,
            'meta_index': meta_index
          });
        }
      }
    }

    // Search for embedded file header
    for (let i=0; i<file_bytes.length; i+=8) {
      if (Static_File_Analyzer.array_equals(file_bytes.slice(i,i+16), embedded_file_header)) {
        let file_size = Static_File_Analyzer.get_int_from_bytes(file_bytes.slice(i+16,i+20), "LITTLE_ENDIAN");
        let embedded_file_bytes = file_bytes.slice(i+36,i+36+file_size);
        let is_valid = Static_File_Analyzer.is_valid_file(embedded_file_bytes);
        let temp_file_name = i + "." + is_valid.type;

        embedded_files.push({
          'name': temp_file_name,
          'type': is_valid.type,
          'directory': false,
          'file_bytes': embedded_file_bytes,
          'file_index': i
        });
      }
    }

    // Match meta info with file data
    for (let i=0; i<embedded_files.length; i++) {

      for (let k=0; k<embedded_files_meta.length; k++) {
        if (embedded_files_meta[k].meta_index < embedded_files[i].file_index &&
           (embedded_files[i].file_index - embedded_files_meta[k].meta_index) < 2048) {

          embedded_files[i].name = embedded_files_meta[k].name;
        }
      }
    }

    return embedded_files;
  }

  /**
   * Parses a OOXML Document relations file.
   *
   * @param  {object} file_info  The file_info object to add findings to.
   * @param  {string} xml_text   The text of the relations file.
   * @return {object} An object with all the parsed relationships.
   */
  static parse_document_relations(file_info, xml_text, file_bytes) {
    let document_relations = {};
    let relation_type_name = "unknown";

    // This will build the relationships for this document
    var relationship_regex = /<\s*Relationship([^\>]+)\>/gmi;
    var relationship_matches = relationship_regex.exec(xml_text);

    while (relationship_matches != null) {
      relation_type_name = "unknown";
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
        relation_type_name = "vba";
      }

      if (rid != "") {
        document_relations[rid] = {
          'type':      type,
          'target':    target,
          'type_name': relation_type_name
        }
      }

      relationship_matches = relationship_regex.exec(xml_text);
    }

    return document_relations;
  }

  /**
   * Parses the FileNodeHeader of a One Note file.
   *
   * @see https://interoperability.blob.core.windows.net/files/MS-ONESTORE/%5bMS-ONESTORE%5d.pdf - 2.4.3 FileNode
   *
   * @param  {array} header_bytes An array of integers 0-255 that represent the bytes of the FileNodeHeader.
   * @return {object} An object with all the parsed header information.
   */
  static parse_file_node_header(header_bytes) {
    let header = {};

    //header['FileNodeID'] = Static_File_Analyzer.get_int_from_bits(header_bytes, 0, 10, "LITTLE_ENDIAN");
    //header['Size'] = Static_File_Analyzer.get_int_from_bits(header_bytes, 10, 23, "LITTLE_ENDIAN");

    let bits = Static_File_Analyzer.get_binary_array(header_bytes);

    header['FileNodeID'] = header_bytes[0];
    header['Size'] = header_bytes[1];

    /* StpFormat
    *  0 - 8 bytes, uncompressed.
    *  1 - 4 bytes, uncompressed.
    *  2 - 2 bytes, compressed
    *  3 - 4 bytes, compressed.
    */
    header['StpFormat'] = Static_File_Analyzer.get_int_from_bits(header_bytes, 23, 25, "LITTLE_ENDIAN");

    /* CbFormat
    *  0 - 4 bytes, uncompressed.
    *  1 - 8 bytes, uncompressed.
    *  2 - 1 byte, compressed.
    *  3 - 2 bytes, compressed.
    */
    header['CbFormat'] = Static_File_Analyzer.get_int_from_bits(header_bytes, 25, 27, "LITTLE_ENDIAN");

    /* BaseType
    *  0 - does not reference other data.
    *  1 - contains a reference to data.
    *  2 - contains a reference to a file node list.
    */
    header['BaseType'] = Static_File_Analyzer.get_int_from_bits(header_bytes, 27, 31, "LITTLE_ENDIAN");

    if (MS_Document_Parser.one_note.file_node_struct.hasOwnProperty(header['FileNodeID'])) {
      header['FileNodeType'] = MS_Document_Parser.one_note.file_node_struct[header['FileNodeID']];
    }

    return header;
  }

  /**
   * Parses the FileNodeHeader of a One Note file.
   *
   * @see https://interoperability.blob.core.windows.net/files/MS-ONESTORE/%5bMS-ONESTORE%5d.pdf
   *
   * @param  {array} bytes An array of integers 0-255 that represent the bytes of the FileNodeHeader.
   * @return {object} An object with all the parsed file node information.
   */
  static parse_file_node_list(bytes) {
    let stp_dict = {0: 8, 1: 4, 2: 2, 3: 4};
    let cb_dict = {0: 4, 1: 8, 2: 1, 3: 2};
    let node_list = {};

    node_list['uintMagic'] = Static_File_Analyzer.get_int_from_bytes(bytes.slice(0,8), "LITTLE_ENDIAN");

    if (node_list['uintMagic'] == 0xA4567AB1F5F7F4C4) {
      node_list['FileNodeListID'] = Static_File_Analyzer.get_int_from_bytes(bytes.slice(8,12), "LITTLE_ENDIAN");
      node_list['nFragmentSequence'] = Static_File_Analyzer.get_int_from_bytes(bytes.slice(12,16), "LITTLE_ENDIAN");
      node_list['FileNodes'] = [];

      let current_byte = 16;

      let file_node = {};
      file_node['FileNodeHeader'] = MS_Document_Parser.parse_file_node_header(bytes.slice(current_byte,current_byte+=4));

      while (file_node['FileNodeHeader']['FileNodeID'] > 0 && current_byte < bytes.length) {
        let extra_bytes = bytes.slice(current_byte, current_byte += (file_node['FileNodeHeader']['Size'] - 4));
        let stp_byte_cnt = stp_dict[file_node['FileNodeHeader']['StpFormat']];
        let cb_byte_cnt = cb_dict[file_node['FileNodeHeader']['CbFormat']];

        if (file_node['FileNodeHeader']['FileNodeType'] == "HashedChunkDescriptor2FND") {
          let stp_bytes = extra_bytes.slice(0,stp_byte_cnt);
          let cb_bytes = extra_bytes.slice(stp_byte_cnt, stp_byte_cnt+cb_byte_cnt);

          let stp_val = Static_File_Analyzer.get_int_from_bytes(stp_bytes, "LITTLE_ENDIAN");
          // Check if STP val is 'compressed' or not.
          stp_val = (file_node['FileNodeHeader']['StpFormat'] > 1) ? stp_val * 8 : stp_val;

          let cb_val = Static_File_Analyzer.get_int_from_bytes(cb_bytes, "LITTLE_ENDIAN");
          // Check if CB val is 'compressed' or not.
          cb_val = (file_node['FileNodeHeader']['CbFormat'] > 1) ? cb_val * 8 : cb_val;

          let cb_test1 = Static_File_Analyzer.get_int_from_bytes(cb_bytes.slice(0,2), "BIG_ENDIAN");

          // Read guidHash
          let current_extra_byte = stp_byte_cnt+cb_byte_cnt;
          let guid_hash_bytes = extra_bytes.slice(current_extra_byte,current_extra_byte+16);

          file_node['value'] = {
            'BlobRef': {
              'stp': stp_val, // Byte location of the referenced data
              'cb':  cb_val // Size in bytes of ref data
            },
            'guidHash': guid_hash_bytes
          };
        }

        node_list['FileNodes'].push(file_node);

        file_node['FileNodeHeader'] = MS_Document_Parser.parse_file_node_header(bytes.slice(current_byte,current_byte+=4));
      }
    } else {
      return null;
    }

    return node_list;
  }
}

// Tools for MSG Files, Microsoft's Outlook Email Format
class MSG_Tools {

  /**
   * Converts an MSG file in CFB version 3 to a MIME formated email.
   *
   * @param  {Object}  cfb_obj The parsed compound file binary.
   * @return {String}  The converted email in MIME format as a string.
   */
  static convert_to_mime(cfb_obj) {
    let msg_properties = MSG_Tools.parse_msg_properties(cfb_obj);

    let body_boundry_name = "";
    let mime_msg = "";
    let msg_body = "";
    let msg_headers = "";

    // Get message headers
    if (msg_properties.properties.hasOwnProperty("PidTagTransportMessageHeaders")) {
      // TODO limit line lenth to 76 chars
      msg_headers = msg_properties.properties['PidTagTransportMessageHeaders'].val + "\n\n";
      mime_msg = msg_headers;
    }

    // Check to see if there is a content boundry in the headers.
    // If one is found use it for the body content ID.
    var boundry_regex = /boundary\s*\=\s*[\"\']?([^\"\'\n\r]+)/gmi;
    let match = boundry_regex.exec(msg_headers)

    if (match !== undefined && match !== null) {
      body_boundry_name = match[1];
    } else {
      // No content boundary in headers.
      // Get Body content id and use a version of it for the body content id.
      if (msg_properties.properties.hasOwnProperty("PidTagBodyContentId")) {
        body_boundry_name = msg_properties.properties['PidTagBodyContentId'].val.split('@')[0];
        body_boundry_name = body_boundry_name.split('').filter(char => /[a-fA-F0-9\-]/.test(char)).join("");
      } else {
        // TODO: generate a body content id if PidTagBodyContentId does not exist.
      }
    }

    let body_boundry_start = "--_" + body_boundry_name + "_\n";
    let body_boundry_end = "--_" + body_boundry_name + "_--\n\n";

    let body_content_header = "Content-Transfer-Encoding: 8bit\n";
    body_content_header += "Content-Type: text/plain; charset=UTF-8;\n"
    body_content_header += " format=flowed\n\n"

    if (msg_properties.properties.hasOwnProperty("PidTagBody")) {
      mime_msg += body_boundry_start;
      mime_msg += body_content_header;

      // TODO limit line lenth to 76 chars
      mime_msg += msg_properties.properties['PidTagBody'].val + "\n\n";

      mime_msg += body_boundry_end
    }

    // Proccess any attachments.
    for (let i=0; i<msg_properties.message_attachments.length; i++) {
      let current_attachment = msg_properties.message_attachments[i];
      let boundry_name = "";

      // Create attachment boundry name/id
      if (current_attachment.hasOwnProperty('content_id')) {
        // Use a version of the content id for the boundry name.
        boundry_name = current_attachment.content_id.split('@')[0];
        boundry_name = boundry_name.split('').filter(char => /[a-fA-F0-9\-]/.test(char)).join("");
      } else {
        // Generate a new boundry name.
        // TODO write code to generate Boundy name.
      }

      let boundry_start = "--_" + boundry_name + "_\n";
      let boundry_end = "--_" + boundry_name + "_--\n\n";

      // Create content header for attachment
      let content_header = "Content-Transfer-Encoding: base64\n";
      content_header += "Content-Type: " + current_attachment.mime_type + ";\n";
      content_header += "  name=" + current_attachment.name + "\n";
      content_header += "Content-Disposition: attachment; filename=" + current_attachment.name + "; size=" + current_attachment.file_bytes.length + "\n\n";

      // Encode to Base64
      let attach_b64 = Encoding_Tools.base64_encode_array(current_attachment.file_bytes, true);

      mime_msg += boundry_start;
      mime_msg += content_header;
      mime_msg += attach_b64 + "\n\n";
      mime_msg += boundry_end;
    }

    return mime_msg;
  }

  /**
   * Parses the various entries in a parsed compound file binary and converts
   * them into MSG properties.
   *
   * @param  {Object} cfb_obj The parsed compound file binary.
   * @return {Object} An object of the parsed properties.
   */
  static parse_msg_properties(cfb_obj) {
    let properties = {};
    let message_attachment_index = -1;
    let message_attachments = [];
    let message_body = "";
    let message_headers = "";
    let sender_display_name = "";
    let sender_email = "";

    for (let i=0; i<cfb_obj.entries.length; i++) {
      let entry = cfb_obj.entries[i];

      if (entry.entry_name.startsWith("__substg1.0_")) {
        let pid_str = entry.entry_name.split("__substg1.0_")[1];

        let data_type_int = parseInt('0x' + pid_str.slice(-2) + pid_str.substr(4, 2));
        let data_type = (TNEF_Parser.props_data_types.hasOwnProperty(data_type_int)) ? TNEF_Parser.props_data_types[data_type_int] : "unknown";

        let pid_int = parseInt('0x'+pid_str);
        let pid_name = (TNEF_Parser.pid_tags.hasOwnProperty(pid_int)) ? TNEF_Parser.pid_tags[pid_int] : pid_str;

        let prop_value = 0;

        if (data_type == "bytes") {
          prop_value = entry.entry_bytes;
        } else if (data_type == "int") {
          prop_value = Static_File_Analyzer.get_int_from_bytes(entry.entry_bytes, "LITTLE_ENDIAN");
        } else if (data_type == "bool") {
          prop_value = Static_File_Analyzer.get_int_from_bytes(entry.entry_bytes, "LITTLE_ENDIAN");
          prop_value = (prop_value == 0) ? false : true;
        } else if (data_type == "date_8") {
          let debug4343=43;
        } else if (data_type == "str") {
          prop_value = Static_File_Analyzer.get_string_from_array(entry.entry_bytes);
        } else if (data_type == "unicode") {
          prop_value = Static_File_Analyzer.get_string_from_array(entry.entry_bytes.filter(ci => ci > 6));
        } else {
          prop_value = entry.entry_bytes;
        }

        // Extract meta data
        if (pid_name == "PidTagAttachContentId") {
          message_attachments[message_attachment_index].content_id = prop_value;
        } else if (pid_name == "PidTagAttachDataBinary") {
          // New attachment binary found
          message_attachments.push({'file_bytes': prop_value, 'directory': false});
          message_attachment_index++;
        } else if (pid_name == "PidTagAttachExtension") {
          message_attachments[message_attachment_index].type = prop_value.substring(1);
        } else if (pid_name == "PidTagAttachFilename") {
          if (!message_attachments[message_attachment_index].hasOwnProperty("name")) {
            // Only add this field if it doesn't exist as the long file name is prefered.
            message_attachments[message_attachment_index].name = prop_value;
          }
        } else if (pid_name == "PidTagAttachLongFilename") {
          message_attachments[message_attachment_index].name = prop_value;
        } else if (pid_name == "PidTagAttachMimeTag") {
          message_attachments[message_attachment_index].mime_type = prop_value;
        } else if (pid_name == "PidTagBody") {
          if (data_type == "unicode" || data_type == "str") {
            message_body = prop_value;
          }
        } else if (pid_name == "PidTagTransportMessageHeaders") {
          message_headers = prop_value;
        }

        if (!properties.hasOwnProperty(pid_name)) {
          properties[pid_name] = {
            'name': pid_name,
            'data_type': data_type,
            'val': prop_value
          };
        } else {
          let dup_name = pid_name + "_2";
          properties[dup_name] = {
            'name': pid_name,
            'data_type': data_type,
            'val': prop_value
          };
        }
      }
    }

    return {
      'properties': properties,
      'message_body': message_body,
      'message_headers': message_headers,
      'message_attachments': message_attachments
    }

  }
}

class PDF_Parser {

  /**
   * Retrieves embedded files and components within the PDF.
   *
   * @param {Object}  file_info - The file_info object used file file parsing results.
   * @param {array}   object_array - An array containing the embedded objects of the PDF file.
   * @return {array}  An array containing the embedded file components of the PDF file.
   */
  static async get_file_components(object_array) {
    let file_components = [];

    for (let i=0; i<object_array.length; i++) {
      // Look for image files
      if (object_array[i].object_dictionary.hasOwnProperty("Subtype")) {
        if (object_array[i].object_dictionary['Subtype'].toLowerCase() == "image") {
          if (object_array[i].object_dictionary.hasOwnProperty("Filter")) {
            if (object_array[i].object_dictionary['Filter'].toLowerCase() == "dctdecode") {
              // Found JPEG file

              // Set default name for JPEG file.
              let obj_name = "Image_" + object_array[i].object_number + ".jpg";

              // Search for name in object dictionary.
              if (object_array[i].object_dictionary.hasOwnProperty("Name")) {
                obj_name = object_array[i].object_dictionary["Name"];
              }

              file_components.push({
                'name': obj_name,
                'type': "jpeg",
                'directory': false,
                'file_bytes': object_array[i].stream_bytes
              });
            } else if (object_array[i].object_dictionary['Filter'].toLowerCase() == "flatedecode" && object_array[i].stream_bytes.length > 0) {
              /*
              *  This logic branch is for other image types encoded in FlateDecode.
              *  FlateDecode is a Zlib encoded data stream.
              *  The easiest conversion is to TIFF file format, so we will do that here.
              *
              *  References:
              *    - https://blog.idrsolutions.com/ccitt-encoding-in-pdf-files-decoding-ccitt-data/
              *    - https://blog.idrsolutions.com/ccitt-encoding-in-pdf-files-converting-pdf-ccitt-data-into-a-tiff/
              */

              // We need to use the pako library to decode the ZLib stream.
              // Check to see if the pako library is available.
              if (pako !== null && pako !== undefined) {
                try {
                  let stream_type = Static_File_Analyzer.is_valid_file(object_array[i].stream_bytes);
                  let stream_bytesU8 = new Uint8Array(object_array[i].stream_bytes);
                  let deflate_bytes = await pako.inflate(stream_bytesU8);

                  // Set default values for image file.
                  let k = 0;
                  let is_black = false;
                  let columns = 1728;
                  let rows = 0;
                  let img_height = 0;
                  let img_width = 0;
                  let img_byte_len = 0;
                  let bits_per_sample = 8;

                  /*
                  *
                  * A predictor value from 10 to 15 indicates that a PNG predictor is in use.
                  *
                  *  1 - No prediction (the default value)
                  *  2 - TIFF Predictor 2
                  * 10 - PNG prediction (on encoding, PNG None on all rows)
                  * 11 - PNG prediction (on encoding, PNG Sub on all rows)
                  * 12 - PNG prediction (on encoding, PNG Up on all rows)
                  * 13 - PNG prediction (on encoding, PNG Average on all rows)
                  * 14 - PNG prediction (on encoding, PNG Paeth on all rows)
                  * 15 - PNG prediction (on encoding, PNG optimum)
                  */
                  let predictor = 1;

                  // Get the actual values for tiff file.
                  if (object_array[i].object_dictionary.hasOwnProperty("DecodeParms")) {
                    if (object_array[i].object_dictionary['DecodeParms'].hasOwnProperty("K")) {
                      k = parseInt(object_array[i].object_dictionary['DecodeParms']['K']);
                    }

                    if (object_array[i].object_dictionary['DecodeParms'].hasOwnProperty("Columns")) {
                      columns = parseInt(object_array[i].object_dictionary['DecodeParms']['Columns']);
                    }

                    if (object_array[i].object_dictionary['DecodeParms'].hasOwnProperty("Rows")) {
                      rows = parseInt(object_array[i].object_dictionary['DecodeParms']['Rows']);
                    } else {
                      rows = columns;
                    }

                    if (object_array[i].object_dictionary['DecodeParms'].hasOwnProperty("Predictor")) {
                      predictor = parseInt(object_array[i].object_dictionary['DecodeParms']['Predictor']);
                    }
                  }

                  if (object_array[i].object_dictionary.hasOwnProperty("Length")) {
                    img_byte_len = parseInt(object_array[i].object_dictionary['Length']);
                  }

                  if (object_array[i].object_dictionary.hasOwnProperty("Height")) {
                    img_height = parseInt(object_array[i].object_dictionary['Height']);
                  } else if (columns > 0) {
                    img_height = columns;
                  }

                  if (object_array[i].object_dictionary.hasOwnProperty("Width")) {
                    img_width = parseInt(object_array[i].object_dictionary['Width']);
                  } else if (rows > 0) {
                    img_width = rows;
                  }

                  if (object_array[i].object_dictionary.hasOwnProperty("BitsPerComponent")) {
                    bits_per_sample = parseInt(object_array[i].object_dictionary['BitsPerComponent']);
                  }

                  // Write the CCITT image data at the end of the array
                  //tiff_file_bytes = tiff_file_bytes.concat(Array.from(deflate_bytes));

                  let image_file_bytes = [];

                  /*
                  file_components.push({
                    'name': "Image_" + object_array[i].object_number + ".tif",
                    'type': "txt",
                    'directory': false,
                    'file_bytes': image_file_bytes
                  });
                  */

                  // Image decode is not working at the moment, just return the file as a zlib file.
                  /*
                  file_components.push({
                    'name': "Image_" + object_array[i].object_number + ".zlib",
                    'type': "zlib",
                    'directory': false,
                    'file_bytes': object_array[i].stream_bytes
                  });
                  */
                } catch (err) {
                  console.log("Can't deflate PDF stream.");
                }

              } else {
                // The Pako library is require to deflate this stream.
                console.log("Pako library not found, component file will be added as a Zlib file.");

                file_components.push({
                  'name': "Image_" + object_array[i].object_number + ".zlib",
                  'type': "zlib",
                  'directory': false,
                  'file_bytes': object_array[i].stream_bytes
                });

              }

            }
          }
        }
      } else if (object_array[i].object_dictionary.hasOwnProperty("Filter/FlateDecode/Length")) {
        if (pako !== null && pako !== undefined) {
          try {
            let stream_type = Static_File_Analyzer.is_valid_file(object_array[i].stream_bytes);
            let stream_bytesU8 = new Uint8Array(object_array[i].stream_bytes);
            let deflate_bytes = await pako.inflate(stream_bytesU8);
            let file_type = Static_File_Analyzer.is_valid_file(deflate_bytes);

            if (file_type.is_valid) {
              let fc_filename =  "Object_" + object_array[i].object_number + "." + file_type.type;

              file_components.push({
                'name': fc_filename,
                'type': file_type.type,
                'directory': false,
                'file_bytes': deflate_bytes
              });
            } else {
              let fc_filename =  "Object_" + object_array[i].object_number + ".txt";

              file_components.push({
                'name': fc_filename,
                'type': "txt",
                'directory': false,
                'file_bytes': deflate_bytes
              });
            }
          } catch (err) {
            console.log("Can't deflate PDF stream.");
          }
        } else {
          // The Pako library is require to deflate this stream.
          console.log("Pako library not found, component file will be added as a Zlib file.");
        }
      } else if (object_array[i].stream_text.substring(0,3) == "ÿØÿ") {
        file_components.push({
          'name': "Image_" + object_array[i].object_number + ".jpeg",
          'type': "Image",
          'directory': false,
          'file_bytes': object_array[i].stream_bytes,
          'file_text': object_array[i].stream_text
        });
      }

    }

    return file_components;
  }

  /**
   * Retrieves embedded object within the PDF.
   *
   * @param {Object}  file_info - The file_info object used file file parsing results.
   * @param {String}  file_text - The unicode text of the PDF file.
   * @param {array}   file_bytes - An array of the bytes of the PDF file.
   * @return {array}  An array containing the embedded objects of the PDF file.
   */
  static async get_objects(file_info, file_bytes, file_text) {
    let embedded_objs = [];
    let match;
    let obj_start_regex = /(\d+)\s+(\d+)\s+obj[\r\n]/gmi;

    while (match = obj_start_regex.exec(file_text)) {
      let object_number = match[1];
      let generation_number = match[2];
      let object_dictionary = {};
      let object_start_index = match.index + match[0].length;
      let object_end_index = file_text.indexOf("endobj", match.index) - 1;
      let object_text = file_text.substring(object_start_index, object_end_index) + "\n";
      let object_bytes = file_bytes.slice(object_start_index, object_end_index);

      // Extract object's dictionary
      try {
        let cur_obj_index = 0;
        let end_obj_index = 0;
        let dictionary_text = "";
        cur_obj_index = object_text.indexOf("<<", cur_obj_index) + 2;

        while (cur_obj_index >= 0 && cur_obj_index < object_text.length) {
          end_obj_index = object_text.indexOf(">>", cur_obj_index);
          dictionary_text = object_text.substr(cur_obj_index, end_obj_index-2);

          if (end_obj_index > 0) {
            cur_obj_index = end_obj_index + 2;
          } else {
            break;
          }

          let dictionary_pair_regex = /\/([^\s<]+)\s*(<<[^>]+>>|[^\/]*)?/gmi;
          let match2;

          while (match2 = dictionary_pair_regex.exec(dictionary_text)) {
            try {
              if (match2[1].toLowerCase() == "f" ||
                  match2[1].toLowerCase() == "filter" ||
                  match2[1].toLowerCase() == "name" ||
                  match2[1].toLowerCase() == "s" ||
                  match2[1].toLowerCase() == "subtype" ||
                  match2[1].toLowerCase() == "type") {

                // Use next key as value
                let dict_key = match2[1];
                match2 = dictionary_pair_regex.exec(dictionary_text);
                object_dictionary[dict_key] = (match2[1] !== null && match2[1] !== undefined) ? match2[1].trim() : "";
                if (object_dictionary[dict_key].endsWith(")")) {
                  let val_index = dictionary_text.indexOf(object_dictionary[dict_key]);
                  let check = dictionary_text.substring(val_index-1, val_index);
                  object_dictionary[dict_key] = (check == "/") ? "/" + object_dictionary[dict_key] : object_dictionary[dict_key];
                }
              } else {
                if (match2[2] !== null && match2[2] !== undefined && match2[2].startsWith("<<")) {
                  // Sub dictionary
                  let sub_dict_start = match2.index + match2[1].length + 1;
                  let sub_dict_end = match2.input.indexOf(">>", sub_dict_start);
                  let sub_dict_str = match2.input.substring(sub_dict_start, sub_dict_end);

                  let sub_dictionary = {};
                  let sub_dictionary_regex = /\/([^\s]+)\s+([^\/]*)?/gmi;
                  let match3;

                  while (match3 = sub_dictionary_regex.exec(match2[2])) {
                    if (match3[2] !== null && match3[2] !== undefined) {
                      if (match3[2].trim().endsWith(">>")) {
                        sub_dictionary[match3[1]] = match3[2].trim().substring(0,match3[2].trim().length - 2).trim();
                      } else {
                        sub_dictionary[match3[1]] = match3[2].trim();
                      }
                    } else {
                      sub_dictionary[match3[1]] = "";
                    }

                    // Check for embedded URIs
                    if (/\/URI/gmi.test(match3[1])) {
                      file_info = Static_File_Analyzer.search_for_iocs(match3[1], file_info);
                    }
                  }

                  object_dictionary[match2[1]] = sub_dictionary;
                } else {
                  // Single value
                  let dictionary_val = match2[2].trim();
                  dictionary_val = (dictionary_val.endsWith(">>")) ? dictionary_val.slice(0,-2).trim() : dictionary_val;
                  dictionary_val = (dictionary_val.endsWith("\n")) ? dictionary_val.slice(0,-2).trim() : dictionary_val;

                  object_dictionary[match2[1]] = (match2[2] !== null && match2[2] !== undefined) ? dictionary_val : "";
                }
              }
            } catch(err) {
              console.log("Error extracting PDF object dictionary (1): " + object_number + "Error: " + err);
              break;
            }
          }

          if (cur_obj_index > 0) {
            cur_obj_index = file_text.indexOf("<<", cur_obj_index) + 2;
          } else {
            break;
          }

        }
      } catch(err) {
        console.log("Error extracting PDF object dictionary (2): " + object_number + "Error: " + err);
      }

      // Extract stream text, if it exists.
      let stream_start_index = object_text.indexOf("stream");
      let stream_end_index = (stream_start_index > 0) ? object_text.indexOf("endstream") : -1;
      let stream_text = (stream_end_index > 0) ? object_text.substring(stream_start_index+6, stream_end_index).trim() : "";
      let stream_bytes = [];

      if (stream_text.length > 0) {
        let end_index_adj = 0;
        let start_index_adj = 6;

        if (object_bytes[stream_start_index+6] == 13 || object_bytes[stream_start_index+6] == 10) start_index_adj = 7;
        if (object_bytes[stream_start_index+7] == 13 || object_bytes[stream_start_index+7] == 10) start_index_adj = 8;
        if (object_bytes[stream_end_index-1] == 13 || object_bytes[stream_end_index-1] == 10) end_index_adj = -1;
        if (object_bytes[stream_end_index-2] == 13 || object_bytes[stream_end_index-2] == 10) end_index_adj = -2;

        stream_bytes = object_bytes.slice(stream_start_index+start_index_adj, stream_end_index+end_index_adj)
      }

      // Check for compressed stream objects, often used to hide links.
      if (object_dictionary.hasOwnProperty("Type")) {
        if (object_dictionary['Type'].toLowerCase() == "objstm") {
          // Stream object, it might contain a URI / URL
          // REF: https://blog.didierstevens.com/2019/03/07/analyzing-a-phishing-pdf-with-objstm/
          if (object_dictionary['Filter'].toLowerCase() == "flatedecode") {
            if (object_dictionary['Filter'].toLowerCase() == "flatedecode") {
              // We need to use the pako library to decode the ZLib stream.
              // Check to see if the pako library is available.
              if (pako !== null && pako !== undefined) {
                try {
                  if (object_dictionary.hasOwnProperty("Length")) {
                    let byte_len = parseInt(object_dictionary['Length']);
                    let stream_bytesU8 = [];
                    stream_bytesU8 = new Uint8Array(stream_bytes);

                    let deflate_bytes = await pako.inflate(stream_bytesU8);
                    let stream_type = Static_File_Analyzer.is_valid_file(deflate_bytes);

                    let decoder = new TextDecoder("utf-8");
                    stream_text = decoder.decode(deflate_bytes);
                    console.log(stream_text); // DEBUG
                    // Check for embedded URIs
                    if (/\/URI/gmi.test(stream_text)) {
                      file_info = Static_File_Analyzer.search_for_iocs(stream_text, file_info);
                    }
                  }
                } catch (err) {
                  console.log("Error decoding stream object: " + err);
                }
              }
            }
          }
        }
      }

      embedded_objs.push({
        'object_number':     object_number,
        'generation_number': generation_number,
        'object_dictionary': object_dictionary,
        'object_text':       object_text,
        'stream_text':       stream_text,
        'stream_bytes':      stream_bytes
      });
    }


    return embedded_objs;
  }
}

class RAR_Parser {

  /**
   * Converts an array with int values 0-255 to a binary array.
   *
   * @param {array} u8int_array Array with int values 0-255 representing byte values.
   * @return {array}  An array with int values of 0 or 1, representing the binary value of the given integer.
   */
  static get_binary_array(u8int_array) {
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
   * Converts an array with int values 0 or 1 to unsined integer.
   *
   * @param {array}    binary_array Array with int values 0 or 1 representing binary values.
   * @param {String}   endianness Value indicating how to interperate the bit order of the binary array. Default is BIG_ENDIAN.
   * @return {integer} The integer value of the given bit array.
   */
  static get_int_from_bin(binary_array, endianness = "LITTLE_ENDIAN") {
    var int_val = 0;

    if (endianness == "LITTLE_ENDIAN") {
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
   * Converts an array with int values 0-255 to an integer.
   *
   * The lower 7 bits of every byte contain integer data and highest bit
   * in every byte is the continuation flag. If highest bit is 0, this is the
   * last byte in sequence.
   *
   * @see https://www.rarlab.com/technote.htm#vint
   *
   * @param {array}     bytes Array with int values 0-255 representing byte values.
   * @return {integer}  The read integer value
   */
  static read_vinteger(bytes, byte_index) {
    let byte_array = [];
    let continue_reading = true;
    let current_byte = byte_index[0];

    while (continue_reading == true) {
      let byte_bits = RAR_Parser.get_binary_array([bytes[current_byte]]);
      byte_array.push(RAR_Parser.get_int_from_bin(byte_bits.slice(0,7)));
      if (byte_bits[7] == 0) continue_reading = false;
      current_byte++;
    }

    let int_result = Static_File_Analyzer.get_int_from_bytes(byte_array);
    byte_index[0] = current_byte;

    return int_result;
  }
}

class Tiff_Tools {
  // see: https://exiftool.org/TagNames/EXIF.html
  static tiff_tags = {
      0x0000 : "GPSVersionID",
      0x0001 : "GPSLatitudeRef",
      0x0002 : "GPSLatitude",
      0x0003 : "GPSLongitudeRef",
      0x0004 : "GPSLongitude",
      0x0005 : "GPSAltitudeRef",
      0x0006 : "GPSAltitude",
      0x0007 : "GPSTimeStamp",
      0x0008 : "GPSSatellites",
      0x0009 : "GPSStatus",
      0x000A : "GPSMeasureMode",
      0x000B : "GPSDOP",
      0x000C : "GPSSpeedRef",
      0x000D : "GPSSpeed",
      0x000E : "GPSTrackRef",
      0x000F : "GPSTrack",
      0x0010 : "GPSImgDirectionRef",
      0x0011 : "GPSImgDirection",
      0x0012 : "GPSMapDatum",
      0x0013 : "GPSDestLatitudeRef",
      0x0014 : "GPSDestLatitude",
      0x0015 : "GPSDestLongitudeRef",
      0x0016 : "GPSDestLongitude",
      0x0017 : "GPSDestBearingRef",
      0x0018 : "GPSDestBearing",
      0x0019 : "GPSDestDistanceRef",
      0x001A : "GPSDestDistance",
      0x001B : "GPSProcessingMethod",
      0x001C : "GPSAreaInformation",
      0x001D : "GPSDateStamp",
      0x001E : "GPSDifferential",
      0x0100 : "ImageWidth",
      0x0101 : "ImageHeight",
      0x0102: "BitsPerSample",
      0x0103: "Compression",
      0x0106: "PhotometricInterpretation",
      0x0111: "StripOffsets",
      0x0112: "Orientation",
      0x0115: "SamplesPerPixel",
      0x0116: "RowsPerStrip",
      0x0117: "StripByteCounts",
      0x011A: "XResolution",
      0x011B: "YResolution",
      0x011C: "PlanarConfiguration",
      0x0128: "ResolutionUnit",
      0x0201: "JpegIFOffset",
      0x0202: "JpegIFByteCount",
      0x0211: "YCbCrCoefficients",
      0x0212: "YCbCrSubSampling",
      0x0213: "YCbCrPositioning",
      0x0214: "ReferenceBlackWhite",
      0x8769 : "ExifIFDPointer",
      0x8825 : "GPSInfoIFDPointer",
      0xA005 : "InteroperabilityIFDPointer",
      0x0102 : "BitsPerSample",
      0x0103 : "Compression",
      0x0106 : "PhotometricInterpretation",
      0x0112 : "Orientation",
      0x0115 : "SamplesPerPixel",
      0x011C : "PlanarConfiguration",
      0x0212 : "YCbCrSubSampling",
      0x0213 : "YCbCrPositioning",
      0x011A : "XResolution",
      0x011B : "YResolution",
      0x0128 : "ResolutionUnit",
      0x0111 : "StripOffsets",
      0x0116 : "RowsPerStrip",
      0x0117 : "StripByteCounts",
      0x0201 : "JPEGInterchangeFormat",
      0x0202 : "JPEGInterchangeFormatLength",
      0x012D : "TransferFunction",
      0x013E : "WhitePoint",
      0x013F : "PrimaryChromaticities",
      0x0211 : "YCbCrCoefficients",
      0x0214 : "ReferenceBlackWhite",
      0x0132 : "DateTime",
      0x010E : "ImageDescription",
      0x010F : "Make",
      0x0110 : "Model",
      0x0131 : "Software",
      0x013B : "Artist",
      0x8298 : "Copyright",
      0x829A : "ExposureTime",
      0x829D : "FNumber",
      0x8822 : "ExposureProgram",
      0x8824 : "SpectralSensitivity",
      0x8827 : "ISOSpeedRatings",
      0x8828 : "OECF",
      0x9000 : "ExifVersion",
      0x9003 : "DateTimeOriginal",
      0x9004 : "DateTimeDigitized",
      0x9010 : "OffsetTime",
      0x9011 : "OffsetTimeOriginal",
      0x9012 : "OffsetTimeDigitized",
      0x9101 : "ComponentsConfiguration",
      0x9102 : "CompressedBitsPerPixel",
      0x9201 : "ShutterSpeedValue",
      0x9202 : "ApertureValue",
      0x9203 : "BrightnessValue",
      0x9204 : "ExposureBias",
      0x9205 : "MaxApertureValue",
      0x9206 : "SubjectDistance",
      0x9207 : "MeteringMode",
      0x9208 : "LightSource",
      0x9209 : "Flash",
      0x9211 : "ImageNumber",
      0x9212 : "SecurityClassification",
      0x9214 : "SubjectArea",
      0x920A : "FocalLength",
      0x927C : "MakerNote",
      0x9286 : "UserComment",
      0x9290 : "SubsecTime",
      0x9291 : "SubsecTimeOriginal",
      0x9292 : "SubsecTimeDigitized",
      0x935c : "ImageSourceData",
      0x9400 : "AmbientTemperature",
      0x9401 : "Humidity",
      0x9402 : "Pressure",
      0x9403 : "WaterDepth",
      0x9404 : "Acceleration",
      0x9405 : "CameraElevationAngle",
      0x9C9D : "XPTitle",
      0x9C9D : "XPAuthor",
      0x9C9E : "XPKeywords",
      0x9C9F : "XPSubject",
      0xA000 : "FlashpixVersion",
      0xA001 : "ColorSpace",
      0xA002 : "PixelXDimension",
      0xA003 : "PixelYDimension",
      0xA004 : "RelatedSoundFile",
      0xA005 : "InteroperabilityIFDPointer",
      0xA20B : "FlashEnergy",
      0xA20C : "SpatialFrequencyResponse",
      0xA20E : "FocalPlaneXResolution",
      0xA20F : "FocalPlaneYResolution",
      0xA210 : "FocalPlaneResolutionUnit",
      0xA214 : "SubjectLocation",
      0xA215 : "ExposureIndex",
      0xA217 : "SensingMethod",
      0xA300 : "FileSource",
      0xA301 : "SceneType",
      0xA302 : "CFAPattern",
      0xA401 : "CustomRendered",
      0xA402 : "ExposureMode",
      0xA403 : "WhiteBalance",
      0xA404 : "DigitalZoomRation",
      0xA405 : "FocalLengthIn35mmFilm",
      0xA406 : "SceneCaptureType",
      0xA407 : "GainControl",
      0xA408 : "Contrast",
      0xA409 : "Saturation",
      0xA40A : "Sharpness",
      0xA40B : "DeviceSettingDescription",
      0xA40C : "SubjectDistanceRange",
      0xA420 : "ImageUniqueID",
      0xA430 : "OwnerName",
      0xA431 : "SerialNumber",
      0xA432 : "LensInfo",
      0xA433 : "LensMake",
      0xA434 : "LensModel",
      0xA435 : "LensSerialNumber",
      0xA436 : "ImageTitle",
      0xA437 : "Photographer",
      0xA438 : "ImageEditor",
      0xA439 : "CameraFirmware",
      0xA43A : "RAWDevelopingSoftware",
      0xA43B : "ImageEditingSoftware",
      0xA43C : "MetadataEditingSoftware",
      0xC4A5 : "PrintIM"
  };

  /**
   * Creates the header and tags for a TIFF file given the specific options.
   * This is used to extract TIFF images from a PDF file.
   *
   * @param {array}  options - Options used to creat header.
   * @return {array} An array with int values of 0 to 255, representing the bit values of the created TIFF header.
   */
  static create_tiff_header(options) {
    // Read in options or assign default values.
    let k = options.hasOwnProperty("k") ? options["k"] : 0;
    let is_black = options.hasOwnProperty("is_black") ? options["is_black"] : false;
    let columns = options.hasOwnProperty("columns") ? options["columns"] : 1728;
    let rows = options.hasOwnProperty("rows") ? options["rows"] : 0;
    let img_height = options.hasOwnProperty("height") ? options["height"] : 0;
    let img_width = options.hasOwnProperty("width") ? options["width"] : 0;
    let img_byte_len = options.hasOwnProperty("byte_len") ? options["byte_len"] : 0;
    let bits_per_sample = options.hasOwnProperty("bits_per_sample") ? options["bits_per_sample"] : 8;

    /*
    *  Create the TIFF file structure to append the image data stream to.
    *
    *  The first two bytes indicate the files byte order.
    *    - 0x4D 0x4D is big-endian byte order
    *    - 0x49 0x49 is little-endian byte order
    *
    *  The reference I am using uses big-endian, so we will use that.
    */
    let tiff_file_bytes = [];
    let tif_header = [0x4d,0x4d,0x00,0x2a,0x00,0x00,0x00,0x08];

    // Indicate the number of Image File Directory (IFD) entries.
    let ifd_entry_count = 8;
    let strip_offset = 8 + 2 + (ifd_entry_count * 12); // Header + idf count field + idf count times 12 byte length.
    tiff_file_bytes = tif_header.concat([0, ifd_entry_count]);

    /*
    *  IFD format is:
    *  Bytes: 0 -  1 -> Tag ID
    *  Bytes: 2 -  3 -> Field Type
    *  Bytes: 4 -  7 -> Type count / The number of values (not bytes)
    *  Bytes: 8 - 11 -> Offset value
    *
    *  Types:
    *  1 - Byte     - 8-bit unsigned integer.
    *  2 - ASCII    - 8-bit byte that contains a 7-bit ASCII code; the last byte must be NUL (binary zero).
    *  3 - SHORT    - 16-bit (2-byte) unsigned integer.
    *  4 - LONG     - 32-bit (4-byte) unsigned integer.
    *  5 - RATIONAL - Two LONGs: the first represents the numerator of a fraction; the second, the denominator.
    *
    *  Note: The entries in an IFD must be sorted in ascending order by Tag.
    *
    *  Reference: https://docs.fileformat.com/image/tiff/
    */

    // ImageWidth - 256 - 0x0100
    tiff_file_bytes = tiff_file_bytes.concat([0x01,0x00, 0,4, 0,0,0,1].concat(Static_File_Analyzer.get_bytes_from_int(columns, "BIG_ENDIAN")));

    // ImageLength - 257 - 0x0101
    tiff_file_bytes = tiff_file_bytes.concat([0x01,0x01, 0,4, 0,0,0,1].concat(Static_File_Analyzer.get_bytes_from_int(img_height, "BIG_ENDIAN")));

    // BitsPerSample - 258 - 0x0102
    //tiff_file_bytes = tiff_file_bytes.concat([0x01,0x02, 0,4, 0,0,0,1].concat(Static_File_Analyzer.get_bytes_from_int(bits_per_sample, "BIG_ENDIAN")));

    // Compression - 259 0x0103
    if (k==0) {
      tiff_file_bytes = tiff_file_bytes.concat([0x01,0x03, 0,3, 0,0,0,1, 0,1,0,0]);
    } else if (k<0) {
      tiff_file_bytes = tiff_file_bytes.concat([0x01,0x03, 0,3, 0,0,0,1, 0,2,0,0]);
    } else {
      tiff_file_bytes = tiff_file_bytes.concat([0x01,0x03, 0,3, 0,0,0,1, 0,1,0,0]);
    }

    // PhotometricInterpretation - 262 0x0106 (0 = WhiteIsZero, 1 = BlackIsZero)
    if (is_black) {
      tiff_file_bytes = tiff_file_bytes.concat([0x01,0x06, 0,3, 0,0,0,1, 0,1,0,0]);
    } else {
      tiff_file_bytes = tiff_file_bytes.concat([0x01,0x06, 0,3, 0,0,0,1, 0,0,0,0]);
    }

    // StripOffsets - 273 0x0111
    tiff_file_bytes = tiff_file_bytes.concat([0x01,0x11, 0,4, 0,0,0,1].concat(Static_File_Analyzer.get_bytes_from_int(strip_offset, "BIG_ENDIAN")));

    // SamplesPerPixel - 277 0x115
    tiff_file_bytes = tiff_file_bytes.concat([0x01,0x15, 0,3, 0,0,0,1, 0,3,0,0]);

    // RowsPerStrip - 278 0x0116 (Use image height)
    tiff_file_bytes = tiff_file_bytes.concat([0x01,0x16, 0,4, 0,0,0,1].concat(Static_File_Analyzer.get_bytes_from_int(img_height, "BIG_ENDIAN")));

    // StripByteCounts - 279 0x0117 (Use Image byte length, for a single strip)
    tiff_file_bytes = tiff_file_bytes.concat([0x01,0x17, 0,4, 0,0,0,1].concat(Static_File_Analyzer.get_bytes_from_int(img_byte_len, "BIG_ENDIAN")));

    // Write next IOD offset zero as no other table
    tiff_file_bytes = tiff_file_bytes.concat([0,0,0,0]);

    return tiff_file_bytes;
  }

  /**
   * Parses data from an Image File Directory (IDF)
   *
   * @param {array}   file_bytes - Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param {integer} ifd_offset - The offset / start of the IFD
   * @param {String}  byte_order - the Byte order of the file: LITTLE_ENDIAN or BIG_ENDIAN.
   * @return {object} The parsed IFD
   *
   * @see https://dev.exiv2.org/projects/exiv2/wiki/The_Metadata_in_TIFF_files
   */
  static parse_ifd(file_bytes, ifd_offset, byte_order) {
    let ifd_object = {
      'field_type':   "UNKNOWN",
      'value_count':  0,
      'value_offset': 0
    };

    let ifd_types = ["UNKNOWN","BYTE","ASCII","SHORT","LONG","RATIONAL","SBYTE","UNDEFINED","SSHORT","SLONG","SRATIONAL","FLOAT","DOUBLE"];

    let ifd_bytes = file_bytes.slice(ifd_offset);

    return ifd_object;
  }

  /**
   * Parses EXIF data in the image file.
   *
   * @param {array}   file_bytes - Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param {integer} ifd_offset - The offset / start of the IFD
   * @param {integer} tiff_start - The start of the TIFF data.
   * @param {String}  byte_order - the Byte order of the file: LITTLE_ENDIAN or BIG_ENDIAN.
   * @return {object} The parsed IFD
   *
   * @see https://dev.exiv2.org/projects/exiv2/wiki/The_Metadata_in_TIFF_files
   */
  static read_tiff_tags(file_bytes, ifd_offset, tiff_start, byte_order) {
    let tags = {};
    let entries = file_bytes[ifd_offset];
    let tag_name;

    for (let i=0; i<entries; i++) {
      let entry_offset = ifd_offset + i*12 + 2;
      let tag_int = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(entry_offset, entry_offset+2), byte_order);

      if (Tiff_Tools.tiff_tags.hasOwnProperty(tag_int)) {
        tag_name = Tiff_Tools.tiff_tags[tag_int];
      } else {
        tag_name = tag_int;
      }

      let tag_value = Tiff_Tools.read_tag_value(file_bytes, entry_offset, tiff_start, byte_order);

      let string_convert_tags_ascii = ["PrintIM"];
      let string_convert_tags_unicode = ["XPAuthor"];

      if (string_convert_tags_ascii.includes(tag_name)) {
        tags[tag_name] = Static_File_Analyzer.get_ascii(tag_value);
      } else if (string_convert_tags_unicode.includes(tag_name)) {
        tags[tag_name] = Static_File_Analyzer.get_string_from_array(tag_value.filter(i => i !== 0));
      } else {
        tags[tag_name] = tag_value;
      }

    }

    return tags;
  }

  /**
   * Parses tag value
   *
   * @param {array}   file_bytes - Array with int values 0-255 representing the bytes of the file to be analyzed.
   * @param {integer} entry_offset - The offset / start of the IFD
   * @param {integer} tiff_start - The start of the TIFF data.
   * @param {String}  byte_order - the Byte order of the file: LITTLE_ENDIAN or BIG_ENDIAN.
   * @return {object} The parsed IFD
  */
  static read_tag_value(file_bytes, entry_offset, tiff_start, byte_order) {
    let type = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(entry_offset+2, entry_offset+4), byte_order);
    let value_count = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(entry_offset+4, entry_offset+8), byte_order);
    let value_offset = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(entry_offset+8, entry_offset+12), byte_order) + tiff_start;

    switch (type) {
      case 1: // Unknown
      case 7: // UNDEFINED
        if (value_count == 1) {
          return file_bytes[entry_offset+8];
        } else {
          let val_offset = value_count > 4 ? value_offset : (entry_offset + 8);
          let values = [];

          for (let i=0; i<value_count; i++) {
            if (val_offset+i < file_bytes.length) {
              values[i] = file_bytes[val_offset+i];
            }
          }

          return values;
        }
      case 2: // ASCII
        let val_offset = value_count > 4 ? value_offset : (entry_offset + 8);
        let ascii_bytes = file_bytes.slice(val_offset, val_offset + value_count-1);
        let ascii_text = Static_File_Analyzer.get_ascii(ascii_bytes);
        return ascii_text;
      case 3: // SHORT - 16 bit
        if (value_count == 1) {
          return Static_File_Analyzer.get_two_byte_int(file_bytes.slice(entry_offset+8, entry_offset+10), byte_order);
        } else {
          let val_offset = value_count > 2 ? value_offset : (entry_offset + 8);
          let values = [];

          for (let i=0; i<value_count; i++) {
            values[i] = Static_File_Analyzer.get_two_byte_int(file_bytes.slice(val_offset+(2*i), val_offset+(2*i)+2), byte_order);
          }

          return values;
        }
      case 4: // LONG - 32 bit
        if (value_count == 1) {
          return Static_File_Analyzer.get_four_byte_int(file_bytes.slice(entry_offset+8, entry_offset+12), byte_order);
        } else {
          let val_offset = value_count > 2 ? value_offset : (entry_offset + 8);
          let values = [];

          for (let i=0; i<value_count; i++) {
            values[i] = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(val_offset+(4*i), val_offset+(4*i)+4), byte_order);
          }

          return values;
        }
      case 5: // RATIONAL - Two 32 bit values
        if (value_count == 1) {
          let numerator = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(value_offset, value_offset+4), byte_order);
          let denominator = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(value_offset+4, value_offset+8), byte_order);

          if (denominator > 0) {
            return (numerator / denominator)
          } else {
            return 0;
          }
        } else {
          let values = Array(value_count).fill(0);
          for (let i=0; i<value_count; i++) {
            let numerator = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(value_offset+(8*i), value_offset+(8*i)+4), byte_order);
            let denominator = Static_File_Analyzer.get_four_byte_int(file_bytes.slice(value_offset+(8*i)+4, value_offset+(8*i)+8), byte_order);

            if (denominator > 0) {
              values[i] = (numerator / denominator);
            }
          }

          return values;
        }
      case 6: // SBYTE
        if (value_count == 1) {
          return file_bytes[entry_offset+8];
        } else {

        }
        break;
      case 8: // SSHORT
        break;
      case 9: // SLONG - 32 bit - Signed
        if (value_count == 1) {
          return file_bytes[entry_offset+8];
        } else {

        }
        break;
      case 10: // SRATIONAL - Two SLONG - first val is numerator, second val is denominator
        if (value_count == 1) {
          return file_bytes[entry_offset+8];
        } else {

        }
        break;
      case 11: // FLOAT
        break;
      case 12: // DOUBLE
        break;
    }
  }
}

class TNEF_Parser {
  static props_data_types = {
    0x0201: "bytes",
    0x0211: "bytes",
    0x0300: "int",
    0x0310: "int",
    0x0b00: "bool",
    0x4000: "date_8",
    0x4010: "date_8",
    0x1e00: "str",
    0x1e10: "str",
    0x1f00: "unicode",
  };

  static pid_tags = {
    0x0002000b: "PidTagAlternateRecipientAllowed",
    0x00020102: "PidTagAlternateRecipientAllowed",
    0x00030102: "PidTagAuthorizingUsers",
    0x00040102: "PidTagScriptData",
    0x001a001f: "PidTagMessageClass",
    0x0023000b: "PidTagOriginatorDeliveryReportRequested",
    0x00260003: "PidTagPriority",
    0x0029000b: "PidTagReadReceiptRequested",
    0x002c0102: "PidTagRedirectionHistory",
    0x00360003: "PidTagSensitivity",
    0x0037001f: "PidTagSubject",
    0x003b0102: "PidTagSentRepresentingSearchKey",
    0x003d001f: "PidTagSubjectPrefix",
    0x003f0102: "PidTagReceivedByEntryId",
    0x0040001f: "PidTagReceivedByName",
    0x00410102: "PidTagSentRepresentingEntryId",
    0x0042001f: "PidTagSentRepresentingName",
    0x00430102: "PidTagReceivedRepresentingEntryId",
    0x0044001f: "PidTagReceivedRepresentingName",
    0x004f0102: "PidTagReplyRecipientEntries",
    0x0050001f: "PidTagReplyRecipientNames",
    0x00510102: "PidTagReceivedBySearchKey",
    0x00520102: "PidTagReceivedRepresentingSearchKey",
    0x0064001f: "PidTagSentRepresentingAddressType",
    0x0065001f: "PidTagSentRepresentingEmailAddress",
    0x0070001e: "PidTagConversationTopic",
    0x0070001f: "PidTagConversationTopic",
    0x00710102: "PidTagConversationIndex",
    0x0075001f: "PidTagReceivedByAddressType",
    0x0076001f: "PidTagReceivedByEmailAddress",
    0x0077001f: "PidTagReceivedRepresentingAddressType",
    0x0078001f: "PidTagReceivedRepresentingEmailAddress",
    0x007d001f: "PidTagTransportMessageHeaders",
    0x007f0102: "PidTagTnefCorrelationKey",
    0x0e01000b: "PidTagDeleteAfterSubmit",
    0x0e200003: "PidTagAttachSize",
    0x0c190102: "PidTagSenderEntryId",
    0x0c1a001f: "PidTagSenderName",
    0x0c1d0102: "PidTagSenderEmailAddress",
    0x0c1e001f: "PidTagSenderAddressType",
    0x0c1f001f: "PidTagSenderEmailAddress",
    0x0e02001f: "PidTagDisplayBcc",
    0x0e03001f: "PidTagDisplayCc",
    0x0e04001f: "PidTagDisplayTo",
    0x0e060040: "PidTagMessageDeliveryTime",
    0x0e0a0102: "PidTagSentMailEntryId",
    0x0e140003: "PidTagSubmitFlags",
    0x0e1d001f: "PidTagNormalizedSubject",
    0x0e1f000b: "PidTagRtfInSync",
    0x0e210003: "PidTagAttachNumber",
    0x0e4b0102: "CreatorGUID",
    0x0e580102: "CreatorSID",
    0x0f030102: "PidTagConversationThreadId",
    0x0ff60102: "PidTagInstanceKey",
    0x0ff80102: "PidTagMappingSignature",
    0x0ff90102:	"PidTagRecordKey",
    0x0ffa0102: "PidTagStoreRecordKey",
    0x0ffb0102: "PidTagStoreEntryId",
    0x0ffe0003: "PidTagObjectType",
    0x0fff0102: "PidTagEntryId",
    0x1000001f: "PidTagBody",
    0x10060003: "PidTagRtfSyncBodyCrc",
    0x10070003: "PidTagRtfSyncBodyCount",
    0x1008001e: "PidTagBody",
    0x10090102: "PidTagRtfCompressed",
    0x10100003: "PidTagRtfSyncPrefixCount",
    0x10110003: "PidTagRtfSyncTrailingCount",
    0x10120102: "PidTagOriginallyIntendedRecipEntryId",
    0x1015001f: "PidTagBodyContentId",
    0x10170102: "AnnotationToken",
    0x1035001f: "PidTagInternetMessageId",
    0x1039001f: "PidTagInternetReferences",
    0x3001001e: "PidTagDisplayName",
    0x3001001f: "PidTagDisplayName",
    0x3002001f: "PidTagAddressType",
    0x3003001f: "PidTagEmailAddress",
    0x300b0102: "PidTagSearchKey",
    0x30140102: "PidTagBody",
    0x340d0003: "PidTagStoreSupportMask",
    0x34140102: "PidTagStoreProvider",
    0x37010102: "PidTagAttachDataBinary",
    0x3703001f:	"PidTagAttachExtension",
    0x3704001f: "PidTagAttachFilename",
    0x3707001f: "PidTagAttachLongFilename",
    0x370e001f: "PidTagAttachMimeTag",
    0x3712001f: "PidTagAttachContentId",
    0x3703001e: "PidTagAttachExtension",
    0x37020102: "PidTagAttachEncoding",
    0x37050003: "PidTagAttachMethod",
    0x3707001e: "PidTagAttachLongFilename",
    0x370b0003: "PidTagRenderingPosition",
    0x37140003: "PidTagAttachFlags",
    0x39fe001f: "PidTagSmtpAddress",
    0x3a20001f: "PidTagTransmittableDisplayName",
    0x3d010102: "PidTagAbProviders",
    0x3fde0003: "PidTagInternetCodepage",
    0x3ff8001f: "PidTagCreatorName",
    0x3ff90102: "PidTagCreatorEntryId",
    0x3ffa001f: "PidTagLastModifierName",
    0x4022001f:	"CreatorAddressType",
    0x4023001f:	"CreatorEmailAddress",
    0x4024001f:	"LastModifierAddressType",
    0x4025001f:	"LastModifierEmailAddress",
    0x4030001f: "SenderSimpleDisplayName",
    0x4031001f:	"SentRepresentingSimpleDisplayName",
    0x4034001f:	"ReceivedBySimpleDisplayName",
    0x4035001f:	"ReceivedRepresentingSimpleDisplayName",
    0x4038001f:	"CreatorSimpleDisplayName",
    0x4039001f:	"LastModifierSimpleDisplayName",
    0x59090003: "PidTagMessageEditorFormat",
    0x5d01001f: "PidTagSenderSmtpAddress",
    0x5d02001f: "PidTagSentRepresentingSmtpAddress",
    0x5d07001f: "PidTagReceivedBySmtpAddress",
    0x5d08001f: "PidTagReceivedRepresentingSmtpAddress",
    0x5d0a001f:	"CreatorSMTPAddress",
    0x5d0b001f:	"LastModifierSMTPAddress",
    0x5fe5001f: "RecipientSipUri",
    0x5ff70102: "PidTagRecipientEntryId",
    0x7ffa0003: "PidTagAttachmentLinkId",
    0x7ffb0040: "PidTagExceptionStartTime",
    0x7ffc0040: "PidTagExceptionEndTime",
    0x7ffd0003: "PidTagAttachmentFlags",
    0x7ffe000b: "PidTagAttachmentHidden",
    0x8000001e: "PidLidReminderFileParameter",
    0x8000001f: "attFrom",
    0x8006001f: "attDateRecd"
  };

  /**
   * Converts an array with eight int values 0-255 to a date.
   * Bytes must be a 64 bit integer representing the number of 100-nanosecond intervals since January 1, 1601
   *
   * @param {array}   bytes Array with eight int values 0-255 representing byte values.
   * @param {String}  endianness Value indicating how to interperate the bit order of the byte array. Default is LITTLE_ENDIAN.
   * @return {String} The date value of the given bit array.
   */
  static get_eight_byte_date(bytes, endianness = "LITTLE_ENDIAN") {
    var int_bits = "";

    if (endianness == "LITTLE_ENDIAN") {
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
   * Converts an array with int values 0-255 to a binary array.
   *
   * @param {array}   bytes Array with int values 0-255 representing byte values.
   * @return {String} The date in string format.
   */
  static get_ptyp_time(bytes) {
    let year = Static_File_Analyzer.get_int_from_bytes(bytes.slice(0,2), "LITTLE_ENDIAN");
    let month = Static_File_Analyzer.get_int_from_bytes(bytes.slice(2,4), "LITTLE_ENDIAN");
    let day = Static_File_Analyzer.get_int_from_bytes(bytes.slice(4,6), "LITTLE_ENDIAN");
    let hour = Static_File_Analyzer.get_int_from_bytes(bytes.slice(6,8), "LITTLE_ENDIAN");
    let minute = Static_File_Analyzer.get_int_from_bytes(bytes.slice(8,10), "LITTLE_ENDIAN");
    let second = Static_File_Analyzer.get_int_from_bytes(bytes.slice(10,12), "LITTLE_ENDIAN");
    let dayOfWeek = Static_File_Analyzer.get_int_from_bytes(bytes.slice(12,14), "LITTLE_ENDIAN");

    year = year.toString();
    month = (month < 10) ? "0"+month.toString() : month.toString();
    day = (day < 10) ? "0"+day.toString() : day.toString();
    hour = (hour < 10) ? "0"+hour.toString() : hour.toString();
    minute = (minute < 10) ? "0"+minute.toString() : minute.toString();
    second = (second < 10) ? "0"+second.toString() : second.toString();

    return year+"-"+month+"-"+day+" "+hour+":"+minute+":"+second;
  }

  /**
   * Parses TNEF PID properties byte stream and returns an array with the parsed results.
   *
   * @param {array}  bytes Array with int values 0-255 representing byte values.
   * @return {array} The array with the parsed results
   */
  static parse_properties(bytes) {
    let properties = [];
    let current_byte = 0;
    let properties_count = Static_File_Analyzer.get_int_from_bytes(bytes.slice(current_byte, current_byte+=4), "LITTLE_ENDIAN");

    for (let i=0; i<properties_count; i++) {
      let properties_bytes = bytes.slice(current_byte, current_byte+=4);

      // For debug
      let properties_hex = ""
      try {
        properties_hex += (properties_bytes[0] < 16) ? "0"+properties_bytes[0].toString(16) : properties_bytes[0].toString(16);
        properties_hex += (properties_bytes[1] < 16) ? "0"+properties_bytes[1].toString(16) : properties_bytes[1].toString(16);
        properties_hex += (properties_bytes[2] < 16) ? "0"+properties_bytes[2].toString(16) : properties_bytes[2].toString(16);
        properties_hex += (properties_bytes[3] < 16) ? "0"+properties_bytes[3].toString(16) : properties_bytes[3].toString(16);
      } catch (err) {};

      let property_type_int = Static_File_Analyzer.get_int_from_bytes(properties_bytes.slice(0,2), "BIG_ENDIAN");
      let property_data_type = (TNEF_Parser.props_data_types.hasOwnProperty(property_type_int)) ? TNEF_Parser.props_data_types[property_type_int] : "unknown";

      let property_id = Static_File_Analyzer.get_int_from_bytes(properties_bytes, "LITTLE_ENDIAN");
      let property_name = (TNEF_Parser.pid_tags.hasOwnProperty(property_id)) ? TNEF_Parser.pid_tags[property_id] : properties_hex;
      let property_val = 0;

      if (property_data_type == "bytes" || property_data_type == "str") {
        let sub_properties_count = Static_File_Analyzer.get_int_from_bytes(bytes.slice(current_byte, current_byte+=4), "LITTLE_ENDIAN");
        let sub_property_size = Static_File_Analyzer.get_int_from_bytes(bytes.slice(current_byte, current_byte+=4), "LITTLE_ENDIAN");
        property_val = [];

        // Special case for PidLid values, not sure why yet.
        if (sub_properties_count == 0x00062008) {
          // read 24 more bytes
          let guid_bytes = [0x08,0x20,0x06,0x00,0x00,0x00,0x00,0x00].concat(bytes.slice(current_byte, current_byte +=8));
          let mnif_id = bytes.slice(current_byte, current_byte +=4);
          let id = bytes.slice(current_byte, current_byte +=4);
          sub_properties_count = Static_File_Analyzer.get_int_from_bytes(bytes.slice(current_byte, current_byte+=4), "LITTLE_ENDIAN");
          sub_property_size = Static_File_Analyzer.get_int_from_bytes(bytes.slice(current_byte, current_byte+=4), "LITTLE_ENDIAN");
        }

        for (let i2=0; i2<sub_properties_count; i2++) {
          let sub_property_val = 0;
          let sub_property_bytes = bytes.slice(current_byte, current_byte+=sub_property_size);
          let sub_property_padding = (4 - (sub_property_size % 4)) % 4;
          let padding_bytes = bytes.slice(current_byte, current_byte+=sub_property_padding);

          if (property_data_type == "bytes") {
            sub_property_val = sub_property_bytes;
          } else if (property_data_type == "str") {
            sub_property_val = Static_File_Analyzer.get_string_from_array(sub_property_bytes.slice(0,-1));
          }

          property_val.push(sub_property_val);
        }
      } else {
        if (property_data_type == "bool") {
          let int_val = Static_File_Analyzer.get_int_from_bytes(bytes.slice(current_byte, current_byte +=4), "LITTLE_ENDIAN");
          property_val = (int_val == 0) ? false : true;

          // Special case for PidLid values, not sure why yet.
          if (int_val == 0x00062008) {
            // read 24 more bytes
            let guid_bytes = [0x08,0x20,0x06,0x00].concat(bytes.slice(current_byte, current_byte +=12));
            let mnif_id = bytes.slice(current_byte, current_byte +=4);
            let id = bytes.slice(current_byte, current_byte +=4);
            let val = bytes.slice(current_byte, current_byte +=4);
            property_val = {'id': id, 'value': val};
          }
        } else if (property_data_type == "date_14") {
          property_val = TNEF_Parser.get_ptyp_time(bytes.slice(current_byte, current_byte+=14));
        } else if (property_data_type == "date_8") {
          property_val = TNEF_Parser.get_eight_byte_date(bytes.slice(current_byte, current_byte+=8), "LITTLE_ENDIAN");
        } else if (property_data_type == "int") {
          property_val = Static_File_Analyzer.get_int_from_bytes(bytes.slice(current_byte, current_byte +=4), "LITTLE_ENDIAN");

          // Special case for PidLid values, not sure why yet.
          if (property_val == 0x00062008) {
            // read 24 more bytes
            let guid_bytes = [0x08,0x20,0x06,0x00].concat(bytes.slice(current_byte, current_byte +=12));
            let mnif_id = bytes.slice(current_byte, current_byte +=4);
            let id = bytes.slice(current_byte, current_byte +=4);
            let val = bytes.slice(current_byte, current_byte +=4);
            property_val = {'id': id, 'value': val};
          }
        } else {
          property_val = bytes.slice(current_byte, current_byte+=4);
        }
      }

      properties.push({'name': property_name, 'type': property_data_type, 'val': property_val});
    }

    return properties;
  }

  /**
   * Parses a TNEF byte stream and returns an object with the parsed results.
   *
   * @param {array}   bytes Array with int values 0-255 representing byte values.
   * @return {object} An object with the parsed results.
   */
  static parse_tnef(bytes) {
    let tnef_attributes = {
      0x0106900800: "attTnefVersion",
      0x0107900600: "attOemCodepage",
      0x0108800700: "attMessageClass",
      0x010d800400: "attPriority",
      0x0104800100: "attSubject",
      0x0105800300: "attDateSent",
      0x0106800300: "attDateRecd",
      0x0120800300: "attDateModified",
      0x0109800100: "attMessageID",
      0x0103900600: "attMsgProps",
      0x0104900600: "attMsgProps",
      0x020f800600: "attAttachData",
      0x0210800100: "attAttachTitle",
      0x0205900600: "attAttachment",
      0x0213800300: "attAttachModifyDate",
      0x0202900600: "attAttachRenddata"
    };

    let attach_key = Static_File_Analyzer.get_int_from_bytes(bytes.slice(4,6), "LITTLE_ENDIAN");
    let current_byte = 6;
    let attribute_count = 0;

    let parsed_attributes = {
      'attAttachment': [],
      'attAttachData': [],
      'attAttachModifyDate': [],
      'attAttachRenddata': []
    };

    let attachments = [];
    let current_attachment = {'filename': "unknown", 'data': ""};

    let msg_attribute_chk = 0;
    let msg_attribute_chk_calc = 0;

    while (current_byte < bytes.length) {
      let msg_attribute_bytes = bytes.slice(current_byte, current_byte+=5);
      let msg_attribute_id   = Static_File_Analyzer.get_int_from_bytes(msg_attribute_bytes, "BIG_ENDIAN");
      let msg_attribute_name = tnef_attributes.hasOwnProperty(msg_attribute_id) ? tnef_attributes[msg_attribute_id] : msg_attribute_bytes.join(",");
      let msg_attribute_len  = Static_File_Analyzer.get_int_from_bytes(bytes.slice(current_byte, current_byte+=4), "LITTLE_ENDIAN");
      let msg_attribute_val  = bytes.slice(current_byte, current_byte+=msg_attribute_len);

      msg_attribute_chk = Static_File_Analyzer.get_int_from_bytes(bytes.slice(current_byte, current_byte+=2), "LITTLE_ENDIAN");
      msg_attribute_chk_calc = Static_File_Analyzer.calculate_checksum(msg_attribute_val);

      if (msg_attribute_name == "attTnefVersion") {
        msg_attribute_val = Static_File_Analyzer.get_int_from_bytes(msg_attribute_val, "LITTLE_ENDIAN");
      } else if (msg_attribute_name == "attMessageClass") {
        msg_attribute_val = Static_File_Analyzer.get_string_from_array(msg_attribute_val.slice(0,-1));
      } else if (msg_attribute_name == "attOemCodepage") {
        let code_page_prm = Static_File_Analyzer.get_int_from_bytes(msg_attribute_val.slice(0,4), "LITTLE_ENDIAN");
        let code_page_sec = Static_File_Analyzer.get_int_from_bytes(msg_attribute_val.slice(4,8), "LITTLE_ENDIAN");
        msg_attribute_val = [code_page_prm, code_page_sec];
      } else if (msg_attribute_name == "attAttachRenddata") {
        let attach_type = msg_attribute_val[0]; // 1 is file, 2 is OLe
        let attach_pos = Static_File_Analyzer.get_int_from_bytes(msg_attribute_val.slice(2,6), "LITTLE_ENDIAN");
        let render_width = Static_File_Analyzer.get_int_from_bytes(msg_attribute_val.slice(6,8), "LITTLE_ENDIAN");
        let render_height = Static_File_Analyzer.get_int_from_bytes(msg_attribute_val.slice(8,10), "LITTLE_ENDIAN");
        let data_flags = msg_attribute_val[10];

        attach_type = (attach_type == 1) ? "file" : "Ole";
        data_flags = (data_flags == 0) ? "FileDataDefault" : "FileDataMacBinary";

        msg_attribute_val = {
          'AttachType': attach_type,
          'AttachPosition': attach_pos,
          'RenderWidth': render_width,
          'RenderHeight': render_height,
          'DataFlags': data_flags
        };
      } else if (msg_attribute_name == "attAttachData") {
        current_attachment = {'filename': "unknown", 'data': msg_attribute_val};
      } else if (msg_attribute_name == "attAttachTitle") {
        msg_attribute_val = Static_File_Analyzer.get_string_from_array(msg_attribute_val.slice(0,-1));
        current_attachment.filename = msg_attribute_val;
        attachments.push(current_attachment);
      } else if (msg_attribute_name == "attAttachment") {
        msg_attribute_val = TNEF_Parser.parse_properties(msg_attribute_val);
      } else if (msg_attribute_name == "attMsgProps") {
        msg_attribute_val = TNEF_Parser.parse_properties(msg_attribute_val);
      } else {
        if (msg_attribute_val.length == 14) {
          msg_attribute_val = TNEF_Parser.get_ptyp_time(msg_attribute_val);
        }
      }

      if (msg_attribute_name == "attAttachment" ||
          msg_attribute_name == "attAttachData" ||
          msg_attribute_name == "attAttachModifyDate" ||
          msg_attribute_name == "attAttachRenddata") {

        parsed_attributes[msg_attribute_name].push(msg_attribute_val);
      } else {
        parsed_attributes[msg_attribute_name] = msg_attribute_val;
      }

    }

    return {
      'attach_key':  attach_key,
      'attributes':  parsed_attributes,
      'attachments': attachments
    };
  }
}

class Universal_Disk_Format_Parser {

  /**
   * Converts an array with int values 0-255 to a binary array.
   *
   * @param {array} u8int_array Array with int values 0-255 representing byte values.
   * @return {array}  An array with int values of 0 or 1, representing the binary value of the given integer.
   */
  static get_binary_array(u8int_array) {
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
   * Converts an array with twelve int values 0-255 to a timestamp.
   *
   * @see https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf
   *
   * @param {array}   bytes Array with twelve int values 0-255 representing byte values.
   * @return {String} The timestamp converted from the four byte array.
   */
  static get_ecma_timestamp(bytes) {
    var type_and_timezone = Static_File_Analyzer.get_int_from_bytes(bytes.slice(0,2), "LITTLE_ENDIAN");
    var year = Static_File_Analyzer.get_int_from_bytes(bytes.slice(2,4), "LITTLE_ENDIAN");
    year = (year == 0) ? "0000" : year;

    var month = (bytes[4] < 10) ? "0"+bytes[4] : bytes[4];
    var day = (bytes[5] < 10) ? "0"+bytes[5] : bytes[5];
    var hour = (bytes[6] < 10) ? "0"+bytes[6] : bytes[6];
    var minute = (bytes[7] < 10) ? "0"+bytes[7] : bytes[7];
    var second = (bytes[8] < 10) ? "0"+bytes[8] : bytes[8];

    var timestamp = year + "-" + month + "-" + day + " " + hour + ":" + minute + ":" + second;
    return timestamp;
  }

  /**
   * Parse the Anchor Volume Descriptor Pointer in Universal Disk Format.
   *
   * @see https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf - 10.2 Anchor Volume Descriptor Pointer
   *
   * @param {array}   arr_bytes The array of bytes starting at the Anchor Volume Descriptor Pointer start byte.
   * @return {object} The parsed Anchor Volume Descriptor Pointer
   */
  static parse_anchor_volume_descriptor_pointer(arr_bytes) {
    var anchor_volume_descriptor_pointer = {
      'descriptor_tag': Universal_Disk_Format_Parser.parse_descriptor_tag(arr_bytes.slice(0,16)),
      'main_volume_descriptor_sequence_extent': {
        'extent_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(16,20), "LITTLE_ENDIAN"),
        'extent_location': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(20,24), "LITTLE_ENDIAN"),
      },
      'reserve_volume_descriptor_sequence_extent': {
        'extent_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(24,28), "LITTLE_ENDIAN"),
        'extent_location': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(28,32), "LITTLE_ENDIAN"),
      },
      'reserved': arr_bytes.slice(32,512)
    };

    return anchor_volume_descriptor_pointer;
  }

  /**
   * Parses the descriptor tag for a Universal Disk Format file.
   *
   * @see https://wiki.osdev.org/UDF
   *
   * @param {array}   decr_tag_buffer Byte buffer with the 16 bytes that make up the descriptor tag.
   * @return {Object}  An object with the parsed descriptor tag.
   */
  static parse_descriptor_tag(decr_tag_buffer) {
    var tag_identifiers = [0x0001,0x0002,0x0003,0x0004,0x0005,0x0006,0x0007,0x0008,0x0009,0x0100,0x0101,0x0102,0x0103,0x0104,0x0105,0x0106,0x0107,0x0108,0x0109,0x010a];

    var descriptor_tag = {
      'tag_identifier': 0,
      'descriptor_version': 0,
      'tag_checksum': 0,
      'tag_serial_number': 0,
      'descriptor_crc': 0,
      'descriptor_crc_length': 0,
      'tag_location': 0,
      'valid': false
    };

    descriptor_tag.tag_identifier = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(0,2), "LITTLE_ENDIAN");
    if (tag_identifiers.includes(descriptor_tag.tag_identifier)) {
      descriptor_tag.descriptor_version = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(2,4), "LITTLE_ENDIAN");
      descriptor_tag.tag_checksum = decr_tag_buffer[4];
      descriptor_tag.tag_serial_number = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(6,8), "LITTLE_ENDIAN");
      descriptor_tag.descriptor_crc = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(8,10), "LITTLE_ENDIAN");
      descriptor_tag.descriptor_crc_length = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(10,12), "LITTLE_ENDIAN");
      descriptor_tag.tag_location = Static_File_Analyzer.get_int_from_bytes(decr_tag_buffer.slice(12,16), "LITTLE_ENDIAN");

      // Verify checksum
      var checksum = 0;
      for (var i2=0; i2<decr_tag_buffer.length; i2++) {
        if (i2==4) continue;
        checksum += decr_tag_buffer[i2];
      }

      while (checksum > 256) checksum -= 256; // Truncate to byte

      if (descriptor_tag.tag_checksum == checksum) {
        descriptor_tag.valid = true;
      } else {
        descriptor_tag.valid = false;
      }
    }

    return descriptor_tag;
  }

  /**
   * Parse the Extended File Entry in Universal Disk Format.
   *
   * @see https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf - 14.17 Extended File Entry
   *
   * @param {array}   arr_bytes The array of bytes starting at the Extended File Entry start byte.
   * @return {object} The parsed Extended File Entry
   */
  static parse_extended_file_entry(arr_bytes) {
    var extended_file_entry = {
      'descriptor_tag': Universal_Disk_Format_Parser.parse_descriptor_tag(arr_bytes.slice(0,16)),
      'icb_tag': Universal_Disk_Format_Parser.parse_icb_tag(arr_bytes.slice(16,36)),
      'uid': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(36,40), "LITTLE_ENDIAN"),
      'gid': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(40,44), "LITTLE_ENDIAN"),
      'permissions': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(44,48), "LITTLE_ENDIAN"),
      'file_link_count': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(48,50), "LITTLE_ENDIAN"),
      'record_format': arr_bytes[50],
      'record_display_attributes': arr_bytes[51],
      'record_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(52,56), "LITTLE_ENDIAN"),
      'information_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(56,64), "LITTLE_ENDIAN"),
      'object_size': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(64,72), "LITTLE_ENDIAN"),
      'logical_blocks_recorded': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(72,80), "LITTLE_ENDIAN"),
      'access_timestamp': Universal_Disk_Format_Parser.get_ecma_timestamp(arr_bytes.slice(80,92)),
      'modification_timestamp': Universal_Disk_Format_Parser.get_ecma_timestamp(arr_bytes.slice(92,104)),
      'creation_timestamp': Universal_Disk_Format_Parser.get_ecma_timestamp(arr_bytes.slice(104,116)),
      'attribute_timestamp': Universal_Disk_Format_Parser.get_ecma_timestamp(arr_bytes.slice(116,128)),
      'checkpoint': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(128,132), "LITTLE_ENDIAN"),
      'reserved': arr_bytes.slice(132,136),
      'extended_attribute_icb': {
        'extent_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(136,140), "LITTLE_ENDIAN"),
        'extent_location': {
          'logical_block_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(140,144), "LITTLE_ENDIAN"),
          'partition_reference_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(144,146), "LITTLE_ENDIAN"),
        },
        'implementation_use': arr_bytes.slice(146,152)
      },
      'stream_directory_icb': {
        'extent_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(152,156), "LITTLE_ENDIAN"),
        'extent_location': {
          'logical_block_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(156,160), "LITTLE_ENDIAN"),
          'partition_reference_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(160,162), "LITTLE_ENDIAN"),
        },
        'implementation_use': arr_bytes.slice(162,168)
      },
      'implementation_identifier': {
        'flags': arr_bytes[168],
        'identifier': Static_File_Analyzer.get_ascii(arr_bytes.slice(167,190).filter(i => i > 31)),
        'identifier_suffix': arr_bytes.slice(190,198)
      },
      'unique_id': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(200,208), "LITTLE_ENDIAN"),
      'length_of_extended_attributes': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(208,212), "LITTLE_ENDIAN"),
      'length_of_allocation_descriptors': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(212,216), "LITTLE_ENDIAN"),
      'allocation_descriptors': []
    };


    extended_file_entry['extended_attributes'] = arr_bytes.slice(216,216+extended_file_entry.length_of_extended_attributes);
    //extended_file_entry['allocation_descriptors'] = arr_bytes.slice(216+extended_file_entry.length_of_extended_attributes,216+extended_file_entry.length_of_extended_attributes+extended_file_entry.length_of_allocation_descriptors);

    var allocation_descriptors_bytes = arr_bytes.slice(216+extended_file_entry.length_of_extended_attributes,216+extended_file_entry.length_of_extended_attributes+extended_file_entry.length_of_allocation_descriptors);
    var current_ad_byte = 0;

    while (current_ad_byte < allocation_descriptors_bytes.length) {
      extended_file_entry.allocation_descriptors.push({
        'extent_length': Static_File_Analyzer.get_int_from_bytes(allocation_descriptors_bytes.slice(current_ad_byte,current_ad_byte+=4), "LITTLE_ENDIAN"),
        'extent_position': Static_File_Analyzer.get_int_from_bytes(allocation_descriptors_bytes.slice(current_ad_byte,current_ad_byte+=4), "LITTLE_ENDIAN"),
      });
    }

    return extended_file_entry;
  }

  /**
   * Parse the File Entry in Universal Disk Format.
   *
   * @see https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf - 14.9 File Entry
   *
   * @param {array}   arr_bytes The array of bytes starting at the File Entry start byte.
   * @return {object} The parsedFile Entry
   */
  static parse_file_entry(arr_bytes) {
    var file_entry = {
      'descriptor_tag': Universal_Disk_Format_Parser.parse_descriptor_tag(arr_bytes.slice(0,16)),
      'icb_tag': Universal_Disk_Format_Parser.parse_icb_tag(arr_bytes.slice(16,36)),
      'uid': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(36,40), "LITTLE_ENDIAN"),
      'gid': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(40,44), "LITTLE_ENDIAN"),
      'permissions': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(44,48), "LITTLE_ENDIAN"),
      'file_link_count': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(48,50), "LITTLE_ENDIAN"),
      'record_format': arr_bytes[50],
      'record_display_attributes': arr_bytes[51],
      'record_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(52,56), "LITTLE_ENDIAN"),
      'information_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(56,64), "LITTLE_ENDIAN"),
      'logical_blocks_recorded': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(64,72), "LITTLE_ENDIAN"),
      'access_timestamp': Universal_Disk_Format_Parser.get_ecma_timestamp(arr_bytes.slice(72,84)),
      'modification_timestamp': Universal_Disk_Format_Parser.get_ecma_timestamp(arr_bytes.slice(84,96)),
      'attribute_timestamp': Universal_Disk_Format_Parser.get_ecma_timestamp(arr_bytes.slice(96,108)),
      'checkpoint': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(108,112), "LITTLE_ENDIAN"),
      'extended_attribute_icb': {
        'extent_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(112,116), "LITTLE_ENDIAN"),
        'extent_location': {
          'logical_block_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(116,120), "LITTLE_ENDIAN"),
          'partition_reference_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(120,122), "LITTLE_ENDIAN"),
        },
        'implementation_use': arr_bytes.slice(122,128)
      },
      'implementation_identifier': {
        'flags': arr_bytes[128],
        'identifier': Static_File_Analyzer.get_ascii(arr_bytes.slice(129,152).filter(i => i > 31)),
        'identifier_suffix': arr_bytes.slice(152,160)
      },
      'unique_id': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(160,168), "LITTLE_ENDIAN"),
      'length_of_extended_attributes': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(168,172), "LITTLE_ENDIAN"),
      'length_of_allocation_descriptors': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(172,176), "LITTLE_ENDIAN"),
      'extended_attributes': [],
      'allocation_descriptors': []
    };

    file_entry.extended_attributes = arr_bytes.slice(176,176+file_entry.length_of_extended_attributes);

    var allocation_descriptors_bytes = arr_bytes.slice(176+file_entry.length_of_extended_attributes,176+file_entry.length_of_extended_attributes+file_entry.length_of_allocation_descriptors);
    var current_ad_byte = 0;

    while (current_ad_byte < allocation_descriptors_bytes.length) {
      file_entry.allocation_descriptors.push({
        'extent_length': Static_File_Analyzer.get_int_from_bytes(allocation_descriptors_bytes.slice(current_ad_byte,current_ad_byte+=4), "LITTLE_ENDIAN"),
        'extent_position': Static_File_Analyzer.get_int_from_bytes(allocation_descriptors_bytes.slice(current_ad_byte,current_ad_byte+=4), "LITTLE_ENDIAN"),
      });
    }

    return file_entry;
  }

  /**
   * Parse the File Identifier Descriptor in Universal Disk Format.
   * There will be multiple File Identifier Descriptors, one for each file and directory.
   *
   * @see https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf - 14.4 File Identifier Descriptor
   *
   * @param {array}   arr_bytes The array of bytes starting at the File Identifier Descriptor start byte.
   * @return {object} The parsed File Identifier Descriptor
   */
  static parse_file_identifier_descriptor(arr_bytes) {
    var descriptors = [];
    var current_byte = 0;

    while (arr_bytes[current_byte] > 0 && arr_bytes[current_byte+1] > 0) {
      var file_characteristics = Universal_Disk_Format_Parser.get_binary_array([arr_bytes[current_byte+18]]).reverse();
      var file_identifier_descriptor = {
        'descriptor_tag': Universal_Disk_Format_Parser.parse_descriptor_tag(arr_bytes.slice(current_byte,current_byte+=16)),
        'file_version_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(current_byte,current_byte+=2), "LITTLE_ENDIAN"),
        'file_characteristics': {
          'hidden': (file_characteristics[0] == 1) ? true : false,
          'directory': (file_characteristics[1] == 1) ? true : false,
          'parent': (file_characteristics[3] == 1) ? true : false
        },
        'length_of_file_identifier': arr_bytes[current_byte+=1],
        'icb': {
          'extent_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(current_byte++,current_byte+=4), "LITTLE_ENDIAN"),
          'logical_block_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(current_byte,current_byte+=4), "LITTLE_ENDIAN"),
          'partition_reference_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(current_byte,current_byte+=2), "LITTLE_ENDIAN"),
          'ad_imp_use': {
            'flags': Universal_Disk_Format_Parser.get_binary_array(arr_bytes.slice(current_byte,current_byte+=2)),
            'udf_unique_id': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(current_byte,current_byte+=4), "LITTLE_ENDIAN")
          }
        },
        'length_of_implementation_use': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(current_byte,current_byte+=2), "LITTLE_ENDIAN"),
        'implementation_use':[],
        'file_identifier': "",
        'padding_length': 0
      };

      file_identifier_descriptor.implementation_use = arr_bytes.slice(current_byte, current_byte+=file_identifier_descriptor.length_of_implementation_use);
      file_identifier_descriptor.file_identifier = Static_File_Analyzer.get_ascii(arr_bytes.slice(current_byte, current_byte+=file_identifier_descriptor.length_of_file_identifier).filter(i => i > 31));
      file_identifier_descriptor.padding_length = 4 - (current_byte % 4);
      current_byte += file_identifier_descriptor.padding_length;

      descriptors.push(file_identifier_descriptor);
    }

    return descriptors;
  }

  /**
   * Parse the ICB Tag in Universal Disk Format.
   *
   * @see https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf - 14.6 ICB Tag
   *
   * @param {array}   arr_bytes The array of bytes starting at the ICB Tag start byte.
   * @return {object} The parsed ICB Tag
   */
  static parse_icb_tag(arr_bytes) {
    var icb_tag = {
      'prior_recorded_number_of_direct_entries': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(0,4), "LITTLE_ENDIAN"),
      'strategy_type': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(4,6), "LITTLE_ENDIAN"),
      'strategy_parameter': arr_bytes.slice(6,8),
      'max_number_of_entries': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(8,10), "LITTLE_ENDIAN"),
      'file_type': arr_bytes[11],
      'parent_icb_location': {
        'logical_block_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(12,16), "LITTLE_ENDIAN"),
        'partition_reference_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(16,18), "LITTLE_ENDIAN")
      },
      'flags': arr_bytes.slice(18,20)
    };

    return icb_tag;
  }

  /**
   * Parse the Implementation Use Volume Descriptor in Universal Disk Format.
   *
   * @see https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf - 10.4 Implementation Use Volume Descriptor
   *
   * @param {array}   arr_bytes The array of bytes starting at the Implementation Use Volume Descriptor start byte.
   * @return {object} The parsed Implementation Use Volume Descriptor
   */
  static parse_implementation_use_volume_descriptor(arr_bytes) {
    var implementation_use_volume_descriptor = {
      'descriptor_tag': Universal_Disk_Format_Parser.parse_descriptor_tag(arr_bytes.slice(0,16)),
      'volume_descriptor_sequence_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(16,20), "LITTLE_ENDIAN"),
      'implementation_identifier': {
        'flags': arr_bytes[20],
        'identifier': Static_File_Analyzer.get_ascii(arr_bytes.slice(21,44).filter(i => i > 31)),
        'identifier_suffix': arr_bytes.slice(44,52),
        'implementation_use': arr_bytes.slice(52,512)
      },
    };

    if (implementation_use_volume_descriptor.implementation_identifier.identifier == "*UDF LV Info") {
      var use_bytes = implementation_use_volume_descriptor.implementation_identifier.implementation_use;

      implementation_use_volume_descriptor['lv_information'] = {
        'lvi_charset': {
          'character_set_type': use_bytes[0],
          'character_set_information': use_bytes.slice(1,64)
        },
        'logical_volume_identifier': Static_File_Analyzer.get_ascii(use_bytes.slice(64,192).filter(i => i > 31)),
        'lv_info1': Static_File_Analyzer.get_ascii(use_bytes.slice(192,228).filter(i => i > 31)),
        'lv_info2': Static_File_Analyzer.get_ascii(use_bytes.slice(228,264).filter(i => i > 31)),
        'lv_info3': Static_File_Analyzer.get_ascii(use_bytes.slice(264,300).filter(i => i > 31)),
        'implementation_identifier': {
          'flags': arr_bytes[300],
          'identifier': Static_File_Analyzer.get_ascii(arr_bytes.slice(301,324).filter(i => i > 31)),
          'identifier_suffix': arr_bytes.slice(324,332)
        },
        'implementation_use': use_bytes.slice(332,460),
      };
    }

    return implementation_use_volume_descriptor;
  }

  /**
   * Parse the Logical Volume Integrity Descriptor in Universal Disk Format.
   *
   * @see https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf - 10.10 Logical Volume Integrity Descriptor
   *
   * @param {array}   arr_bytes The array of bytes starting at the Logical Volume Integrity Descriptor start byte.
   * @return {object} The parsed Logical Volume Integrity Descriptor
   */
  static parse_logical_volume_integrity_descriptor(arr_bytes) {
    var logical_volume_integrity_descriptor = {
      'descriptor_tag': Universal_Disk_Format_Parser.parse_descriptor_tag(arr_bytes.slice(0,16)),
      'recording_date_and_time': Universal_Disk_Format_Parser.get_ecma_timestamp(arr_bytes.slice(16,28)),
      'integrity_type': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(28,32), "LITTLE_ENDIAN"),
      'next_integrity_extent': {
        'extent_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(32,36), "LITTLE_ENDIAN"),
        'extent_location': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(36,40), "LITTLE_ENDIAN"),
      },
      'logical_volume_contents_use': arr_bytes.slice(40,72),
      'number_of_partitions': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(72,76), "LITTLE_ENDIAN"),
      'length_of_implementation_use': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(76,80), "LITTLE_ENDIAN"),
      'free_space_table': [],
      'size_table': [],
      'implementation_use': {}
    };

    var current_byte = 80;

    for (var i=0; i<logical_volume_integrity_descriptor.number_of_partitions; i++) {
      logical_volume_integrity_descriptor.free_space_table.push(Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(current_byte,current_byte+=4), "LITTLE_ENDIAN"));
    }

    for (var i=0; i<logical_volume_integrity_descriptor.number_of_partitions; i++) {
      logical_volume_integrity_descriptor.size_table.push(Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(current_byte,current_byte+=4), "LITTLE_ENDIAN"));
    }

    logical_volume_integrity_descriptor.implementation_use = {
      'flags': arr_bytes[current_byte],
      'identifier': Static_File_Analyzer.get_ascii(arr_bytes.slice(current_byte++,current_byte+=23).filter(i => i > 31)),
      'identifier_suffix': arr_bytes.slice(current_byte,current_byte+=8)
    };

    return logical_volume_integrity_descriptor;
  }

  /**
   * Parse the Logical Volume Descriptor in Universal Disk Format.
   *
   * @see https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf - 10.6 Logical Volume Descriptor
   *
   * @param {array}   arr_bytes The array of bytes starting at the Logical Volume Descriptor start byte.
   * @return {object} The parsed Logical Volume Descriptor
   */
  static parse_logical_volume_descriptor(arr_bytes) {
    var logical_volume_descriptor = {
      'descriptor_tag': Universal_Disk_Format_Parser.parse_descriptor_tag(arr_bytes.slice(0,16)),
      'volume_descriptor_sequence_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(16,20), "LITTLE_ENDIAN"),
      'descriptor_character_set': {
        'character_set_type': arr_bytes[20],
        'character_set_information': arr_bytes.slice(21,84)
      },
      'logical_volume_identifier': Static_File_Analyzer.get_ascii(arr_bytes.slice(84,212).filter(i => i > 31)),
      'logical_block_size': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(212,216), "LITTLE_ENDIAN"),
      'domain_identifier': {
        'flags': arr_bytes[216],
        'identifier': Static_File_Analyzer.get_ascii(arr_bytes.slice(217,240).filter(i => i > 31)),
        'identifier_suffix': arr_bytes.slice(240,248)
      },
      'logical_volume_contents_use': arr_bytes.slice(248,264),
      'map_table_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(264,268), "LITTLE_ENDIAN"),
      'number_of_partition_maps': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(268,272), "LITTLE_ENDIAN"),
      'implementation_identifier': {
        'flags': arr_bytes[272],
        'identifier': Static_File_Analyzer.get_ascii(arr_bytes.slice(273,296).filter(i => i > 31)),
        'identifier_suffix': arr_bytes.slice(296,304)
      },
      'implementation_use': arr_bytes.slice(304,432),
      'integrity_sequence_extent': {
        'extent_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(432,436), "LITTLE_ENDIAN"),
        'extent_location': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(436,440), "LITTLE_ENDIAN"),
      },
      'raw_partition_maps': arr_bytes.slice(440,512),
      'partition_maps': []
    };

    var partition_index = 0;

    for (var i2=0; i2<logical_volume_descriptor.number_of_partition_maps; i2++) {
      var partition_map = {
        'partition_map_type': logical_volume_descriptor.raw_partition_maps[partition_index],
        'partition_map_length': logical_volume_descriptor.raw_partition_maps[partition_index+1],
        'partition_mapping': {}
      }

      if (logical_volume_descriptor.raw_partition_maps[partition_index] == 1) {
        logical_volume_descriptor.partition_maps.push({
          'partition_map_type': logical_volume_descriptor.raw_partition_maps[partition_index],
          'partition_map_length': logical_volume_descriptor.raw_partition_maps[partition_index+1],
          'volume_sequence_number': Static_File_Analyzer.get_int_from_bytes(logical_volume_descriptor.raw_partition_maps.slice(partition_index+2,partition_index+4), "LITTLE_ENDIAN"),
          'partition_number': Static_File_Analyzer.get_int_from_bytes(logical_volume_descriptor.raw_partition_maps.slice(partition_index+4,partition_index+6), "LITTLE_ENDIAN")
        });
      } else if (partition_map.partition_map_type == 2) {
        // See: http://www.osta.org/specs/pdf/udf260.pdf - 2.2.10 Metadata Partition Map
        // Note: partition_type_identifier seems to sometimes have a trailing version of the form 3 bytes: 0x50 0x02 0x06

        logical_volume_descriptor.partition_maps.push({
          'partition_map_type': logical_volume_descriptor.raw_partition_maps[partition_index],
          'partition_map_length': logical_volume_descriptor.raw_partition_maps[partition_index+1],
          'reserved1': logical_volume_descriptor.raw_partition_maps.slice(partition_index+2,partition_index+4),
          'partition_type_identifier': Static_File_Analyzer.get_ascii(logical_volume_descriptor.raw_partition_maps.slice(partition_index+4,partition_index+36).filter(i => i > 31)),
          'volume_sequence_number': Static_File_Analyzer.get_int_from_bytes(logical_volume_descriptor.raw_partition_maps.slice(partition_index+36,partition_index+38), "LITTLE_ENDIAN"),
          'partition_number': Static_File_Analyzer.get_int_from_bytes(logical_volume_descriptor.raw_partition_maps.slice(partition_index+38,partition_index+40), "LITTLE_ENDIAN"),
          'metadata_file_location': Static_File_Analyzer.get_int_from_bytes(logical_volume_descriptor.raw_partition_maps.slice(partition_index+40,partition_index+44), "LITTLE_ENDIAN"),
          'metadata_mirror_file_location': Static_File_Analyzer.get_int_from_bytes(logical_volume_descriptor.raw_partition_maps.slice(partition_index+44,partition_index+48), "LITTLE_ENDIAN"),
          'metadata_bitmap_file_location': Static_File_Analyzer.get_int_from_bytes(logical_volume_descriptor.raw_partition_maps.slice(partition_index+48,partition_index+52), "LITTLE_ENDIAN"),
          'allocation_unit_size': Static_File_Analyzer.get_int_from_bytes(logical_volume_descriptor.raw_partition_maps.slice(partition_index+52,partition_index+56), "LITTLE_ENDIAN"),
          'alignment_unit_size': Static_File_Analyzer.get_int_from_bytes(logical_volume_descriptor.raw_partition_maps.slice(partition_index+56,partition_index+58), "LITTLE_ENDIAN"),
          'flags': logical_volume_descriptor.raw_partition_maps[partition_index+58],
          'reserved2': logical_volume_descriptor.raw_partition_maps.slice(partition_index+59,partition_index+64)
        });
      }

      partition_index += logical_volume_descriptor.raw_partition_maps[partition_index+1];
    }

    logical_volume_descriptor['file_set_descriptor_location'] = {
      'length': Static_File_Analyzer.get_int_from_bytes(logical_volume_descriptor.logical_volume_contents_use.slice(0,4), "LITTLE_ENDIAN"),
      'logical_block_number': Static_File_Analyzer.get_int_from_bytes(logical_volume_descriptor.logical_volume_contents_use.slice(4,8), "LITTLE_ENDIAN"),
      'partition_reference_number': Static_File_Analyzer.get_int_from_bytes(logical_volume_descriptor.logical_volume_contents_use.slice(8,10), "LITTLE_ENDIAN"),
      'implementation_use': logical_volume_descriptor.logical_volume_contents_use.slice(10,16)
    };

    return logical_volume_descriptor;
  }

  /**
   * Parse the Partition Descriptor in Universal Disk Format.
   *
   * @see https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf - 10.5 Partition Descriptor
   *
   * @param {array}   arr_bytes The array of bytes starting at the Partition Descriptor start byte.
   * @return {object} The parsed Partition Descriptor
   */
  static parse_partition_descriptor(arr_bytes) {
    var partition_descriptor = {
      'descriptor_tag': Universal_Disk_Format_Parser.parse_descriptor_tag(arr_bytes.slice(0,16)),
      'volume_descriptor_sequence_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(16,20), "LITTLE_ENDIAN"),
      'flags': arr_bytes.slice(20,22),
      'partition_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(22,24), "LITTLE_ENDIAN"),
      'partition_contents': {
        'flags': arr_bytes[24],
        'identifier': Static_File_Analyzer.get_ascii(arr_bytes.slice(25,48).filter(i => i > 31)),
        'identifier_suffix': arr_bytes.slice(48,56)
      },
      'partition_contents_use': arr_bytes.slice(56,184),
      'access_type': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(184,188), "LITTLE_ENDIAN"),
      'partition_starting_location': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(188,192), "LITTLE_ENDIAN"),
      'partition_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(192,196), "LITTLE_ENDIAN"),
      'implementation_identifier': {
        'flags': arr_bytes[196],
        'identifier': Static_File_Analyzer.get_ascii(arr_bytes.slice(197,220).filter(i => i > 31)),
        'identifier_suffix': arr_bytes.slice(220,228)
      },
      'implementation_use': arr_bytes.slice(228,356),
      'reserved': arr_bytes.slice(356,512)
    };

    var use_bytes = partition_descriptor.partition_contents_use;

    partition_descriptor['partition_header_descriptor'] = {
      'unallocated_space_table': {
        'extent_length': Static_File_Analyzer.get_int_from_bytes(use_bytes.slice(0,4), "LITTLE_ENDIAN"),
        'extent_location': Static_File_Analyzer.get_int_from_bytes(use_bytes.slice(4,8), "LITTLE_ENDIAN"),
      },
      'unallocated_space_bitmap': {
        'extent_length': Static_File_Analyzer.get_int_from_bytes(use_bytes.slice(8,12), "LITTLE_ENDIAN"),
        'extent_location': Static_File_Analyzer.get_int_from_bytes(use_bytes.slice(12,16), "LITTLE_ENDIAN"),
      },
      'partition_integrity_table': {
        'extent_length': Static_File_Analyzer.get_int_from_bytes(use_bytes.slice(16,20), "LITTLE_ENDIAN"),
        'extent_location': Static_File_Analyzer.get_int_from_bytes(use_bytes.slice(20,24), "LITTLE_ENDIAN"),
      },
      'freed_space_table': {
        'extent_length': Static_File_Analyzer.get_int_from_bytes(use_bytes.slice(24,28), "LITTLE_ENDIAN"),
        'extent_location': Static_File_Analyzer.get_int_from_bytes(use_bytes.slice(28,32), "LITTLE_ENDIAN"),
      },
      'freed_space_bitmap': {
        'extent_length': Static_File_Analyzer.get_int_from_bytes(use_bytes.slice(32,36), "LITTLE_ENDIAN"),
        'extent_location': Static_File_Analyzer.get_int_from_bytes(use_bytes.slice(36,40), "LITTLE_ENDIAN"),
      },
      'reserved': use_bytes.slice(40,128)
    };

    return partition_descriptor;
  }

  /**
   * Parse the Primary Volume Descriptor in Universal Disk Format.
   *
   * @see https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf - 10.1 Primary Volume Descriptor
   *
   * @param {array}   arr_bytes The array of bytes starting at the Primary Volume Descriptor start byte.
   * @return {object} The parsed Primary Volume Descriptor
   */
  static parse_primary_volume_descriptor(arr_bytes) {
    var primary_volume_descriptor = {
      'descriptor_tag': Universal_Disk_Format_Parser.parse_descriptor_tag(arr_bytes.slice(0,16)),
      'volume_descriptor_sequence_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(16,20), "LITTLE_ENDIAN"),
      'primary_volume_descriptor_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(20,24), "LITTLE_ENDIAN"),
      'volume_identifier': Static_File_Analyzer.get_ascii(arr_bytes.slice(24,56).filter(i => i > 31)),
      'volume_sequence_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(56,58), "LITTLE_ENDIAN"),
      'maximum_volume_sequence_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(58,60), "LITTLE_ENDIAN"),
      'interchange_level': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(60,62), "LITTLE_ENDIAN"),
      'maximum_interchange_level': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(62,64), "LITTLE_ENDIAN"),
      'character_set_list': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(64,68), "LITTLE_ENDIAN"),
      'maximum_character_set_list': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(68,72), "LITTLE_ENDIAN"),
      'volume_set_identifier': Static_File_Analyzer.get_ascii(arr_bytes.slice(72,200).filter(i => i > 31)),
      'descriptor_character_set': {
        'character_set_type': arr_bytes[200],
        'character_set_information': arr_bytes.slice(201,264)
      },
      'explanatory_character_set': {
        'character_set_type': arr_bytes[264],
        'character_set_information': arr_bytes.slice(265,328)
      },
      'volume_abstract': {
        'extent_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(328,332), "LITTLE_ENDIAN"),
        'extent_location': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(332,336), "LITTLE_ENDIAN"),
      },
      'volume_copyright_notice': {
        'extent_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(336,340), "LITTLE_ENDIAN"),
        'extent_location': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(340,344), "LITTLE_ENDIAN"),
      },
      'recording_date_and_time': Universal_Disk_Format_Parser.get_ecma_timestamp(arr_bytes.slice(376,388)),
      'implementation_identifier': {
        'flags': arr_bytes[388],
        'identifier': Static_File_Analyzer.get_ascii(arr_bytes.slice(389,412).filter(i => i > 31)),
        'identifier_suffix': arr_bytes.slice(412,420)
      },
      'implementation_use': arr_bytes.slice(420,484),
      'predecessor_volume_descriptor_sequence_location': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(484,488), "LITTLE_ENDIAN"),
      'flags': arr_bytes.slice(488,490),
      'reserved': arr_bytes.slice(490,512)
    };

    return primary_volume_descriptor;
  }

  /**
   * Parses a sector for a Universal Disk Format file.
   *
   * @see https://wiki.osdev.org/UDF
   *
   * @param {array}    bytes_buffer Byte buffer starting at the sector to parse.
   * @param {integer}  sector_size  The byte size of sectors in this UDF file.
   * @param {integer}  sector_start The byte starting location within the file of this sector.
   * @return {Object}  An object with the parsed sector.
   */
  static parse_sector(bytes_buffer, sector_size, sector_start) {
    var sector_descriptor_buffer = bytes_buffer.slice(0, 16);
    var descriptor_tag = Universal_Disk_Format_Parser.parse_descriptor_tag(sector_descriptor_buffer);
    var udf_sector;

    if (descriptor_tag.valid) {
      if (descriptor_tag.tag_identifier == 0x0001) {
        // Primary Volume Descriptor
        var primary_volume_descriptor = Universal_Disk_Format_Parser.parse_primary_volume_descriptor(bytes_buffer.slice(0,512));

        udf_sector = {
          'type': "Primary Volume Descriptor",
          'byte_location': sector_start,
          'descriptor': primary_volume_descriptor
        };
      } else if (descriptor_tag.tag_identifier == 0x0002) {
        // Anchor Volume Descriptor Pointer
        var anchor_volume_descriptor_pointer = Universal_Disk_Format_Parser.parse_anchor_volume_descriptor_pointer(bytes_buffer.slice(0,512));

        udf_sector = {
          'type': "Anchor Volume Descriptor Pointer",
          'byte_location': sector_start,
          'descriptor': anchor_volume_descriptor_pointer
        };
      } else if (descriptor_tag.tag_identifier == 0x0003) {
        // Volume Descriptor Pointer, not implemented
        udf_sector = {
          'type': "Volume Descriptor Pointer",
          'byte_location': sector_start,
          'descriptor': {}
        };
      } else if (descriptor_tag.tag_identifier == 0x0004) {
        // Implementation Use Volume Descriptor
        var implementation_use_volume_descriptor = Universal_Disk_Format_Parser.parse_implementation_use_volume_descriptor(bytes_buffer.slice(0,512));

        udf_sector = {
          'type': "Implementation Use Volume Descriptor",
          'byte_location': sector_start,
          'descriptor': implementation_use_volume_descriptor
        };
      } else if (descriptor_tag.tag_identifier == 0x0005) {
        // Partition Descriptor
        var partition_descriptor = Universal_Disk_Format_Parser.parse_partition_descriptor(bytes_buffer.slice(0,512));
        partition_descriptor['byte_start'] = (sector_size * partition_descriptor.partition_starting_location);

        udf_sector = {
          'type': "Partition Descriptor",
          'byte_location': sector_start,
          'descriptor': partition_descriptor
        };
      } else if (descriptor_tag.tag_identifier == 0x0006) {
        // Logical Volume Descriptor
        var logical_volume_descriptor = Universal_Disk_Format_Parser.parse_logical_volume_descriptor(bytes_buffer);

        udf_sector = {
          'type': "Logical Volume Descriptor",
          'byte_location': sector_start,
          'descriptor': logical_volume_descriptor
        };
      } else if (descriptor_tag.tag_identifier == 0x0007) {
        // Unallocated Space Descriptor
        var unallocated_space_descriptor = Universal_Disk_Format_Parser.parse_unallocated_space_descriptor(bytes_buffer);

        udf_sector = {
          'type': "Unallocated Space Descriptor",
          'byte_location': sector_start,
          'descriptor': unallocated_space_descriptor
        };
      } else if (descriptor_tag.tag_identifier == 0x0008) {
        // Terminating Descriptor
        var terminating_descriptor = Universal_Disk_Format_Parser.parse_terminating_descriptor(bytes_buffer.slice(0,512));;

        udf_sector = {
          'type': "Terminating Descriptor",
          'byte_location': sector_start,
          'descriptor': terminating_descriptor
        };
      } else if (descriptor_tag.tag_identifier == 0x0009) {
        // Logical Volume Integrity Descriptor
        var logical_volume_integrity_descriptor = Universal_Disk_Format_Parser.parse_logical_volume_integrity_descriptor(bytes_buffer);

        udf_sector = {
          'type': "Logical Volume Integrity Descriptor",
          'byte_location': sector_start,
          'descriptor': logical_volume_integrity_descriptor
        };
      } else if (descriptor_tag.tag_identifier == 0x0100) {
        // File Set Descriptor, not implemented
        udf_sector = {
          'type': "File Set Descriptor",
          'byte_location': sector_start,
          'descriptor': {}
        };
      } else if (descriptor_tag.tag_identifier == 0x0101) {
        // File Identifier Descriptor
        var file_identifier_descriptor = Universal_Disk_Format_Parser.parse_file_identifier_descriptor(bytes_buffer);

        udf_sector = {
          'type': "File Identifier Descriptor",
          'byte_location': sector_start,
          'descriptor': file_identifier_descriptor
        };
      } else if (descriptor_tag.tag_identifier == 0x0102) {
        // Allocation Extent Descriptor, not implemented
        udf_sector = {
          'type': "Allocation Extent Descriptor",
          'byte_location': sector_start,
          'descriptor': {}
        };
      } else if (descriptor_tag.tag_identifier == 0x0103) {
        // Indirect Entry, not implemented
        udf_sector = {
          'type': "Indirect Entry",
          'byte_location': sector_start,
          'descriptor': {}
        };
      } else if (descriptor_tag.tag_identifier == 0x0104) {
        // Terminating Descriptor
        var terminating_descriptor = Universal_Disk_Format_Parser.parse_terminating_descriptor(bytes_buffer.slice(0,512));;

        udf_sector = {
          'type': "Terminating Descriptor",
          'byte_location': sector_start,
          'descriptor': terminating_descriptor
        };
      } else if (descriptor_tag.tag_identifier == 0x0105) {
        // File Entry
        var file_entry = Universal_Disk_Format_Parser.parse_file_entry(bytes_buffer);

        udf_sector = {
          'type': "File Entry",
          'byte_location': sector_start,
          'descriptor': file_entry
        };
      } else if (descriptor_tag.tag_identifier == 0x0106) {
        // Extended Attribute Header Descriptor, not implemented
        udf_sector = {
          'type': "Extended Attribute Header Descriptor",
          'byte_location': sector_start,
          'descriptor': {}
        };
      } else if (descriptor_tag.tag_identifier == 0x0107) {
        // Unallocated Space Entry, not implemented
        udf_sector = {
          'type': "Unallocated Space Entry",
          'byte_location': sector_start,
          'descriptor': {}
        };
      } else if (descriptor_tag.tag_identifier == 0x0108) {
        // Space Bitmap Descriptor, not implemented
        udf_sector = {
          'type': "Space Bitmap Descriptor",
          'byte_location': sector_start,
          'descriptor': {}
        };
      } else if (descriptor_tag.tag_identifier == 0x0109) {
        // Partition Integrity Entry, not implemented
        udf_sector = {
          'type': "Partition Integrity Entry",
          'byte_location': sector_start,
          'descriptor': {}
        };
      } else if (descriptor_tag.tag_identifier == 0x010A) {
        // Extended File Entry
        var extended_file_entry = Universal_Disk_Format_Parser.parse_extended_file_entry(bytes_buffer);

        udf_sector = {
          'type': "Extended File Entry",
          'byte_location': sector_start,
          'descriptor': extended_file_entry
        };
      } else {
        // Not a sector
        udf_sector = {
          'type': "invalid",
          'byte_location': sector_start,
          'descriptor': {}
        };
      }
    } else {
      // Not a sector
      udf_sector = {
        'type': "invalid",
        'byte_location': sector_start,
        'descriptor': {}
      };
    }

    return udf_sector;
  }

  /**
   * Parse the Terminating Descriptor in Universal Disk Format.
   *
   * @see https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf - 10.9 Terminating Descriptor
   *
   * @param {array}   arr_bytes The array of bytes starting at the Terminating Descriptor start byte.
   * @return {object} The parsed Terminating Descriptor
   */
  static parse_terminating_descriptor(arr_bytes) {
    var terminating_descriptor = {
      'descriptor_tag': Universal_Disk_Format_Parser.parse_descriptor_tag(arr_bytes.slice(0,16)),
      'reserved': arr_bytes.slice(16,512)
    };

    return terminating_descriptor;
  }

  /**
   * Parse the Unallocated Space Descriptor in Universal Disk Format.
   *
   * @see https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf - 10.8 Unallocated Space Descriptor
   *
   * @param {array}   arr_bytes The array of bytes starting at the Unallocated Space Descriptor start byte.
   * @return {object} The parsed Unallocated Space Descriptor
   */
  static parse_unallocated_space_descriptor(arr_bytes) {
    var unallocated_space_descriptor = {
      'descriptor_tag': Universal_Disk_Format_Parser.parse_descriptor_tag(arr_bytes.slice(0,16)),
      'volume_descriptor_sequence_number': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(16,20), "LITTLE_ENDIAN"),
      'number_of_allocation_descriptors': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(20,24), "LITTLE_ENDIAN"),
      'allocation_descriptors': []
    };

    var current_byte = 24;

    for (var i=0; i<unallocated_space_descriptor.number_of_allocation_descriptors; i++) {
      unallocated_space_descriptor.allocation_descriptors.push({
        'extent_length': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(current_byte,current_byte+=4), "LITTLE_ENDIAN"),
        'extent_location': Static_File_Analyzer.get_int_from_bytes(arr_bytes.slice(current_byte,current_byte+=4), "LITTLE_ENDIAN"),
      });
    }

    return unallocated_space_descriptor;
  }
}
