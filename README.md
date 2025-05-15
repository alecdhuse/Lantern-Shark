# Lantern Shark
Lantern Shark is a file analyzer written in HTML and JavaScript. It can extract metadata and embedded script code from multiple file types. It also attempts to identify suspicious and malicious attributes of various file types.

A live demo of this project can be viewed [here](https://alecdhuse.github.io/Lantern-Shark/).

# Additional Features
  - Deobfuscation of extracted scripts via inserted comments. Look for the comment character followed by the 🦈 shark emoji.
  - Excel 4.0 Macro emulation and deobfuscation.

# Notes
This project is under heavy development, and currently only supports a small number of file types.
See the table below for a list of supported file types and types of data extracted from each.

| File Extension | File Type ID | File Attributes | Components List | Metadata | Script Detection & Extraction |
| -------------- | ------------ | --------------- | --------------- | -------- | ----------------------------- |
| ACE            | X            | X               |                 |          |                               |
| DLL            | X            |                 |                 |          |                               |
| DOCX           | X            | X               | X               | X        | X                             |
| EML            | X            | X               | X               | X        |                               |
| EXE            | X            | X               |                 |          |                               |
| FODT           | X            |                 |                 |          | X                             |
| GZ             | X            | X               |                 |          |                               |
|[ISO - ISO 9660](https://github.com/alecdhuse/Lantern-Shark/wiki/ISO-9660)| X | X | X | X |                   |
|[ISO - UDF](https://github.com/alecdhuse/Lantern-Shark/wiki/Universal-Disk-Format)| X | X | X | X |           |
| JPEG           | X            | X               |                 | X        |                               |
| LNK            | X            | X               |                 | X        | X                             |
| MSG            | X            | X               | X               | X        |                               |        
| PDF            | X            | X               | Partial         | X        | X                             |    
| PNG            | X            | X               |                 | X        |                               |
| PPTX           | X            | X               | X               | X        |                               |
| RAR            | X            | X               |                 |          |                               |
| RTF            | X            | X               |                 | X        |                               |
| SVG            | X            |                 |                 | X        | X                             |
| TIFF           | X            |                 |                 |          |                               |
| XLS            | X            | X               |                 | X        | X                             |
| XLSB           | X            | X               | X               | X        | X                             |
| XLSX           | X            | X               | X               | X        | X                             |
| XML            | X            |                 |                 | X        |                               |
| ZIP            | X            | X               | X               |          |                               |
| ZLIB           | X            |                 |                 |          |                               |

# CVE Detection
Lantern Shark should be able to detect the following CVEs:

- EML
  - CVE-2024-11182
- FODT
  - CVE-2024-12425
- MSG
  - CVE-2023-23397
- PDF
  - CVE-2024-4367
  - CVE-2019-7089
  - CVE-2018-4993
- RTF
  - CVE-2017-11882 (Limited Detection)
  - CVE-2025-21298
- XLSB, XLSM, XLSX
  - CVE-2017-11882 (Limited Detection)

# Dependencies
Lantern Shark uses the following libraries:
- jQuery - Included in this repository but also available from https://jquery.com/download/
- pako - Included in this repository but also available from https://github.com/nodeca/pako
- Zip.js - Included in this repository but also available from https://gildas-lormeau.github.io/zip.js/core-api.html


# Credits
- File Icon by Komkrit Noenpoempisut - https://thenounproject.com/icon/file-1876047/ (Purchased for this project)
- Lightning Icon by Oh Rian - https://thenounproject.com/icon/lightning-4945896/ (Purchased for this project)
- Unlock Icon by Andy M - https://thenounproject.com/icon/unlock-4584617/ (Purchased for this project)
