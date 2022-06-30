# Lantern Shark
Lantern Shark is a file analyzer written in HTML and JavaScript. It can extract metadata and embedded script code from multiple file types. It also attempts to identify suspicious and malicious attributes of various file types.

A live demo of this project can be viewed [here](https://alecdhuse.github.io/Lantern-Shark/).

# Additional Features
  - Deobfuscation of extracted scripts via inserted comments. Look for the comment caracter followed by the 🦈 shark emoji.

# Notes
This project is under heavy development, and currently only supports a small number of file types.
See the table below for a list of supported file types and types of data extracted from each.

| File Extension | File Type ID | File Attributes | Components List | Metadata | Script Detection | Script Extraction |
| -------------- | ------------ | --------------- | --------------- | -------- | ---------------- | ----------------- |
| ACE            | X            | X               |                 |          |                  |                   |
| DOCX           | X            | X               | X               | X        |                  |                   |
| EXE            | X            | X               |                 |          |                  |                   |
| GZ             | X            | X               |                 |          |                  |                   |
| ISO            | X            | X               |                 |          |                  |                   |
| JPEG           | X            | X               |                 |          |                  |                   |
| LNK            | X            |                 |                 |          | X                | X                 |
| PDF            | X            | X               |                 | X        | X                | X                 |
| RAR            | X            | X               |                 |          |                  |                   |
| RTF            | X            | X               |                 | X        |                  |                   |
| PNG            | X            | X               |                 | X        |                  |                   |
| PPTX           | X            | X               | X               | X        |                  |                   |
| XLS            | X            | X               |                 | X        | X                | X                 |
| XLSB           | X            | X               | X               | X        | X                | X                 |
| XLSX           | X            | X               | X               | X        | X                | X                 |
| XML            | X            |                 |                 |          |                  |                   |
| ZIP            | X            | X               | X               |          |                  |                   |

# CVE Detection
Lantern Shark should be able to detect the following CVEs:

- PDF
  - CVE-2019-7089
  - CVE-2018-4993
- RTF
  - CVE-2017-11882 (Limited Detection)
- XLSB, XLSM, XLSX
  - CVE-2017-11882 (Limited Detection)

# Dependencies
Lantern Shark uses the following libraries:
- Zip.js - Included in this repository but also available from https://gildas-lormeau.github.io/zip.js/core-api.html.
- jQuery - Included in this repository but also available from https://jquery.com/download/

# Credits
- File Icon by Komkrit Noenpoempisut - https://thenounproject.com/icon/file-1876047/ (Purchased for this project)
- Lightning Icon by Oh Rian - https://thenounproject.com/icon/lightning-4945896/ (Purchased for this project)
- Unlock Icon by Andy M - https://thenounproject.com/icon/unlock-4584617/ (Purchased for this project)
