# Extension-Checker (ExtCheck)
# File Signature Analysis Tool

Joseph Avanzato, joeavanzato@gmail.com

Simple script to check files against known file signatures stored in external file ('filesignatures.txt').

Returns events if missing expected signature and checks files for other possible signatures.

Potential usage in determining mislabeled files (.exe labeled as .jpg, etc).

Allows custom extensions, maximum size specifications and outputs detect/skip list to CWD in .txt.

Uses 'filesignatures.txt' to detect file signatures - text file contains rows consisting of 3 columns - Hex Signature, Expected Offset and associated Description/Extension -expected in same directory as script.  

Currently only ~200 file signatures stored, will add many more shortly.

