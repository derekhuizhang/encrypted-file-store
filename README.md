## How To Run
`make test` will test all cstore functionality--adding, extracting, deleting, and listing files.

## Archive Constraints
- Max file name length is 100. Trying to add a file with a longer name will cause an error.
- Max # of files is 2000. 
- If a file with the same base name already exists in the directory, the existing file will be deleted and overwritten.
- In general, the entire archive file should not exceed the running system's memory, as the archive is stored in memory in order to create the hash. 
- Any single file can be a max of ~ 4.2 gb, the maximum file size that can be stored in an unsigned long.
- Extracting a file will return it in the current directory, with the word ".extracted" appended to the end of the file.
- Archive is created on `archive -p [password] add [archive name] [file names]`, if the archive name doesn't exist.

## Design Decisions
The archive file contains two parts. The first 32 bytes is an SHA 256 hash. The rest of the file is a metadata header, followed by the file's data encrypted via AES, using the  CBC mode of operation. The metadata header contains the randomly generated IV, the file size, and other metadata. To encrypt the file, I used the CBC mode of operation because the random generated IV means that every time an identical file is removed or added to the archive, the resulting encrypted data will be different, even if the plaintext consists of similar data. To complete the encryption, each file is padded with 0's to the nearest remainder of 16. 

The first 32 bytes of the archive is an HMAC hash over the rest of the file, with the key provided by a hash over the password and an additional padding. This protects the integrity of the archive because if any file or its metadata is changed or modified in any way, the resulting hash will be different.