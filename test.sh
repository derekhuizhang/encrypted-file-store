PATH=$PATH:./

mkdir -p tests

cd tests

FILE1_DATA="Data for file 1"
FILE2_DATA="Data for file 2"
FILE3_DATA="Data for file 3"

echo "$FILE1_DATA" > file1.txt
echo "$FILE2_DATA" > file2.txt
echo "$FILE3_DATA" > file3.txt

cstore add -p password archive.test file1.txt file2.txt

# Test wrong password
WRONG_PASS=$(cstore add -p wrong-pass archive.test file3.txt 2>&1 > /dev/null)
if [ "$WRONG_PASS" != "invalid password or archive" ]
then
    echo "Password protection failed"
    cd ..
    rm -r tests
    exit 1
fi 

# Test adding nonexistent file
FILE_DNE_ADD=$(cstore add -p password archive.test file4.txt 2>&1 > /dev/null)
if [ "$FILE_DNE_ADD" != "file file4.txt does not exist or cannot be opened" ]
then
    echo "Failed to give correct error on adding nonexistent file"
    cd ..
    rm -r tests
    exit 1
fi 

# Test listing files
LIST_RESULT=$(cstore list archive.test)
if [ "$LIST_RESULT" != $'file1.txt\nfile2.txt' ]
then
    echo "Failed to list files"
    cd ..
    rm -r tests
    exit 1
fi 

# Test extracting files
cstore extract -p password archive.test file1.txt file2.txt

FILE1_EXTRACTED=$(<file1.txt.extracted)
FILE2_EXTRACTED=$(<file2.txt.extracted)
if [ "$FILE1_EXTRACTED" != "$FILE1_DATA" ] || [ "$FILE2_EXTRACTED" != "$FILE2_DATA" ]
then
    echo "Failed to extract file1.txt or file2.txt"
    cd ..
    rm -r tests
    exit 1
fi
rm *.extracted

# Tests deleting files
cstore delete -p password archive.test file1.txt
cstore extract -p password archive.test file2.txt
FILE2_EXTRACTED=$(<file2.txt.extracted)
LIST_RESULT=$(cstore list archive.test)
if [ "$LIST_RESULT" != $'file2.txt' ] || [ "$FILE2_EXTRACTED" != "$FILE2_DATA" ]
then
    echo "Failed to delete file1.txt"
    cd ..
    rm -r tests
    exit 1
fi 
rm *.extracted

# Test extracting and deleting files not in archive
FILE_DNE_EXTRACT=$(cstore extract -p password archive.test file3.txt 2>&1 > /dev/null)
FILE_DNE_DELETE=$(cstore delete -p password archive.test file4.txt 2>&1 > /dev/null)
if [ "$FILE_DNE_EXTRACT" != "file file3.txt could not be found in archive" ] || [ "$FILE_DNE_DELETE" != "file file4.txt could not be found in archive" ] 
then 
    echo "Failed to give correct error on extracting or deleting file not in archive"
    cd ..
    rm -r tests
    exit 1
fi

# Tests adding duplicate files--should only be in archive once
cstore add -p password archive.test file3.txt file3.txt file3.txt
cstore add -p password archive.test file3.txt 
LIST_RESULT=$(cstore list archive.test)
cstore extract -p password archive.test file2.txt file3.txt
FILE2_EXTRACTED=$(<file2.txt.extracted)
FILE3_EXTRACTED=$(<file3.txt.extracted)
if [ "$LIST_RESULT" != $'file2.txt\nfile3.txt' ] || [ "$FILE2_EXTRACTED" != "$FILE2_DATA" ] || [ "$FILE3_EXTRACTED" != "$FILE3_DATA" ]
then
    echo "Failed to properly handle duplicate file adds"
    cd ..
    rm -r tests
    exit 1
fi 
rm *.extracted

# Tests deleting all files 
cstore delete -p password archive.test file2.txt file3.txt
LIST_RESULT=$(cstore list archive.test)
if [ "$LIST_RESULT" != "" ]
then
    echo "Failed to delete all files"
    cd ..
    rm -r tests
    exit 1
fi 

echo "All tests successfully passed!"
cd ..
rm -r tests