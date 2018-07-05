@echo off
color 0A
echo d8888b. d8888b.  .d8b.   d888b  .88b  d88.  .d8b.
echo 88  `8D 88  `8D d8' `8b 88' Y8b 88'YbdP`88 d8' `8b
echo 88oodD' 88oobY' 88ooo88 88      88  88  88 88ooo88
echo 88~~~   88`8b   88~~~88 88  ooo 88  88  88 88~~~88
echo 88      88 `88. 88   88 88. ~8~ 88  88  88 88   88
echo 88      88   YD YP   YP  Y888P  YP  YP  YP YP   YP
echo  - XCI to Decrypted XCI v2.1
echo https://gbatemp.net/threads/506954
echo.

echo :: Decrypting .xci's NCA files and finding the biggest NCA...
@hactool.exe -k keys.ini -txci --securedir="xciDecrypted" "%~1" >nul 2>&1
dir "xciDecrypted" /b /o-s > nca_name.txt
set /P nca_file= < nca_name.txt 
del nca_name.txt
echo :: Decrypting Biggest .NCA's romfs to romfs.bin and all exefs files to /exefs... This may take a while...
@hactool.exe -k keys.ini --romfs="xciDecrypted\romfs.bin" --exefsdir="xciDecrypted\exefs" "xciDecrypted\%nca_file%" >nul 2>&1
echo !! === If it says section 0 is corrupt, then you need to obtain more keys than what you already have :(
echo :: Deleting ncas as we dont need them anymore
del "xciDecrypted\*.nca"
echo DONE! You should have a folder: xciDecrypted
echo xciDecrypted should contain an exefs folder and a romfs.bin. It should NOT contain anything else.
pause >nul