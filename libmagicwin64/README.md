These files are for using libmagic with 64 bit Windows and were compiled using MSYS2.
Hopefully this will save someone else a lot of pain. Huge thanks to the MSYS2 folks 
because getting the tool chain to build this natively was a horrible pain.  

Drop the dlls in C:\Windows\System32 and python magic will import correctly.  
file_magic = magic.Magic(magic_file="c:\path\to\magic.mgc")
