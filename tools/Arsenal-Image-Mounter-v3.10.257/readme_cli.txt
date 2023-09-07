Please read "Arsenal Recon - End User License Agreement.txt" carefully before using this software.

Arsenal Image Mounter offers two command-line interface executables:

Arsenal Image Mounter CLI (a/k/a AIM CLI, aim_cli.exe) is a .NET tool that provides an integrated command line interface to Arsenal Image Mounter's virtual SCSI miniport driver. Most of Arsenal Image Mounter’s core functionality is available with AIM CLI. The command “AIM_CLI --?” displays basic syntax for using AIM CLI. AIM CLI mounts disk images in read-only mode by default. AIM CLI is provided within the Arsenal Image Mounter download.

Arsenal Image Mounter Low Level (a/k/a AIM LL, aim_ll.exe) is a tool that does not use .NET and provides more “low level” access to the Arsenal Image Mounter driver. The command “AIM_LL --?” displays basic syntax for using AIM LL. AIM LL mounts disk images in write-original mode by default, to maintain compatibility with existing scripts. AIM LL is largely deprecated and is only available directly from Arsenal.

Please note: 
•   Arsenal Image Mounter CLI and Low Level should normally be run with administrative privileges, but converting disk images from one format to another without mounting (and without using physical disks as targets) and calculating checksums can be done without administrative privileges.
•   If you would like to use AIM CLI or LL executables to interact with EnCase (E01 and Ex01), AFF4, or qcow/qcow2 disk images, you must make the Libewf (libewf.dll), LibAFF4 (libaff4.dll), and qcow/qcow2 (libqcow.dll) libraries available in the expected (/lib/x64) or same folder as the AIM CLI or LL executable.

Also note that AIM GUI actively onlines partitions within mounted/attached disks, but AIM CLI does not. Mounting/attaching a disk with AIM CLI is similar to simply attaching a physical disk to Windows without any extra logic, so (for example) Windows policy on the forensic workstation or file system errors within the mounted/attached disk may result (at least initially) in offline partitions and a lack of drive letter assignments.

Particular examples of Arsenal Image Mounter CLI syntax:

#mount an E01 forensic disk image with the write-temporary mount option and fake disk signature, then automatically delete the differencing file
aim_cli.exe --mount --fakesig --filename=C:\path\Win10Disk.E01 --provider=libewf --writeoverlay=C:\path\Win10Disk.E01.diff --autodelete

#mount a dd raw disk image with the write-original mount option
aim_cli.exe --mount --writable --filename=C:\path\Win10Disk.dd

#mount a VMDK virtual machine disk image with the read-only mount option
aim_cli.exe --mount --readonly --filename=C:\path\Win10Disk.vmdk --provider=DiscUtils

#convert an E01 forensic disk image to a new dd raw disk image, without mounting
aim_cli.exe --filename=Win10Disk.E01 --provider=LibEWF --convert=rawconversion.dd

#save an already mounted E01 forensic disk image (using disk id from AIM) to a dd raw disk image
aim_cli.exe --device=000200 --saveas=rawoutput.dd

#save an already mounted E01 forensic disk image (using disk device name from AIM) to a dd raw disk image
aim_cli.exe --device=\\?\physicaldrive4 --saveas=rawoutput.dd

#restore an E01 forensic disk image to an actual physical disk
aim_cli.exe --filename=Win10Disk.E01 --provider=LibEwf --convert=\\?\PhysicalDrive4

Detailed Arsenal Image Mounter CLI syntax:

#mount a raw/forensic/virtual machine disk image as a "real" disk
aim_cli.exe --mount[:removable|:cdrom] [--buffersize=bytes] [--readonly] [--writable] [--fakesig] [--fakembr] --filename=imagefilename --provider=DiscUtils|LibEWF|LibAFF4|MultipartRaw|None [--writeoverlay=differencingimagefile] [--autodelete] [--background]

#start shared memory service mode, for mounting from other applications
aim_cli.exe --name=objectname [--buffersize=bytes] [--readonly] [--writable] [--fakembr] --filename=imagefilename --provider=DiscUtils|LibEWF|LibAFF4|MultipartRaw|None [--background]

#start TCP/IP service mode, for mounting from other computers
aim_cli.exe [--ipaddress=listenaddress] --port=tcpport [--readonly] [--writable] [--fakembr] --filename=imagefilename --provider=DiscUtils|LibEWF|LibAFF4|MultipartRaw|None [--background]

#convert a disk image without mounting
aim_cli.exe [--fakembr] --filename=imagefilename --provider=DiscUtils|LibEWF|LibAFF4|MultipartRaw|None --convert=outputimagefilename [--variant=fixed|dynamic] [--background]

#calculate MD5, SHA1, or SHA256 checksum over disk image contents without mounting (all three caculated if a specific checksum is not specified)
aim_cli.exe --filename=imagefilename --provider=DiscUtils|LibEWF|LibAFF4|MultipartRaw|None --checksum=[MD5|SHA1|SHA256]

#save a new disk image after mounting
aim_cli.exe --device=sixdigitdevicenumber|\\?\physicaldriveN --saveas=outputimagefilename [--variant=fixed|dynamic] [--background]

#dismount a mounted device
aim_cli.exe --dismount[=sixdigitdevicenumber|\\?\physicaldriveN] [--force]

#restore a disk image to an actual physical disk
aim_cli.exe --filename=imagefilename [--fakembr] --provider=DiscUtils|LibEwf|LibAFF4|MultiPartRaw|None --convert=\\?\PhysicalDriveN [--background]

Additional information regarding Arsenal Image Mounter CLI switches:

The --background switch will re-launch AIM CLI in a new process, detach from the current console window, and continue running in the background.

When the --force switch is used in combination with --dismount, the specified device is dismounted even if it may be in use.

The --autodelete switch will automatically delete the differencing file after the disk image is dismounted.

When converting or saving "physical" objects (whether mounted or not), output type for disk images can be raw (.raw, .dd, .img, .ima, .bin), forensic (.e01), virtual machine (.vhd, .vhdx, .vdi, .vmdk), or dmg (.dmg). AIM CLI selects output type based on the outputimagefilename file extension. For virtual machine disk image formats, the optional --variant switch can be used to specify either fixed or dynamically expanding formats - the default is dynamic. This function can also be used to save virtually mounted objects (such as archives or directories mounted as CD/DVD-ROMs) to raw CD/DVD images, using the extensions .iso and .bin.

Use and License
We chose a dual-license for Arsenal Image Mounter (more specifically, Arsenal Image Mounter’s source code, APIs, and executables) to allow for royalty-free use in open source projects, but require financial support from commercial projects.

Arsenal Consulting, Inc. (d/b/a Arsenal Recon) retains the copyright to Arsenal Image Mounter, including the Arsenal Image Mounter source code, APIs, and executables, being made available under terms of the Affero General Public License v3. Arsenal Image Mounter source code, APIs, and executables may be used in projects that are licensed so as to be compatible with AGPL v3. If your project is not licensed under an AGPL v3 compatible license and you would like to use Arsenal Image Mounter source code, APIs, and/or executables, contact us (sales@ArsenalRecon.com) to obtain alternative licensing.

Contributors to Arsenal Image Mounter must sign the Arsenal Contributor Agreement (“ACA”). The ACA gives Arsenal and the contributor joint copyright interests in the source code.

