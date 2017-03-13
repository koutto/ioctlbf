

	IOCTLbf v0.4 (Proof of Concept)
	
	 _                   _  _       ___ 
	(_)              _  | || |     / __)
	 _  ___   ____ _| |_| || |__ _| |__ 
	| |/ _ \ / ___|_   _) ||  _ (_   __)
	| | |_| ( (___  | |_| || |_) )| |   
	|_|\___/ \____)  \__)\_)____/ |_|   
	
	http://code.google.com/p/ioctlbf/
	http://poppopret.blogspot.com
	
	xst3nz@gmail.com
	
	
=====================================================================
	Overview
=====================================================================

IOCTLbf is just a small tool (Proof of Concept) that can be used to
search vulnerabilities in Windows kernel drivers by performing two
tasks:
	- Scanning for valid IOCTLs codes supported by drivers,
	- Generation-based IOCTL fuzzing
	
An advantage of this tool is that it does not rely on captured
IOCTLs. Therefore, it is able to detect valid IOCTLs codes supported 
by drivers and that are not often, or even never, used by 
applications from user land. For example, it may be the case for:
	- IOCTLs called in very specific conditions (not easy to
	discover and/or to reproduce).
	- IOCTLs used for debugging purpose that are sometimes let in 
	drivers.
	
Once scanning is done and valid IOCTLs have been found for a given
driver, the user can choose one IOCTL in the list to begin the 
fuzzing process. Note that this tool only performs generation-based
fuzzing. Compared to mutation-based fuzzing (which consists in taking
valid IOCTL buffers and adding anomalies), the code coverage is of
course less important. 
	
Note: for mutation-based IOCTL fuzzing, check out the great tool
"IOCTL fuzzer" (http://code.google.com/p/ioctlfuzzer/). Basically, it
hooks NtDeviceIoControlFile in order to take control of all IOCTL 
requests throughout the system.


=====================================================================
	Reminder about IOCTLs
=====================================================================

  IOCTL codes:
  ------------

  According to winioctl.h:

   IOCTL's are defined by the following bit layout.
 [Common |Device Type|Required Access|Custom|Function Code|Transfer Type]
   31     30       16 15          14  13   12           2  1            0

   Common          - 1 bit.  This is set for user-defined
                     device types.
   Device Type     - This is the type of device the IOCTL
                     belongs to.  This can be user defined
                     (Common bit set).  This must match the
                     device type of the device object.
   Required Access - FILE_READ_DATA, FILE_WRITE_DATA, etc.
                     This is the required access for the
                     device.
   Custom          - 1 bit.  This is set for user-defined
                     IOCTL's.  This is used in the same
                     manner as "WM_USER".
   Function Code   - This is the function code that the
                     system or the user defined (custom
                     bit set)
   Transfer Type   - METHOD_IN_DIRECT, METHOD_OUT_DIRECT,
                     METHOD_NEITHER, METHOD_BUFFERED, This
                     the data transfer method to be used.

	For a given device, only the fields "Function Code" and "Transfer Type"
	change for the different supported IOCTL codes.


  Buffer specifications:
  ---------------------

Buffer sizes:

Input Size   =  nt!_IO_STACK_LOCATION.Parameters.DeviceIoControl.InputBufferLength
Output Size  =  nt!_IO_STACK_LOCATION.Parameters.DeviceIoControl.OutputBufferLength

The way buffers are passed from userland to kernelland, and from kernelland to
userland, depends on the method which is used. Here are the differences:

  - METHOD_BUFFERED: 
		Input Buffer  = nt!_IRP.AssociatedIrp.SystemBuffer
		Output Buffer = nt!_IRP.AssociatedIrp.SystemBuffer
  
		input & output buffers use the same location, so the buffer allocated 
		by the I/O manager is the size of the larger value (output vs. input).

  - METHOD_X_DIRECT: 
		Input Buffer  = nt!_IRP.AssociatedIrp.SystemBuffer
		Output Buffer = nt!_IRP.MdlAddress
		
		the input buffer is passed in using "BUFFERED" implementation. The 
		output buffer is passed in using a MDL (which permits Direct Memory
		Access). The difference between "IN" and "OUT" is that with "IN", 
		you can use the output buffer to pass in data! The "OUT" is only 
		used to return data.
					 
  - METHOD_NEITHER:  
		Input Buffer  = nt!_IO_STACK_LOCATION.Parameters.DeviceIoControl.Type3InputBuffer
		Output Buffer = nt!_IRP.UserBuffer
  
		input & output buffers sizes may be different. The I/O manager does not
		provide any system buffers or MDLs. The IRP supplies the user-mode 
		virtual addresses of the input and output buffer


=====================================================================
	Command line options
=====================================================================


>ioctlbf.EXE

  Usage
  -----
  ioctlbf.EXE -d <deviceName> (-i <code>|-r <code>-<code>) [-u] [-q] [-f] [-e]

  Options
  -------
  -d    Symbolic device name (without \\.\)
  -i    IOCTL code used as reference for scanning (see also -u)
  -r    IOCTL codes range (format: 00004000-00008000) to fuzz
  -u    Fuzz only the IOCTL specified with -i
  -f    Filter out IOCTLs with no buffer length restriction
  -q    Quiet mode (do not display hexdumps when fuzzing)
  -e    Display error codes during IOCTL codes scanning
  -h    Display this help

  Examples
  --------
Scanning by Function code + Transfer type bruteforce from given valid IOCTL:
  > ioctlbf.EXE -d deviceName -i 00004000 -q

Scanning a given IOCTL codes range (filter enabled):
  > ioctlbf.EXE -d deviceName -r 00004000-00004fff -f

Fuzzing only a given IOCTL (quiet mode):
  > ioctlbf.EXE -d deviceName -i 00004000 -u -q

=====================================================================
	Usage
=====================================================================

1. First of all, it is necessary to locate the target driver. A tool
like "DriverView" (http://www.nirsoft.net/utils/driverview.html) can 
be used in order to easily spot non-Microsoft drivers (third-party
drivers).

2. Then, it is necessary to check the device(s) associated with the
target driver. A good tool to do this is "DeviceTree" for example
(http://www.osronline.com/article.cfm?article=97)

3. Check the security attributes (DACL) of the device(s). It should
be available for limited users in order to make it interesting from
an attacker point of view. Indeed, vulnerabilities in drivers may 
lead to Local Privilege Escalation on the system, or just Denial of
Service when it is not exploitable.

4. Retrieve the symbolic link used by applications to communicate 
with one device of the target driver. All symbolic links can be 
listed with the Sysinternal's tool "WinObj" in the "GLOBAL??" section
(http://technet.microsoft.com/en-us/sysinternals/bb896657).

5. Finally, it is necessary to know at least one valid IOCTL code
supported by the target driver. For example, it can be easily done by 
monitoring IRPs with a tool like "OSR's IrpTracker Utility"
(http://www.osronline.com/article.cfm?article=199).
Make sure to apply a filter on "DEVICE_CONTROL" only and to select
only the target driver.

Of course, it is also possible to retrieve valid IOCTL codes directly
by reverse engineering the driver.

6. Once a valid IOCTL code is retrieved, "ioctlbf" can be used. One of 
the following IOCTL codes scanning modes can be chosen:
	- Function code + Transfer type bruteforce
	- IOCTL codes range
	- Single IOCTL code
The scanning process returns supported IOCTL codes and accepted 
buffer sizes for each one.

7. The next step simply consists in chosing one IOCTL to fuzz. The 
fuzzing process actually follows the following steps:
	- [if method != METHOD_BUFFERED] Invalid addresses of 
	  input/output buffers
	- Check for trivial kernel overflows
	- Fuzzing with predetermined DWORDs (invalid addresses, 
	addresses pointing to long ascii/unicode strings, address 
	pointing to a table of invalid addresses).
	- Fuzzing with fully random data

	
=====================================================================
	Example
=====================================================================

>ioctlbf.EXE -d aswSnx -i 82ac0200 -q

[~] Open handle to the device \\.\aswSnx ... OK

  Summary
  -------
  IOCTL scanning mode   : Function + transfer type bf 0x82ac0000 - 0x82ac3fff
  Filter mode           : Filter disabled
  Symbolic Device Name  : \\.\aswSnx
  Device Type           : 0x000082ac
  Device handle         : 0x000007dc

[~] Bruteforce function code + transfer type and determine input sizes...
................
[+] 11 valid IOCTL have been found

  Valid IOCTLs found
  ------------------
  0x82ac0204    function code: 0x0081
                transfer type: METHOD_BUFFERED
                input bufsize: fixed size = 240 (0xf0)

  0x82ac00cc    function code: 0x0033
                transfer type: METHOD_BUFFERED
                input bufsize: min = 4 (0x4) | max = 4096 (0x1000)

[...]

[?] Choose an IOCTL to fuzz...
        [0] 0x82ac0204
        [1] 0x82ac00cc
        [2] 0x82ac0098
        [3] 0x82ac0074
        [4] 0x82ac0070
        [5] 0x82ac0068
        [6] 0x82ac0064
        [7] 0x82ac0060
        [8] 0x82ac0058
        [9] 0x82ac0054
        [10] 0x82ac0014
Choice : 0

  FuzZing IOCTL 0x82ac0204
  ------------------------
[0x82ac0204] Checking for trivial kernel overflows ...
................DONE

[0x82ac0204] Fuzzing with predetermined DWORDs, max buffer size...
(Ctrl+C to pass to the next step)

[...]

=====================================================================
	Building from sources
=====================================================================

1. Go to the directory .\src\

2. Edit the file "makefile.txt" (set correct API directories 
   "API_DIRx") and the PATH in the file "build.bat"

3. Execute ".\build.bat release"


