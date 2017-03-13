
/*

	 _                   _  _       ___ 
	(_)              _  | || |     / __)
	 _  ___   ____ _| |_| || |__ _| |__ 
	| |/ _ \ / ___|_   _) ||  _ (_   __)
	| | |_| ( (___  | |_| || |_) )| |   
	|_|\___/ \____)  \__)\_)____/ |_| 
	  
Features:
	* IOCTL codes scanning
		- IOCTL codes range
		- Function code + Transfer type bruteforce
		- Single IOCTL
	* IOCTL fuzzing
		- [if method != METHOD_BUFFERED] Invalid addresses of input/output buffers
		- Check for kernel stack/heap overflows
		- Fuzzing with predetermined DWORDs
		- Fuzzing with fully random data
		
*/


// System includes ------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <time.h>
#include <WINDOWS.h>
#include <winioctl.h>
#include <winerror.h>

// Program include ------------------------------------------------------------
#include "getopt.h"
#include "rng.c"
#include "ioctl_manipulation.h"
#include "ihm.h"
#include "utilities.h"

// Parameters -----------------------------------------------------------------
#define MAX_BUFSIZE 4096		// Max length for input buffer
#define SLEEP_TIME  10			// Sleep time between each fuzzing attempt
#define INVALID_BUF_ADDR_ATTEMPTS	5 

// Junk data used for fuzzing -------------------------------------------------
CHAR asciiString10[0x10];
CHAR asciiString100[0x100];
CHAR asciiString1000[0x1000];

WCHAR unicodeString10[0x10];
WCHAR unicodeString100[0x100];
WCHAR unicodeString1000[0x1000];
	
DWORD tableDwords[0x100];
	
DWORD FuzzConstants[] = {	0x00000000, 0x00000001, 0x00000004, 0xFFFFFFFF,
							0x00001000, 0xFFFF0000, 0xFFFFFFFE, 0xFFFFFFF0, 
							0xFFFFFFFC, 0x70000000, 0x7FFEFFFF, 0x7FFFFFFF, 
							0x80000000, 
							(DWORD)asciiString10, 
							(DWORD)asciiString100, 
							(DWORD)asciiString1000,
							(DWORD)unicodeString10, 
							(DWORD)unicodeString100, 
							(DWORD)unicodeString1000,
							(DWORD)tableDwords }; 
							
DWORD invalidAddresses[] = { 0xFFFF0000, 0x00001000 };

BOOL cont;

// Initialize junk data -------------------------------------------------------
void initializeJunkData() {
	int i;
	memset(asciiString10,      0x41,   0x10);
	memset(asciiString100,     0x41,   0x100);
	memset(asciiString1000,    0x41,   0x1000);
	
	wmemset(unicodeString10,   0x0041, 0x10);
	wmemset(unicodeString100,  0x0041, 0x100);
	wmemset(unicodeString1000, 0x0041, 0x1000);
	
	for(i=0; i<(sizeof(tableDwords)/4); i++) 
		tableDwords[i] = 0xFFFF0000;
	return;
}


// Handler for the CTRL-C signal, used to stop an action without quitting -----
BOOL CtrlHandler(DWORD fdwCtrlType) { 
	switch( fdwCtrlType ) { 
		case CTRL_C_EVENT:
		case CTRL_CLOSE_EVENT:
			cont = FALSE;
			return TRUE;
		default:
			return FALSE;
	} 
} 


// Main function --------------------------------------------------------------
int main(int argc, char *argv[]) {

	int c;
	extern char *optarg;
	char *deviceSymbolicName = NULL;
	char *singleIoctl		 = NULL;
	char *rangeIoctl		 = NULL;
	int singleflg  = 0;
	int errflg 	 = 0;
	int quietflg = 0;
	int displayerrflg = 0;
	int filteralwaysok = 0;
	
	HANDLE deviceHandle;
	char   deviceName[100] = "\\\\.\\";
	DWORD  beginIoctl, endIoctl, currentIoctl;
	DWORD  status, errorCode;
	DWORD  nbBytes = 0;
	
	pIOCTLlist listIoctls 	 = NULL;
	pIOCTLlist posListIoctls = NULL;
	
	int choice = -1;
	unsigned int i,j;   
	int fuzzData;
		
	BYTE  bufInput[0x10000];
	BYTE  bufOutput[0x10000];
	size_t randomLength;
	
	
	// Parse options from command-line
	while((c = getopt(argc, argv, "d:i:r:uqh?ef")) != -1) {
		switch(c) {
			case 'd':
				deviceSymbolicName = optarg;
				break;
			case 'i':
				if(rangeIoctl)
					errflg++;
				else
					singleIoctl = optarg;
				break;
			case 'r':
				if(singleIoctl)
					errflg++;
				else
					rangeIoctl = optarg;
				break;
			case 'u':
				if(rangeIoctl)
					errflg++;
				singleflg = 1;
				break;
			case 'q':
				quietflg++;
				break;
			case 'e':
				displayerrflg++;
				break;
			case 'f':
				filteralwaysok++;
				break;
			case 'h':
			case '?':
				errflg++;
		}
	}
	
	// Check & parse options from command line
	if(deviceSymbolicName == NULL || (rangeIoctl == NULL && singleIoctl == NULL))
		errflg++;
	
	if(!errflg) {
		// IOCTL range mode
		if(rangeIoctl) {
			if(strchr(rangeIoctl, '-') == NULL)
				errflg++;
			else {
				beginIoctl 	= (DWORD)parseHex(strtok(rangeIoctl, "-"));
				endIoctl	= (DWORD)parseHex(strtok(NULL, "-"));
				if(endIoctl < beginIoctl)
					errflg++;
			}
		}
		// Function code + Transfer type (14 lowest bits) bruteforce mode
		else if(singleIoctl && !singleflg) {
			beginIoctl = (DWORD)parseHex(singleIoctl) & 0xffffc000;
			endIoctl   = ((DWORD)parseHex(singleIoctl) & 0xffffc000) | 0x00003fff;			
		}
		// Single IOCTL mode
		else {
			beginIoctl 	= (DWORD)parseHex(singleIoctl);
			endIoctl	= beginIoctl;
		}
	}
	
	// Print usage if necessary
	if(errflg)
		usage(argv[0]);
					

	banner();
	
	// Open handle to the device
	strncat(deviceName, deviceSymbolicName, 90); 
	printf("[~] Open handle to the device %s ... ", deviceName);
	deviceHandle = CreateFile((HANDLE)deviceName, 
							  GENERIC_READ, 
							  0, 
							  NULL, 
							  OPEN_EXISTING, 
							  0, 
							  NULL);
	if(deviceHandle == INVALID_HANDLE_VALUE) {
		printf("FAILED, error code: %d\n%s\n", GetLastError(), 
										errorCode2String(GetLastError()));
		exit(1);
	}
	printf("OK\n\n");
	
	memset(bufInput,  0x00, 0x10000);
	memset(bufOutput, 0x00, 0x10000);
	
	
	// Print summary	
	printf("  Summary                             	\n");
	printf("  -------								\n");
	printf("  IOCTL scanning mode 	: ");
	if(rangeIoctl)
		printf("Range mode 0x%08x - 0x%08x\n", beginIoctl, endIoctl);
	else if(singleIoctl && singleflg)
		printf("Single mode 0x%08x\n", beginIoctl);
	else
		printf("Function + transfer type bf 0x%08x - 0x%08x\n", 
													   beginIoctl, endIoctl);
	printf("  Filter mode           : ");
	if(filteralwaysok)
		printf("Filter codes that return true for all buffer sizes\n");
	else
		printf("Filter disabled\n");

	printf("  Symbolic Device Name  : %s\n", deviceName);
	if(singleIoctl)
		printf("  Device Type    	: 0x%08x\n", 
						(beginIoctl & 0xffff0000) >> 16);
	printf("  Device handle         : 0x%08x\n", deviceHandle);
	printf("\n");
	
	
	// IOCTL code scanning
	if(singleIoctl && singleflg)
		printf("[~] Test given IOCTL and determine input size...\n");
	else
		printf("[~] Bruteforce function code + transfer type and determine "
		       "input sizes...\n");

	
	i = 0;
	for(currentIoctl = beginIoctl; currentIoctl<=endIoctl; currentIoctl++) {
		
		if(!singleflg && !displayerrflg && currentIoctl % 0x400 == 0)
			printf(".");
			
		// DeviceIoControl: if the operation completes successfully, the 
		// return value is nonzero
		status = DeviceIoControl(deviceHandle, 
								 currentIoctl, 
								 NULL,
								 0,
								 NULL, 
								 0, 
								 &nbBytes, 
								 NULL);
	
		// No further tests for the current IOCTL if the operation fails with 
		// one of the following error codes:
		// - ERROR_INVALID_FUNCTION		0x1
		// - ERROR_ACCESS_DENIED		0x5
		// - ERROR_NOT_SUPPORTED		0x50
		// cf. winerror.h
		if(status == 0) {
			errorCode = GetLastError();
						
			// -- DEBUG
			//if(errorCode != 87)
			if(displayerrflg) {
				printf("0x%08x -> error code %03d - %s\n", currentIoctl, 
				       errorCode, errorCode2String(errorCode));
			}
			
			//printf("0x%08x -> code %d\n", currentIoctl, errorCode);
			// errorCode == ERROR_INVALID_FUNCTION || 
			if(errorCode == ERROR_ACCESS_DENIED    || 
			   errorCode == ERROR_NOT_SUPPORTED)
				continue;
		}
		
		// Filter out IOCTLs that always return status != 0
		if(filteralwaysok) {
			status = DeviceIoControl(deviceHandle, 
									currentIoctl, 
									&bufInput, 
									MAX_BUFSIZE, 
									&bufOutput, 
									MAX_BUFSIZE, 
									&nbBytes, 
									NULL);
			if(status != 0) {
				cont   = TRUE;
				status = 1; 
				for(j=0; j<4 && status != 0 && cont; j++) {
					status = DeviceIoControl(deviceHandle, 
										 currentIoctl, 
										 &bufInput, 
										 j, 
										 &bufOutput, 
										 j,
										 &nbBytes, 
										 NULL);	
					
					/*
					if(status == 0)
						printf("0x%08x (size %d) -> error code %03d \n", currentIoctl, j, GetLastError());
					else 
						printf("0x%08x (size %d) -> status != 0 \n", currentIoctl, j);
					*/
					
				}
				if(j == 4) {
					//printf("Skip 0x%08x\n", currentIoctl);
					continue;
				}
			}
		}
									
		// Determine min/max input buffer size
		cont = TRUE;
		for(j=0; j<MAX_BUFSIZE && cont; j++) {
			status = DeviceIoControl(deviceHandle, 
									 currentIoctl, 
									 &bufInput, 
									 j, 
									 &bufOutput, 
									 j,
									 &nbBytes, 
									 NULL);

			if(status != 0) {
				listIoctls = addIoctlList(listIoctls, 
										  currentIoctl, 
										  0, 
										  j, 
										  MAX_BUFSIZE);
				cont = FALSE;
				i++;
			}
			/*
			else {
				// DEBUG
				if(GetLastError() != 31)
					printf("Size = %04x -> code %d\n", j, GetLastError());
			}
			*/
			
		}
		if(!cont) {
			// Ok, the min buffer size has been found. Let's find the max size
			cont = TRUE;
			status = DeviceIoControl(deviceHandle, 
									 currentIoctl, 
									 &bufInput, 
									 MAX_BUFSIZE, 
									 &bufOutput, 
									 MAX_BUFSIZE, 
									 &nbBytes, 
									 NULL);
			if(status != 0) {
				listIoctls->maxBufferLength = MAX_BUFSIZE;
				cont = FALSE;
			}
			
			for(j=listIoctls->minBufferLength+1; 
			    j<MAX_BUFSIZE && cont; j++) {
				status = DeviceIoControl(deviceHandle, 
									     currentIoctl, 
										 &bufInput, 
										 j, 
										 &bufOutput, 
										 j, 
										 &nbBytes, 
										 NULL);
				if(status == 0) {
					listIoctls->maxBufferLength = j-1;
					cont = FALSE;
				}
			}
			if(cont) {
				listIoctls->maxBufferLength = MAX_BUFSIZE;
			}
		}
		/*
		else {
			// If we're here, it means no min input buffer size has been found
			// DEBUG -----
			printf("No min bufsize found for IOCTL 0x%08x\n", currentIoctl);
			//listIoctls = addIoctlList(listIoctls, currentIoctl, 
			//GetLastError(), 0, MAX_BUFSIZE);
			//i++;
		}
		*/
	}
	printf("\n");
	if(i == 0) {
		if(singleflg)
			printf("[!] Given IOCTL code seems not to be recognized by the "
			       "driver !\n");
		else
			printf("[!] No valid IOCTL code has been found !\n");
		exit(1);
	}
	else {
		if(singleflg)
			printf("[!] Given IOCTL code is recognized by the driver !\n\n");
		else
			printf("[+] %d valid IOCTL have been found\n\n", i);
	}
	
	
	// Fuzzing IOCTL buffer
	while(1) {
	
		// Choice of the IOCTL to fuzz
		printf("  Valid IOCTLs found \n");
		printf("  ------------------ \n");
		printIoctlList(listIoctls, MAX_BUFSIZE);
		printf("\n");
		
		if(singleflg) {
			choice  = 0;
		}
		else {
			printf("[?] Choose an IOCTL to fuzz...\n");
			printIoctlChoice(listIoctls);
			printf("Choice : ");
			scanf_s("%d", &choice, 3);
			
			if(choice < 0 || choice >= getIoctlListLength(listIoctls))
				continue;
		}
		
		
		posListIoctls = getIoctlListElement(listIoctls, choice);
		
		// Start fuzzing
		printf("\n");
		printf("  FuzZing IOCTL 0x%08x     \n", posListIoctls->IOCTL);
		printf("  ------------------------ \n");

		
		// --------------------------------------------------------------------
		// Stage 1: Check for invalid addresses of buffer 
		// (for method != METHOD_BUFFERED)
		if((posListIoctls->IOCTL & 0x00000003) != 0) {
			printf("[0x%08x] Checking for invalid addresses of in/out buffers...",
				   posListIoctls->IOCTL);
			getch();
			printf("\n");
			cont = TRUE;
			for(i=0; cont && i<INVALID_BUF_ADDR_ATTEMPTS; i++) {
				for(j=0; cont && j<(sizeof(invalidAddresses)/4); j++) {
					// Choose a random length for the buffer
					randomLength = getrand(posListIoctls->minBufferLength, 
										   posListIoctls->maxBufferLength);
										   
					status = DeviceIoControl(deviceHandle, 
											 posListIoctls->IOCTL, 
											 (LPVOID)invalidAddresses[j], 
											 randomLength,
											 (LPVOID)invalidAddresses[j], 
											 randomLength, 
											 &nbBytes, 
											 NULL);
					Sleep(SLEEP_TIME);
				}
				printf(".");
			}
			printf("DONE\n\n");
		}
		
		
		// --------------------------------------------------------------------
		// Stage 2: Check for trivial kernel overflow
		printf("[0x%08x] Checking for trivial kernel overflows ...", 
			   posListIoctls->IOCTL);
		getch();
		printf("\n");
		cont = TRUE;
		memset(bufInput, 0x41, 0x10000);
		for(i=0x100; i<=0x10000; i+=0x100) {
			if(i % 0x1000 == 0)
				printf(".");
			status = DeviceIoControl(deviceHandle, 
									 posListIoctls->IOCTL, 
									 &bufInput, 
									 i, 
			                         &bufOutput, 
									 i, 
									 &nbBytes, 
									 NULL);
			Sleep(SLEEP_TIME);
		}
		memset(bufInput, 0x00, 0x10000);
		printf("DONE\n\n");

		
		// --------------------------------------------------------------------
		// Stage 3: Fuzzing with predetermined DWORDs
		printf("[0x%08x] Fuzzing with predetermined DWORDs, max buffer size...\n", 
			   posListIoctls->IOCTL);
		printf("(Ctrl+C to pass to the next step)");
		getch();
		printf("\n");
		cont = TRUE;
		if(SetConsoleCtrlHandler((PHANDLER_ROUTINE) CtrlHandler, TRUE)) {
		
			// Fill the buffer with data from FuzzConstants (1 DWORD after 1)
			memset(bufInput, 0x00, MAX_BUFSIZE);
			for(i=0; cont && i<posListIoctls->maxBufferLength; i=i+4) {
			
				printf("Fuzzing DWORD %d/%d\n", 
					   i/4+1, posListIoctls->maxBufferLength/4);
				
				// Fill the whole buffer with random data...
				for(j=0; cont && j<posListIoctls->maxBufferLength; j++) {
					bufInput[j] = (BYTE)getrand(0x00, 0xff);
				}
				
				// ...and put a DWORD from FuzzConstants at the i_th position
				for(j=0; cont && j<(sizeof(FuzzConstants)/4); j++) {
					fuzzData = FuzzConstants[j];
					
					/*
					printf("Fuzzing DWORD %d/%d with 0x%08x (%d/%d)\n", 
						   i/4+1, posListIoctls->maxBufferLength/4, 
						   fuzzData, j+1, sizeof(FuzzConstants)/4);
					*/
													
					// Choose a random element into FuzzConstants
					bufInput[i]   = fuzzData & 0x000000ff;
					bufInput[i+1] = (fuzzData & 0x0000ff00) >> 8;
					bufInput[i+2] = (fuzzData & 0x00ff0000) >> 16;
					bufInput[i+3] = (fuzzData & 0xff000000) >> 24;
					
					if(!quietflg) {
						Hexdump(bufInput, posListIoctls->maxBufferLength);
						printf("Fuzzing DWORD %d/%d with 0x%08x (%d/%d)\n", 
						       i/4+1, posListIoctls->maxBufferLength/4, 
						       fuzzData, j+1, sizeof(FuzzConstants)/4);
						printf("Input buffer: %d (0x%x) bytes \n", 
						                     posListIoctls->maxBufferLength,
							                 posListIoctls->maxBufferLength);
					}
					
					status = DeviceIoControl(deviceHandle, 
											 posListIoctls->IOCTL, 
											 &bufInput, 
											 posListIoctls->maxBufferLength,
											 &bufOutput, 
											 posListIoctls->maxBufferLength, 
											 &nbBytes, 
											 NULL);
											 
					if(!quietflg) {
						if(status == 0)
							printf("Error %d: %s\n\n", GetLastError(), 
							                 errorCode2String(GetLastError()));
						printf("-------------------------------------------------------------------\n\n");
					}
					
					Sleep(SLEEP_TIME);
				}
			}
			
			printf("Filling the whole buffer with predetermined DWORDs\n");
			while(cont) {
				// Choose a random length for the buffer
				randomLength = getrand(posListIoctls->minBufferLength, 
				                       posListIoctls->maxBufferLength);
				
				// Fill the whole buffer with data from FuzzConstants
				memset(bufInput, 0x00, MAX_BUFSIZE);
				for(i=0; i<randomLength; i=i+4) {
					fuzzData = FuzzConstants[getrand(0, (sizeof(FuzzConstants)/4)-1)];
														
					// Choose a random element into FuzzConstants
					bufInput[i]   = fuzzData & 0x000000ff;
					bufInput[i+1] = (fuzzData & 0x0000ff00) >> 8;
					bufInput[i+2] = (fuzzData & 0x00ff0000) >> 16;
					bufInput[i+3] = (fuzzData & 0xff000000) >> 24;
				}
				
				if(!quietflg) {
					Hexdump(bufInput, randomLength);
					printf("Filling the whole buffer with predetermined DWORDs\n");
					printf("Input buffer: %d (0x%x) bytes \n", randomLength,
															   randomLength);
				}

				status = DeviceIoControl(deviceHandle, 
										 posListIoctls->IOCTL, 
										 &bufInput, 
										 randomLength,
										 &bufOutput, 
										 randomLength, 
										 &nbBytes, 
										 NULL);
										 
				if(!quietflg) {
					if(status == 0)
						printf("Error %d: %s\n\n", GetLastError(), errorCode2String(GetLastError()));
					printf("-------------------------------------------------------------------\n\n");
				}
										 
				Sleep(SLEEP_TIME);	
			}
				
		}
		else {
			printf("[!] Error: could not set control handler.");
			exit(1);
		}
		printf("STOPPED\n\n");
		
		
		// --------------------------------------------------------------------
		// Stage 4: Fuzzing with fully random data
		printf("[0x%08x] Fuzzing with fully random data...\n", 
		       posListIoctls->IOCTL);
		printf("(Ctrl+C to pass to the next step)");
		getch();
		printf("\n");
		cont = TRUE;
		if(SetConsoleCtrlHandler((PHANDLER_ROUTINE) CtrlHandler, TRUE)) {
			while(cont) {
				// Choose a random length for the buffer
				randomLength = getrand(posListIoctls->minBufferLength, 
									   posListIoctls->maxBufferLength);
				
				// Fill the buffer with random data
				memset(bufInput, 0x00, MAX_BUFSIZE);
				for(i=0; i<randomLength; i++) {
					bufInput[i] = (BYTE)getrand(0x00, 0xff);
				}
				

				if(!quietflg) {
					Hexdump(bufInput, randomLength);
					printf("Input buffer: %d (0x%x) bytes \n", randomLength,
															   randomLength);
				}				

				status = DeviceIoControl(deviceHandle, 
										 posListIoctls->IOCTL, 
										 &bufInput, 
										 randomLength,
				                         &bufOutput, 
										 randomLength, 
										 &nbBytes, 
										 NULL);
										 
				if(!quietflg) {
					if(status == 0)
						printf("Error %d: %s\n\n", GetLastError(), 
						                   errorCode2String(GetLastError()));
					printf("-------------------------------------------------------------------\n\n");
				}

				Sleep(SLEEP_TIME);
			}
		}
		else {
			printf("[!] Error: could not set control handler.");
			exit(1);
		}
		printf("STOPPED\n\n");
		
		
		// --------------------------------------------------------------------

		
		printf("[0x%08x] FuzZing finished, no BSOD :'(\n\n", 
		       posListIoctls->IOCTL);

		printf("[?] Continue ? (y/n)");
		if(getch() == 'n')
			exitProgram(listIoctls);
		printf("\n");
	}

	return 0;
}