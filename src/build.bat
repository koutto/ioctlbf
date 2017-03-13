@echo off
REM bldusr.bat ----------------------------------------------------------------

REM Set up build environment---------------------------------------------------

set THIS_FILE=build.bat

ECHO [%THIS_FILE%]: Establish build environment
set SAVED_PATH=%PATH%
set PATH=%PATH%;C:\WinDDK\7600.16385.1\bin\x86;C:\WinDDK\7600.16385.1\bin\x86\x86

REM Perform Build--------------------------------------------------------------

ECHO [%THIS_FILE%]: Invoking nmake.exe

IF "%~1" == "" GOTO usage
IF %1 == debug 	 (echo [%THIS_FILE%]: Debug)&(nmake.exe /NOLOGO /S /F makefile.txt BLDTYPE=DEBUG %1)&(GOTO ELevel)
IF %1 == release (echo [%THIS_FILE%]: Release)&(nmake.exe /NOLOGO /S /F makefile.txt %1)&(GOTO ELevel)
IF %1 == clean   (echo [%THIS_FILE%]: Clean)&(nmake.exe /NOLOGO /S /F makefile.txt %1)&(GOTO ELevel)

:usage
ECHO [%THIS_FILE%]: ********ERROR - BAD ARGUMENTS*********************
ECHO [%THIS_FILE%]: USAGE: %THIS_FILE% ^( debug ^| release ^| clean ^)
GOTO end

:ELevel
IF %ERRORLEVEL% == 0 GOTO good
IF %ERRORLEVEL% == 1 GOTO incomplete
IF %ERRORLEVEL% == 2 GOTO apperror
IF %ERRORLEVEL% == 4 GOTO syserror
IF %ERRORLEVEL% == 255 GOTO uptodate
GOTO unexpected

:good
	ECHO [%THIS_FILE%]: Success	
	GOTO END
:incomplete
	ECHO [%THIS_FILE%]: Incomplete build (issued only when /K is used)	
	GOTO END
:apperror
	ECHO [%THIS_FILE%]: Program error (makefile syntax error, command error, or user interruption)	
	GOTO END
:syserror
	ECHO [%THIS_FILE%]: System error (out of memory) 	
	GOTO END
:uptodate
	ECHO [%THIS_FILE%]: Target is not up to date (issued only when /Q is used)  	
	GOTO END
:unexpected
	ECHO [%THIS_FILE%]: Unexpected return code	
	GOTO END
:end
ECHO [%THIS_FILE%]: ERRORLEVEL= %ERRORLEVEL%

REM Restore Old Environment----------------------------------------------------

ECHO [%THIS_FILE%]: Restoring old environment
set PATH=""
set PATH=%SAVED_PATH%