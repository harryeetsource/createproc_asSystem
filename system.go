package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type SHELLEXECUTEINFO struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     uintptr
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <path_to_program>\n", os.Args[0])
		os.Exit(1)
	}

	programPath := os.Args[1]

	err := createProcessAsNT(programPath)
	if err != nil {
		log.Printf("Failed to create process as NT Authority/System: %v", err)

		err = runAsAdmin(programPath)
		if err != nil {
			log.Fatalf("Failed to run program as administrator: %v", err)
		}
	}
}

func createProcessAsNT(programPath string) error {
	// Get the primary token of the local system account
	var systemToken windows.Token
	err := windows.WTSQueryUserToken(windows.WTSGetActiveConsoleSessionId(), &systemToken)
	if err != nil {
		return err
	}
	defer systemToken.Close()

	// Duplicate the token to create a primary token
	var primaryToken windows.Token
	err = windows.DuplicateTokenEx(systemToken, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityIdentification, windows.TokenPrimary, &primaryToken)
	if err != nil {
		return err
	}
	defer primaryToken.Close()

	// Create an environment block for the new process
	var env *uint16
	err = windows.CreateEnvironmentBlock(&env, primaryToken, false)
	if err != nil {
		return err
	}
	defer windows.DestroyEnvironmentBlock(env)

	// Set the process creation flags
	createFlags := uint32(windows.CREATE_UNICODE_ENVIRONMENT) | uint32(windows.CREATE_NEW_CONSOLE)

	// Set the process startup information
	startupInfo := windows.StartupInfo{
		Cb:         uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Desktop:    windows.StringToUTF16Ptr("Winsta0\\Default"),
		Title:      windows.StringToUTF16Ptr(""),
		Flags:      windows.STARTF_USESHOWWINDOW,
		ShowWindow: windows.SW_SHOW,
	}

	// Set the process information
	var processInfo windows.ProcessInformation

	// Create the process with the primary token
	err = windows.CreateProcessAsUser(primaryToken, nil, windows.StringToUTF16Ptr(programPath), nil, nil, false, createFlags, env, nil, &startupInfo, &processInfo)
	if err != nil {
		return err
	}

	// Close the process and thread handles
	windows.CloseHandle(processInfo.Process)
	windows.CloseHandle(processInfo.Thread)

	return nil
}

func runAsAdmin(programPath string) error {
	// Load shell32.dll library
	shell32, err := syscall.LoadDLL("shell32.dll")
	if err != nil {
		return err
	}
	defer shell32.Release()

	// Get the pointer to the ShellExecuteEx function
	shellExecuteEx, err := shell32.FindProc("ShellExecuteExW")
	if err != nil {
		return err
	}

	// Prepare parameters for ShellExecuteEx function
	sei := &SHELLEXECUTEINFO{
		cbSize: uint32(unsafe.Sizeof(SHELLEXECUTEINFO{})),
		lpVerb: syscall.StringToUTF16Ptr("runas"),
		lpFile: syscall.StringToUTF16Ptr(programPath),
		nShow:  syscall.SW_NORMAL,
	}

	// Call the ShellExecuteEx function to run the program as administrator
	ret, _, err := shellExecuteEx.Call(uintptr(unsafe.Pointer(sei)))
	if ret == 0 {
		return err
	}

	return nil
}
