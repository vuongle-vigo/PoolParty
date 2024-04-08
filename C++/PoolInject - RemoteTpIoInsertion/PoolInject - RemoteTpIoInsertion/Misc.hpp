#include <windows.h>
#include <winternl.h>

#include <stdio.h>
#include <winternl.h>
#include <dbghelp.h>
#include <TlHelp32.h>
#include <string.h>
#include <tchar.h>
#include <iostream>
#include <vector>
using namespace std;

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")
