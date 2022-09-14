// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "framework.h"
#include "detours.h"
#include "winInfo.h"
#include "util.h"
#include <cstdio>
#include <cstdarg>
#include <iostream>
#include <fstream>
#include <QReadWriteLock>

using namespace std;

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")

fstream* logFile;
fstream* tmpFile = new fstream();
SYSTEMTIME st;
HANDLE STDIN, STDOUT, STDERR;

#pragma data_seg("Shared")
bool injectMessageBoxA = false;
bool injectMessageBoxW = false;
bool injectHeapCreate = false;
bool injectHeapDestroy = false;
bool injectHeapAlloc = false;
bool injectHeapFree = false;
bool injectOpenFile = false;
bool injectCreateFile = false;
bool injectReadFile = false;
bool injectWriteFile = false;
bool injectRegCreateKeyEx = false;
bool injectRegSetValueEx = false;
bool injectRegDeleteValue = false;
bool injectRegCloseKey = false;
bool injectRegOpenKeyEx = false;

QReadWriteLock lock;
bool mutexSignal = false;
#pragma data_seg()

bool entranceWatchdog = false;
unsigned int logCounter = 0;
#pragma comment(linker, "/Section:Shared,rws")

extern "C" __declspec(dllexport) void openInjectMessageBoxA(bool choice){injectMessageBoxA = choice;};
extern "C" __declspec(dllexport) void openInjectMessageBoxW(bool choice){injectMessageBoxW = choice;};
extern "C" __declspec(dllexport) void openInjectHeapCreate(bool choice){injectHeapCreate = choice;};
extern "C" __declspec(dllexport) void openInjectHeapDestroy(bool choice){injectHeapDestroy = choice;};
extern "C" __declspec(dllexport) void openInjectHeapAlloc(bool choice){injectHeapAlloc = choice;};
extern "C" __declspec(dllexport) void openInjectHeapFree(bool choice){injectHeapFree = choice;};
extern "C" __declspec(dllexport) void openInjectOpenFile(bool choice){injectOpenFile = choice;};
extern "C" __declspec(dllexport) void openInjectCreateFile(bool choice){injectCreateFile = choice;};
extern "C" __declspec(dllexport) void openInjectReadFile(bool choice){injectReadFile = choice;};
extern "C" __declspec(dllexport) void openInjectWriteFile(bool choice){injectWriteFile = choice;};
extern "C" __declspec(dllexport) void openInjectRegCreateKeyEx(bool choice){injectRegCreateKeyEx = choice;};
extern "C" __declspec(dllexport) void openInjectRegSetValueEx(bool choice){injectRegSetValueEx = choice;};
extern "C" __declspec(dllexport) void openInjectRegDeleteValue(bool choice){injectRegDeleteValue = choice;};
extern "C" __declspec(dllexport) void openInjectRegCloseKey(bool choice){injectRegCloseKey = choice;};
extern "C" __declspec(dllexport) void openInjectRegOpenKeyEx(bool choice){injectRegOpenKeyEx = choice;};

extern "C" __declspec(dllexport) QReadWriteLock* getLock(){return &lock;};
extern "C" __declspec(dllexport) void setMutexSignal(){mutexSignal = false;};
extern "C" __declspec(dllexport) bool getMutexSignal(){return mutexSignal;};

char* writeLog(const char* funcName) {
    char* buffer = (char*)calloc(1, 0x400);
    GetLocalTime(&st);
    sprintf(buffer, "ID: %d\n"
                    "DLL log output: %4d-%02d-%02d %02d:%02d:%02d:%03d\n%s Hooked.\n", logCounter, st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, funcName);
    return buffer;
}

string getFileInfo(string processNameA){
    STDIN = GetStdHandle(STD_INPUT_HANDLE);
    STDOUT = GetStdHandle(STD_OUTPUT_HANDLE);
    STDERR = GetStdHandle(STD_ERROR_HANDLE);
    char buf[0x100];
    sprintf_s(buf, "STDIN handle: %#zx\n"
                   "STDOUT handle: %#zx\n"
                   "STDERR handle: %#zx\n", (size_t)STDIN, (size_t)STDOUT, (size_t)STDERR);
    bool getSuccess;
    string fileDescription;
    getSuccess = GetFileDescription(processNameA, fileDescription);
    if(!getSuccess)
        fileDescription = "<FILE DESCRIPTION NOT EXIST OR NOT ACCESSIBLE>";
    string fileVersion;
    getSuccess = GetFileVersion(processNameA, fileVersion);
    if(!getSuccess)
        fileDescription = "<FILE VERSION NOT EXIST OR NOT ACCESSIBLE>";
    string internalName;
    getSuccess = GetInternalName(processNameA, internalName);
    if(!getSuccess)
        internalName = "<INTERNAL NAME NOT EXIST OR NOT ACCESSIBLE>";
    string companyName;
    getSuccess = GetCompanyName(processNameA, companyName);
    if(!getSuccess)
        companyName = "<COMPANY NAME NOT EXIST OR NOT ACCESSIBLE>";
    string legalCopyright;
    getSuccess = GetLegalCopyright(processNameA, legalCopyright);
    if(!getSuccess)
        legalCopyright = "<LEGAL COPYRIGHT NOT EXIST OR NOT ACCESSIBLE>";
    string originalFileName;
    getSuccess = GetOriginalFilename(processNameA, originalFileName);
    if(!getSuccess)
        originalFileName = "<ORIGINAL FILE NAME NOT EXIST OR NOT ACCESSIBLE>";
    string productVersion;
    getSuccess = GetProductVersion(processNameA, productVersion);
    if(!getSuccess)
        productVersion = "<PRODUCT VERSION NOT EXIST OR NOT ACCESSIBLE>";

    string totalOut;
    totalOut += buf;
    totalOut += "File Description: " + fileDescription + "\n";
    totalOut += "File Version: " + fileVersion + "\n";
    totalOut += "Internal Name: " + internalName + "\n";
    totalOut += "Company Name: " + companyName + "\n";
    totalOut += "Legal Copyright: " + legalCopyright + "\n";
    totalOut += "Original File Name: " + originalFileName + "\n";
    totalOut += "Product Version: " + productVersion + "\n";

    return totalOut;
}

string getMainInfo(char* currentTime, char* argsInfo){
    string totalOut(currentTime);
    totalOut += argsInfo;
    wstring totalOutW = stringTowstring(totalOut);
    WCHAR* processName = getCurrentProcessName();
    string pNameStr = wstring2string(processName);
    if(pNameStr == "D:\\SSdesign\\UI\\designMain\\debug\\designMain.exe")       // 主UI进程，不需要钩子
        return "";
    if(processName == nullptr){
        DWORD lasterr = GetLastError();
        totalOutW += L"<ERROR: FAILED TO FETCH PROCESS NAME>: " + std::to_wstring(lasterr);
    }
    else
        totalOutW += processName;       // 获取进程名
    totalOutW += L"\n";

    totalOut = wstring2string(totalOutW);

    string processNameA = wstring2string(processName);
    string fileInfo = getFileInfo(processNameA);

    totalOut += fileInfo;

    return totalOut;
}

void getLastInfoAndWrite(string totalOut, string returnVal, string otherString = ""){
    totalOut += returnVal;
    totalOut += otherString;
    totalOut += "----------------------------------------------------\n";

//    lock.lockForRead();
    while(mutexSignal);
    *logFile << totalOut;
    tmpFile->open("./hookLog/lasthook.tmp", ios::out | ios::trunc);
    *tmpFile << totalOut;
    tmpFile->close();
    mutexSignal = true;
//    lock.unlock();
    logCounter++;
}

// 对话框调用截取
static int (WINAPI* OldMessageBoxW)
    (_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType) = MessageBoxW;
static int (WINAPI* OldMessageBoxA)
    (_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType) = MessageBoxA;

extern "C" __declspec(dllexport)int WINAPI NewMessageBoxA
(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType) {
    if(entranceWatchdog)
        return OldMessageBoxA(hWnd, lpText, lpCaption, uType);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectMessageBoxA){
        char* buffer = writeLog("MessageBoxA");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tHWND hWnd = 0x%p\n"
                        "\tLPCSTR lpText = 0x%p / \"%s\"\n"
                        "\tLPCSTR lpCaption = 0x%p / \"%s\"\n"
                        "\tUINT uType = %u / %x\n"
                        "Current process name: ", hWnd, lpText, lpText, lpCaption, lpCaption, uType, uType);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    int returnVal =  OldMessageBoxA(NULL, lpText, lpCaption, MB_OK);
    if(ArgsAndDetails == ""){    // 如果是本程序自身的调用，不写日志
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x80];
    sprintf_s(retStr, "Return value: (int) %d / %#x\n", returnVal, returnVal);
    getLastInfoAndWrite(ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)int WINAPI NewMessageBoxW
(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType) {
    if(entranceWatchdog)
        return OldMessageBoxW(hWnd, lpText, lpCaption, uType);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectMessageBoxW){
        char* buffer = writeLog("MessageBoxW");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tHWND hWnd = 0x%p\n"
                        "\tLPCWSTR lpText = 0x%p / \"%ls\"\n"
                        "\tLPCWSTR lpCaption = 0x%p / \"%ls\"\n"
                        "\tUINT uType = %u / %#x\n"
                        "Current process name: ", hWnd, lpText, lpText, lpCaption, lpCaption, uType, uType);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    int returnVal = OldMessageBoxW(NULL, lpText, lpCaption, MB_OK);
    if(ArgsAndDetails == ""){    // 如果是本程序自身的调用，不写日志
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x80];
    sprintf_s(retStr, "Return value: (int) %d / %#x\n", returnVal, returnVal);
    getLastInfoAndWrite(ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

// 堆操作调用截取
static HANDLE(WINAPI* OldHeapCreate)(DWORD fIOoptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) = HeapCreate;
static BOOL(WINAPI* OldHeapDestroy)(HANDLE hHeap) = HeapDestroy;
static LPVOID(WINAPI* OldHeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) = HeapAlloc;
static BOOL(WINAPI* OldHeapFree)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) = HeapFree;

extern "C" __declspec(dllexport)HANDLE WINAPI NewHeapCreate(DWORD fIOoptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) {
    if(entranceWatchdog)
        return OldHeapCreate(fIOoptions, dwInitialSize, dwMaximumSize);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectHeapCreate){
        char* buffer = writeLog("HeapCreate");
        char* args = (char*)calloc(1, 200);
        sprintf(args, "Arguments:\n"
                        "\tDWORD fIOoptions = %lu / %#lx\n"
                        "\tSIZE_T dwInitialSize = %zd / %#zx\n"
                        "\tSIZE_T dwMaximumSize = %zd / %#zx\n"
                        "Current process name: ", fIOoptions, fIOoptions, dwInitialSize, dwInitialSize, dwMaximumSize, dwMaximumSize);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    HANDLE returnVal = OldHeapCreate(fIOoptions, dwInitialSize, dwMaximumSize);
    if(ArgsAndDetails == ""){    // 如果是本程序自身的调用，不写日志
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (HANDLE) 0x%p\n", returnVal);
    getLastInfoAndWrite(ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)BOOL WINAPI NewHeapDestroy(HANDLE hHeap){
    if(entranceWatchdog)
        return OldHeapDestroy(hHeap);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectHeapDestroy){
        char* buffer = writeLog("HeapDestroy");
        char* args = (char*)calloc(1, 200);
        sprintf(args, "Arguments:\n"
                        "\tHANDLE hHeap = 0x%p\n"
                        "Current process name: ", hHeap);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    BOOL returnVal = OldHeapDestroy(hHeap);
    if(ArgsAndDetails == ""){    // 如果是本程序自身的调用，不写日志
        entranceWatchdog = false;
        return returnVal;
    }
    string retStr = "Return Value: (BOOL) ";
    retStr += returnVal ? "1 / true\n" : "0 / false\n";
    getLastInfoAndWrite(ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)LPVOID WINAPI NewHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes){
    if(entranceWatchdog)
        return OldHeapAlloc(hHeap, dwFlags, dwBytes);
    entranceWatchdog = true;
    string* ArgsAndDetails = nullptr;
    if(injectHeapAlloc){
        ArgsAndDetails = new string();
        char* buffer = writeLog("HeapAlloc");
        char* args = (char*)calloc(1, 200);
        sprintf(args, "Arguments:\n"
                        "\tHANDLE hHeap = 0x%p\n"
                        "\tDWORD dwFlags = %lu / %#lx\n"
                        "\tSIZE_T dwBytes = %llu / %#llx\n"
                        "Current process name: ", hHeap, dwFlags, dwFlags, dwBytes, dwBytes);
        *ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }else{
        entranceWatchdog = false;
        return OldHeapAlloc(hHeap, dwFlags, dwBytes);
    }
    LPVOID returnVal = OldHeapAlloc(hHeap, dwFlags, dwBytes);
    if(*ArgsAndDetails == "")
        return returnVal;
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (LPVOID) 0x%p\n", returnVal);
    getLastInfoAndWrite(*ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)BOOL WINAPI NewHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem){
    if(entranceWatchdog)
        return OldHeapFree(hHeap, dwFlags, lpMem);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectHeapFree){
        char* buffer = writeLog("HeapFree");
        char* args = (char*)calloc(1, 200);
        sprintf(args, "Arguments:\n"
                        "\tHANDLE hHeap = 0x%p\n"
                        "\tDWORD dwFlags = %lu / %#lx\n"
                        "\tLPVOID lpMem = 0x%p\n"
                        "Current process name: ", hHeap, dwFlags, dwFlags, lpMem);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    BOOL returnVal = OldHeapFree(hHeap, dwFlags, lpMem);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    string retStr = "Return Value: (BOOL) ";
    retStr += returnVal ? "1 / true\n" : "0 / false\n";
    getLastInfoAndWrite(ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

// 文件操作截取
static HANDLE (WINAPI* OldCreateFile)(
        _In_ LPCWSTR lpFileName,//指向文件名的指针
        _In_ DWORD dwDesiredAccess,// 访问模式（写 / 读）
        _In_ DWORD dwShareMode,// 共享模式
        _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,// 指向安全属性的指针
        _In_ DWORD dwCreationDisposition,// 如何创建
        _In_ DWORD dwFlagsAndAttributes, // 文件属性
        _In_opt_ HANDLE hTemplateFile// 用于复制文件句柄
    ) = CreateFile;
static BOOL (WINAPI* OldReadFile)(
        __in HANDLE hFile, // 文件句柄
        __out LPVOID lpBuffer, // 接收数据用的 buffer
        __in DWORD nNumberOfBytesToRead, // 要读取的字节数
        __out LPDWORD lpNumberOfBytesRead, // 实际读取到的字节数
        __in LPOVERLAPPED lpOverlapped // OVERLAPPED 结构，一般设定为 NULL
    ) = ReadFile;
static BOOL (WINAPI* OldWriteFile)(
        __in HANDLE hFile,                   // 文件句柄
        __in LPCVOID lpBuffer,               // 要写入的数据
        __in DWORD nNumberOfBytesToWrite,    // 要写入的字节数
        __out LPDWORD lpNumberOfBytesWritten, // 实际写入的字节数
        __in LPOVERLAPPED lpOverlapped       // OVERLAPPED 结构，一般设定为 NULL
      ) = WriteFile;
static HFILE (WINAPI* OldOpenFile)(
    _In_ LPCSTR lpFileName,          // 文件名
    _Inout_ LPOFSTRUCT lpReOpenBuff,
    _In_ UINT uStyle
    ) = OpenFile;

extern "C" __declspec(dllexport)HANDLE WINAPI NewCreateFile(
        _In_ LPCWSTR lpFileName,//指向文件名的指针
        _In_ DWORD dwDesiredAccess,// 访问模式（写 / 读）
        _In_ DWORD dwShareMode,// 共享模式
        _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,// 指向安全属性的指针
        _In_ DWORD dwCreationDisposition,// 如何创建
        _In_ DWORD dwFlagsAndAttributes, // 文件属性
        _In_opt_ HANDLE hTemplateFile// 用于复制文件句柄
        ){
    if(entranceWatchdog)
        return OldCreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                             dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectCreateFile){
        char* buffer = writeLog("CreateFile");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tLPCWSTR lpFileName = 0x%p / \"%ls\"\n"
                        "\tDWORD dwDesiredAccess = %lu / %#lx\n"
                        "\tDWORD dwShareMode = %lu / %#lx\n"
                        "\tLPSECURITY_ATTRIBUTES lpSecurityAttributes = %p\n"
                        "\tDWORD dwCreationDisposition = %lu / %#lx\n"
                        "\tDWORD dwFlagsAndAttributes = %lu / %#lx\n"
                        "\tHANDLE hTemplateFile = 0x%p\n"
                        "Current process name: ", lpFileName, lpFileName, dwDesiredAccess, dwDesiredAccess,
                dwShareMode, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwCreationDisposition,
                dwFlagsAndAttributes, dwFlagsAndAttributes, hTemplateFile);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    HANDLE returnVal = OldCreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                  dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (HANDLE) 0x%p\n", returnVal);
    getLastInfoAndWrite(ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)BOOL WINAPI NewReadFile(
        __in HANDLE hFile, // 文件句柄
        __out LPVOID lpBuffer, // 接收数据用的 buffer
        __in DWORD nNumberOfBytesToRead, // 要读取的字节数
        __out LPDWORD lpNumberOfBytesRead, // 实际读取到的字节数
        __in LPOVERLAPPED lpOverlapped // OVERLAPPED 结构，一般设定为 NULL
        ){
    if(entranceWatchdog)
        return OldReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectReadFile){
        char* buffer = writeLog("ReadFile");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tHANDLE hFile = 0x%p\n"
                        "\tLPVOID lpBuffer = 0x%p\n"
                        "\tDWORD nNumberOfBytesToRead = %lu / %#lx\n"
                        "\tLPDWORD lpNumberOfBytesRead = 0x%p\n"
                        "\tLPOVERLAPPED lpOverlapped = 0x%p\n"
                        "Current process name: ", hFile, lpBuffer,
                nNumberOfBytesToRead, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    BOOL returnVal = OldReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    string retStr = "Return Value: (BOOL) ";
    retStr += returnVal ? "1 / true\n" : "0 / false\n";
    char outputArgVal[0x100];
    sprintf_s(outputArgVal, "After execution:\n"
                            "\tLPDWORD lpNumberOfBytesRead => %u / 0x%x\n", *lpNumberOfBytesRead, *lpNumberOfBytesRead);
    getLastInfoAndWrite(ArgsAndDetails, retStr, outputArgVal);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)BOOL WINAPI NewWriteFile(
        __in          HANDLE hFile,                   // 文件句柄
        __in          LPCVOID lpBuffer,               // 要写入的数据
        __in          DWORD nNumberOfBytesToWrite,    // 要写入的字节数
        __out         LPDWORD lpNumberOfBytesWritten, // 实际写入的字节数
        __in          LPOVERLAPPED lpOverlapped       // OVERLAPPED 结构，一般设定为 NULL
        ){
    if(entranceWatchdog)
        return OldWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectWriteFile){
        char* buffer = writeLog("WriteFile");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tHANDLE hFile = 0x%p\n"
                        "\tLPVOID lpBuffer = 0x%p\n"
                        "\tDWORD nNumberOfBytesToWrite = %lu / %#lx\n"
                        "\tLPDWORD lpNumberOfBytesWritten = 0x%p\n"
                        "\tLPOVERLAPPED lpOverlapped = 0x%p\n"
                        "Current process name: ", hFile, lpBuffer,
                nNumberOfBytesToWrite, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    BOOL returnVal = OldWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    string retStr = "Return Value: (BOOL) ";
    retStr += returnVal ? "1 / true\n" : "0 / false\n";
    char outputArgVal[0x100];
    sprintf_s(outputArgVal, "After execution:\n"
                            "\tLPDWORD lpNumberOfBytesWritten => %u / 0x%x\n", *lpNumberOfBytesWritten, *lpNumberOfBytesWritten);
    getLastInfoAndWrite(ArgsAndDetails, retStr, outputArgVal);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)HFILE WINAPI NewOpenFile(
        _In_    LPCSTR lpFileName,          // 文件名
        _Inout_ LPOFSTRUCT lpReOpenBuff,
        _In_    UINT uStyle
        ){
    if(entranceWatchdog)
        return OldOpenFile(lpFileName, lpReOpenBuff, uStyle);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectOpenFile){
        char* buffer = writeLog("OpenFile");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tLPCSTR lpFileName = 0x%p / \"%s\"\n"
                        "\tLPOFSTRUCT lpReOpenBuff = 0x%p\n"
                        "\tUINT uStyle = %u / %#x\n"
                        "Current process name: ", lpFileName, lpFileName, lpReOpenBuff, uStyle, uStyle);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    BOOL returnVal = OldOpenFile(lpFileName, lpReOpenBuff, uStyle);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (HFILE) %#x\n", returnVal);
    getLastInfoAndWrite(ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

static LSTATUS (WINAPI* OldRegCreateKeyEx)(
        _In_ HKEY hKey,
        _In_ LPCWSTR lpSubKey,
        _Reserved_ DWORD Reserved,
        _In_opt_ LPWSTR lpClass,
        _In_ DWORD dwOptions,
        _In_ REGSAM samDesired,
        _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        _Out_ PHKEY phkResult,
        _Out_opt_ LPDWORD lpdwDisposition
        ) = RegCreateKeyEx;
static LSTATUS (WINAPI* OldRegSetValueEx)(
        _In_ HKEY hKey,
        _In_opt_ LPCWSTR lpValueName,
        _Reserved_ DWORD Reserved,
        _In_ DWORD dwType,
        _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
        _In_ DWORD cbData
        ) = RegSetValueEx;
static LSTATUS (WINAPI* OldRegDeleteValue)(
        _In_ HKEY hKey,
        _In_opt_ LPCWSTR lpValueName
        ) = RegDeleteValue;
static LSTATUS (WINAPI* OldRegCloseKey)(
        _In_ HKEY hKey
        ) = RegCloseKey;
static LSTATUS (WINAPI* OldRegOpenKeyEx)(
        _In_ HKEY hKey,
        _In_opt_ LPCWSTR lpSubKey,
        _In_opt_ DWORD ulOptions,
        _In_ REGSAM samDesired,
        _Out_ PHKEY phkResult
        ) = RegOpenKeyEx;

extern "C" __declspec(dllexport)LSTATUS WINAPI NewRegCreateKeyEx(
        _In_ HKEY hKey,
        _In_ LPCWSTR lpSubKey,
        _Reserved_ DWORD Reserved,
        _In_opt_ LPWSTR lpClass,
        _In_ DWORD dwOptions,
        _In_ REGSAM samDesired,
        _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        _Out_ PHKEY phkResult,
        _Out_opt_ LPDWORD lpdwDisposition
        ){
    if(entranceWatchdog)
        return OldRegCreateKeyEx(hKey, lpSubKey, Reserved, lpClass,
                                 dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectRegCreateKeyEx){
        char* buffer = writeLog("RegCreateKeyEx");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tHKEY hKey = 0x%p\n"
                        "\tLPCWSTR lpSubKey = 0x%p / \"%ls\"\n"
                        "\tDWORD Reserved = %lu / %#lx\n"
                        "\tLPWSTR lpClass = 0x%p / \"%ls\"\n"
                        "\tDWORD dwOptions = %lu / %#lx\n"
                        "\tREGSAM samDesired = %lu / %#lx\n"
                        "\tLPSECURITY_ATTRIBUTES lpSecurityAttributes = 0x%p\n"
                        "\tPHKEY phkResult = 0x%p\n"
                        "\tLPDWORD lpdwDisposition = 0x%p\n"
                        "Current process name: ", hKey, lpSubKey, lpSubKey, Reserved, Reserved,
                lpClass, lpClass, dwOptions, dwOptions, samDesired, samDesired, lpSecurityAttributes,
                phkResult, lpdwDisposition);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    LSTATUS returnVal = OldRegCreateKeyEx(hKey, lpSubKey, Reserved, lpClass,
                                       dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (LSTATUS) %#x\n", returnVal);
    char outputArgVal[0x100];
    sprintf_s(outputArgVal, "After execution:\n"
                            "\tPHKEY phkResult => 0x%p\n", *phkResult);
    getLastInfoAndWrite(ArgsAndDetails, retStr, outputArgVal);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)LSTATUS WINAPI NewRegSetValueEx(
        _In_ HKEY hKey,
        _In_opt_ LPCWSTR lpValueName,
        _Reserved_ DWORD Reserved,
        _In_ DWORD dwType,
        _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
        _In_ DWORD cbData
        ){
    if(entranceWatchdog)
        return OldRegSetValueEx(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectRegSetValueEx){
        char* buffer = writeLog("RegSetValueEx");
        char* args = (char*)calloc(1, 0x200);
        if(dwType == REG_SZ || dwType == REG_EXPAND_SZ || dwType == REG_MULTI_SZ)
            sprintf(args, "Arguments:\n"
                            "\tHKEY hKey = 0x%p\n"
                            "\tLPCWSTR lpValueName = 0x%p / \"%ls\"\n"
                            "\tDWORD Reserved = %lu / %#lx\n"
                            "\tDWORD dwType = %lu / %#lx\n"
                            "\tBYTE* lpData = 0x%p / \"%ls\"\n"
                            "\tDWORD cbData = %lu / %#lx\n"
                            "Current process name: ", hKey, lpValueName, lpValueName, Reserved, Reserved,
                    dwType, dwType, lpData, (wchar_t*)lpData, cbData, cbData);
        else
            sprintf(args, "Arguments:\n"
                            "\tHKEY hKey = 0x%p\n"
                            "\tLPCWSTR lpValueName = 0x%p / \"%ls\"\n"
                            "\tDWORD Reserved = %lu / %#lx\n"
                            "\tDWORD dwType = %lu / %#lx\n"
                            "\tBYTE* lpData = 0x%p\n"
                            "\tDWORD cbData = %lu / %#lx\n"
                            "Current process name: ", hKey, lpValueName, lpValueName, Reserved, Reserved,
                    dwType, dwType, lpData, cbData, cbData);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    LSTATUS returnVal = OldRegSetValueEx(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (LSTATUS) %#x\n", returnVal);
    getLastInfoAndWrite(ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)LSTATUS WINAPI NewRegDeleteValue(
        _In_ HKEY hKey,
        _In_opt_ LPCWSTR lpValueName
        ){
    if(entranceWatchdog)
        return OldRegDeleteValue(hKey, lpValueName);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectRegDeleteValue){
        char* buffer = writeLog("RegDeleteValue");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tHKEY hKey = 0x%p\n"
                        "\tLPCWSTR lpValueName = 0x%p / \"%ls\"\n"
                        "Current process name: ", hKey, lpValueName, lpValueName);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    LSTATUS returnVal = OldRegDeleteValue(hKey, lpValueName);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (LSTATUS) %#x\n", returnVal);
    getLastInfoAndWrite(ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)LSTATUS WINAPI NewRegCloseKey(
        _In_ HKEY hKey
        ){
    if(entranceWatchdog)
        return OldRegCloseKey(hKey);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectRegCloseKey){
        char* buffer = writeLog("RegCloseKey");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tHKEY hKey = 0x%p\n"
                        "Current process name: ", hKey);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    LSTATUS returnVal = OldRegCloseKey(hKey);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (LSTATUS) %#x\n", returnVal);
    getLastInfoAndWrite(ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)LSTATUS WINAPI NewRegOpenKeyEx(
        _In_ HKEY hKey,
        _In_opt_ LPCWSTR lpSubKey,
        _In_opt_ DWORD ulOptions,
        _In_ REGSAM samDesired,
        _Out_ PHKEY phkResult
        ){
    if(entranceWatchdog)
        return OldRegOpenKeyEx(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectRegOpenKeyEx){
        char* buffer = writeLog("RegOpenKeyEx");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tHKEY hKey = 0x%p\n"
                        "\tLPCWSTR lpSubKey = 0x%p / \"%ls\"\n"
                        "\tDWORD ulOptions = %lu / %lx\n"
                        "\tREGSAM samDesired = %lu / %lx\n"
                        "\tPHKEY phkResult = 0x%p\n"
                        "Current process name: ", hKey, lpSubKey, lpSubKey,
                ulOptions, ulOptions, samDesired, samDesired, phkResult);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    LSTATUS returnVal = OldRegOpenKeyEx(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (LSTATUS) %#x\n", returnVal);
    getLastInfoAndWrite(ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        logFile = new fstream("./hookLog/hookLogs.log", ios::trunc | ios::out);
        DisableThreadLibraryCalls(hModule);
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OldMessageBoxW, (void*)NewMessageBoxW);
        DetourAttach(&(PVOID&)OldMessageBoxA, (void*)NewMessageBoxA);
        DetourAttach(&(PVOID&)OldHeapCreate, (void*)NewHeapCreate);
        DetourAttach(&(PVOID&)OldHeapDestroy, (void*)NewHeapDestroy);
        DetourAttach(&(PVOID&)OldHeapAlloc, (void*)NewHeapAlloc);
        DetourAttach(&(PVOID&)OldHeapFree, (void*)NewHeapFree);
        DetourAttach(&(PVOID&)OldCreateFile, (void*)NewCreateFile);
        DetourAttach(&(PVOID&)OldReadFile, (void*)NewReadFile);
        DetourAttach(&(PVOID&)OldWriteFile, (void*)NewWriteFile);
        DetourAttach(&(PVOID&)OldRegCreateKeyEx, (void*)NewRegCreateKeyEx);
        DetourAttach(&(PVOID&)OldRegSetValueEx, (void*)NewRegSetValueEx);
        DetourAttach(&(PVOID&)OldRegDeleteValue, (void*)NewRegDeleteValue);
        DetourAttach(&(PVOID&)OldRegCloseKey, (void*)NewRegCloseKey);
        DetourAttach(&(PVOID&)OldRegOpenKeyEx, (void*)NewRegOpenKeyEx);
        DetourTransactionCommit();
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH: {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)OldMessageBoxA, (void*)NewMessageBoxA);
        DetourDetach(&(PVOID&)OldMessageBoxW, (void*)NewMessageBoxW);
        DetourDetach(&(PVOID&)OldHeapCreate, (void*)NewHeapCreate);
        DetourDetach(&(PVOID&)OldHeapDestroy, (void*)NewHeapDestroy);
        DetourDetach(&(PVOID&)OldHeapAlloc, (void*)NewHeapAlloc);
        DetourDetach(&(PVOID&)OldHeapFree, (void*)NewHeapFree);
        DetourDetach(&(PVOID&)OldCreateFile, (void*)NewCreateFile);
        DetourDetach(&(PVOID&)OldReadFile, (void*)NewReadFile);
        DetourDetach(&(PVOID&)OldWriteFile, (void*)NewWriteFile);
        DetourDetach(&(PVOID&)OldRegCreateKeyEx, (void*)NewRegCreateKeyEx);
        DetourDetach(&(PVOID&)OldRegSetValueEx, (void*)NewRegSetValueEx);
        DetourDetach(&(PVOID&)OldRegDeleteValue, (void*)NewRegDeleteValue);
        DetourDetach(&(PVOID&)OldRegCloseKey, (void*)NewRegCloseKey);
        DetourDetach(&(PVOID&)OldRegOpenKeyEx, (void*)NewRegOpenKeyEx);
        DetourTransactionCommit();
        logCounter = 0;
        logFile->close();
        break;
    }
    }
    return TRUE;
}

