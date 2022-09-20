// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "framework.h"
#include "WinSock2.h"
#include "detours.h"
#include "winInfo.h"
#include "util.h"
#include <cstdio>
#include <cstdarg>
#include <iostream>
#include <fstream>
#include <QString>
#include <QReadWriteLock>

using namespace std;

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "ws2_32.lib")

fstream* memoryCap;
fstream* tmpFile = new fstream();
fstream* tmpCap = new fstream();
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
bool injectCloseHandle = false;
bool injectRegCreateKeyEx = false;
bool injectRegSetValueEx = false;
bool injectRegDeleteValue = false;
bool injectRegCloseKey = false;
bool injectRegOpenKeyEx = false;
bool injectRegDeleteKeyEx = false;
bool injectSend = false;
bool injectRecv = false;
bool injectConnect = false;
bool injectBind = false;
bool injectSocket = false;
bool injectAccept = false;

bool mutexSignal = false;
char lastHookbuffer[0x400] = {0};
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
extern "C" __declspec(dllexport) void openInjectCloseHandle(bool choice){injectCloseHandle = choice;};
extern "C" __declspec(dllexport) void openInjectRegCreateKeyEx(bool choice){injectRegCreateKeyEx = choice;};
extern "C" __declspec(dllexport) void openInjectRegSetValueEx(bool choice){injectRegSetValueEx = choice;};
extern "C" __declspec(dllexport) void openInjectRegDeleteValue(bool choice){injectRegDeleteValue = choice;};
extern "C" __declspec(dllexport) void openInjectRegCloseKey(bool choice){injectRegCloseKey = choice;};
extern "C" __declspec(dllexport) void openInjectRegOpenKeyEx(bool choice){injectRegOpenKeyEx = choice;};
extern "C" __declspec(dllexport) void openInjectRegDeleteKeyEx(bool choice){injectRegDeleteKeyEx = choice;};
extern "C" __declspec(dllexport) void openInjectSend(bool choice){injectSend = choice;};
extern "C" __declspec(dllexport) void openInjectRecv(bool choice){injectRecv = choice;};
extern "C" __declspec(dllexport) void openInjectConnect(bool choice){injectConnect = choice;};
extern "C" __declspec(dllexport) void openInjectSocket(bool choice){injectSocket = choice;};
extern "C" __declspec(dllexport) void openInjectBind(bool choice){injectBind = choice;};
extern "C" __declspec(dllexport) void openInjectAccept(bool choice){injectAccept = choice;};

extern "C" __declspec(dllexport) void setMutexSignal(){mutexSignal = false;};
extern "C" __declspec(dllexport) bool getMutexSignal(){return mutexSignal;};

extern "C" __declspec(dllexport) char* getLastHookBeforeCall(){return lastHookbuffer;};

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
    strcpy_s(lastHookbuffer, totalOut.c_str());
    return totalOut;
}

void getLastInfoAndWrite(string totalOut, string returnVal, string otherString = "",
                         unsigned bufLen = 0, const char* buf = nullptr){
    totalOut += returnVal;
    totalOut += otherString;
    totalOut += "----------------------------------------------------\n";

    while(mutexSignal);

    // 写入二进制文件，拷贝内存中的内容
    uint64_t addr = (uint64_t)buf;
    unsigned size = bufLen;
    memoryCap->write((char*)(&addr), 8);
    memoryCap->write((char*)(&size), 4);
    if(bufLen != 0)
        memoryCap->write(buf, bufLen);

    tmpCap->open("./hookLog/lastCap.dat", ios::binary | ios::out | ios::trunc);
    if(bufLen != 0)
        tmpCap->write(buf, bufLen);
    tmpCap->close();

    tmpFile->open("./hookLog/lasthook.tmp", ios::out | ios::trunc);
    *tmpFile << totalOut;
    tmpFile->close();

    mutexSignal = true;

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
static BOOL (WINAPI* OldCloseHandle)(_In_ _Post_ptr_invalid_ HANDLE hObject) = CloseHandle;

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
    if(entranceWatchdog || hFile == GetStdHandle(STD_INPUT_HANDLE))
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
    if(hFile != STDIN && hFile != STDOUT && hFile != STDERR)
        getLastInfoAndWrite(ArgsAndDetails, retStr, outputArgVal, *lpNumberOfBytesRead, (char*)lpBuffer);
    else
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
    if(entranceWatchdog || hFile == GetStdHandle(STD_OUTPUT_HANDLE) || hFile == GetStdHandle(STD_ERROR_HANDLE))
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
    if(hFile != STDIN && hFile != STDOUT && hFile != STDERR)
        getLastInfoAndWrite(ArgsAndDetails, retStr, outputArgVal, *lpNumberOfBytesWritten, (char*)lpBuffer);
    else
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

extern "C" __declspec(dllexport)BOOL WINAPI NewCloseHandle(_In_ _Post_ptr_invalid_ HANDLE hObject){
    if(entranceWatchdog)
        return OldCloseHandle(hObject);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectCloseHandle){
        char* buffer = writeLog("CloseHandle");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tHANDLE hObject = 0x%p\n"
                        "Current process name: ", hObject);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    BOOL returnVal = OldCloseHandle(hObject);
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
static LSTATUS (WINAPI* OldRegDeleteKeyEx)(
        _In_ HKEY hKey,
        _In_ LPCWSTR lpSubKey,
        _In_ REGSAM samDesired,
        _Reserved_ DWORD Reserved
        ) = RegDeleteKeyEx;

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
    char outputArgVal[0x100];
    sprintf_s(outputArgVal, "After execution:\n"
                            "\tPHKEY phkResult => 0x%p\n", *phkResult);
    getLastInfoAndWrite(ArgsAndDetails, retStr, outputArgVal);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)LSTATUS WINAPI NewRegDeleteKeyEx(
        _In_ HKEY hKey,
        _In_ LPCWSTR lpSubKey,
        _In_ REGSAM samDesired,
        _Reserved_ DWORD Reserved
        ){
    if(entranceWatchdog)
        return OldRegDeleteKeyEx(hKey, lpSubKey, samDesired, Reserved);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectRegDeleteKeyEx){
        char* buffer = writeLog("RegDeleteKeyEx");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tHKEY hKey = 0x%p\n"
                        "\tLPCWSTR lpSubKey = 0x%p / \"%ls\"\n"
                        "\tREGSAM samDesired = %lu / %lx\n"
                        "\tDWORD Reserved = %lu / %lx\n"
                        "Current process name: ", hKey, lpSubKey, lpSubKey,
                samDesired, samDesired, Reserved, Reserved);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    LSTATUS returnVal = OldRegDeleteKeyEx(hKey, lpSubKey, samDesired, Reserved);
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

static int (WSAAPI* OldSend)(
        _In_ SOCKET s,
        _In_reads_bytes_(len) const char FAR * buf,
        _In_ int len,
        _In_ int flags
        ) = send;
static int (WSAAPI* OldRecv)(
        _In_ SOCKET s,
        _Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR * buf,
        _In_ int len,
        _In_ int flags
        ) = recv;
static int (WSAAPI* OldBind)(
        _In_ SOCKET s,
        _In_reads_bytes_(namelen) const struct sockaddr FAR * name,
        _In_ int namelen
        ) = bind;
static SOCKET (WSAAPI* OldSocket)(
        _In_ int af,
        _In_ int type,
        _In_ int protocol
        ) = socket;
static int (WSAAPI* OldConnect)(
        _In_ SOCKET s,
        _In_reads_bytes_(namelen) const struct sockaddr FAR * name,
        _In_ int namelen
        ) = connect;
static SOCKET (WSAAPI* OldAccept)(
        _In_ SOCKET s,
        _Out_writes_bytes_opt_(*addrlen) struct sockaddr FAR * addr,
        _Inout_opt_ int FAR * addrlen
        ) = accept;

//static int (WSAAPI* OldWSASend)(
//    _In_ SOCKET s,
//    _In_reads_(dwBufferCount) LPWSABUF lpBuffers,
//    _In_ DWORD dwBufferCount,
//    _Out_opt_ LPDWORD lpNumberOfBytesSent,
//    _In_ DWORD dwFlags,
//    _Inout_opt_ LPWSAOVERLAPPED lpOverlapped,
//    _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
//    ) = WSASend;
//static int (WSAAPI* OldWSARecv)(
//    _In_ SOCKET s,
//    _In_reads_(dwBufferCount) __out_data_source(NETWORK) LPWSABUF lpBuffers,
//    _In_ DWORD dwBufferCount,
//    _Out_opt_ LPDWORD lpNumberOfBytesRecvd,
//    _Inout_ LPDWORD lpFlags,
//    _Inout_opt_ LPWSAOVERLAPPED lpOverlapped,
//    _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
//    ) = WSARecv;
//static int (WSAAPI* OldWSAConnect)(
//    _In_ SOCKET s,
//    _In_reads_bytes_(namelen) const struct sockaddr FAR * name,
//    _In_ int namelen,
//    _In_opt_ LPWSABUF lpCallerData,
//    _Out_opt_ LPWSABUF lpCalleeData,
//    _In_opt_ LPQOS lpSQOS,
//    _In_opt_ LPQOS lpGQOS
//    ) = WSAConnect;
//static SOCKET (WSAAPI* OldWSASocketW)(
//    _In_ int af,
//    _In_ int type,
//    _In_ int protocol,
//    _In_opt_ LPWSAPROTOCOL_INFOW lpProtocolInfo,
//    _In_ GROUP g,
//    _In_ DWORD dwFlags
//    ) = WSASocketW;

extern "C" __declspec(dllexport)int WINAPI NewSend(
        _In_ SOCKET s,
        _In_reads_bytes_(len) const char FAR * buf,
        _In_ int len,
        _In_ int flags
        ){
    if(entranceWatchdog)
        return OldSend(s, buf, len, flags);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectSend){
        char* buffer = writeLog("send");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tSOCKET s = 0x%zx\n"
                        "\tconst_char* buf = 0x%p\n"
                        "\tint len = %d / %x\n"
                        "\tint flags = %d / %x\n"
                        "Current process name: ", s, buf,
                len, len, flags, flags);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    int returnVal = OldSend(s, buf, len, flags);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (int) %d / %#x\n", returnVal, returnVal);
    getLastInfoAndWrite(ArgsAndDetails, retStr, "", len, buf);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)int WINAPI NewRecv(
        _In_ SOCKET s,
        _Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR * buf,
        _In_ int len,
        _In_ int flags
        ){
    if(entranceWatchdog)
        return OldRecv(s, buf, len, flags);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectRecv){
        char* buffer = writeLog("recv");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tSOCKET s = 0x%zx\n"
                        "\tconst_char* buf = 0x%p\n"
                        "\tint len = %d / %x\n"
                        "\tint flags = %d / %x\n"
                        "Current process name: ", s, buf,
                len, len, flags, flags);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    int returnVal = OldRecv(s, buf, len, flags);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (int) %d / %#x\n", returnVal, returnVal);
    getLastInfoAndWrite(ArgsAndDetails, retStr, "", len, buf);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)int WINAPI NewConnect(
        _In_ SOCKET s,
        _In_reads_bytes_(namelen) const struct sockaddr FAR * name,
        _In_ int namelen
        ){
    if(entranceWatchdog)
        return OldConnect(s, name, namelen);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectConnect){
        char* buffer = writeLog("connect");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tSOCKET s = 0x%zx\n"
                        "\tsockaddr* name = 0x%p\n"
                        "\tshort name->sin_family = %d / 0x%hx\n"
                        "\tULONG name->sin_addr.s_addr = %lu / 0x%lx\n"
                        "\tshort name->sin_port = %d / %0xhx\n"
                        "\tint namelen = %d / %x\n"
                        "Current process name: ", s, name, ((sockaddr_in*)name)->sin_family,
                ((sockaddr_in*)name)->sin_family, ((sockaddr_in*)name)->sin_addr.s_addr,
                ((sockaddr_in*)name)->sin_addr.s_addr, ((sockaddr_in*)name)->sin_port,
                ((sockaddr_in*)name)->sin_port, namelen, namelen);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    int returnVal = OldConnect(s, name, namelen);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (int) %d / %#x\n", returnVal, returnVal);
    getLastInfoAndWrite(ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)int WINAPI NewBind(
        _In_ SOCKET s,
        _In_reads_bytes_(namelen) const struct sockaddr FAR * name,
        _In_ int namelen
        ){
    if(entranceWatchdog)
        return OldBind(s, name, namelen);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectBind){
        char* buffer = writeLog("bind");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tSOCKET s = 0x%zx\n"
                        "\tsockaddr* name = 0x%p\n"
                        "\tshort name->sin_family = %d / 0x%hx\n"
                        "\tULONG name->sin_addr.s_addr = %lu / 0x%lx\n"
                        "\tshort name->sin_port = %d / 0x%hx\n"
                        "\tint namelen = %d / %x\n"
                        "Current process name: ", s, name, ((sockaddr_in*)name)->sin_family,
                ((sockaddr_in*)name)->sin_family, ((sockaddr_in*)name)->sin_addr.s_addr,
                ((sockaddr_in*)name)->sin_addr.s_addr, ((sockaddr_in*)name)->sin_port,
                ((sockaddr_in*)name)->sin_port, namelen, namelen);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    int returnVal = OldBind(s, name, namelen);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (int) %d / %#x\n", returnVal, returnVal);
    getLastInfoAndWrite(ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)SOCKET WSAAPI NewSocket(
        _In_ int af,
        _In_ int type,
        _In_ int protocol
        ){
    if(entranceWatchdog)
        return OldSocket(af, type, protocol);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectSocket){
        char* buffer = writeLog("socket");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tint af = %d / 0x%x\n"
                        "\tint type = %d / 0x%x\n"
                        "\tint protocol = %d / 0x%x\n"
                        "Current process name: ", af, af, type, type, protocol, protocol);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    SOCKET returnVal = OldSocket(af, type, protocol);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (SOCKET) %#zx\n", returnVal);
    getLastInfoAndWrite(ArgsAndDetails, retStr);
    entranceWatchdog = false;
    return returnVal;
}

extern "C" __declspec(dllexport)SOCKET WSAAPI NewAccept(
        _In_ SOCKET s,
        _Out_writes_bytes_opt_(*addrlen) struct sockaddr FAR * addr,
        _Inout_opt_ int FAR * addrlen
        ){
    if(entranceWatchdog)
        return OldAccept(s, addr, addrlen);
    entranceWatchdog = true;
    string ArgsAndDetails;
    if(injectAccept){
        char* buffer = writeLog("accept");
        char* args = (char*)calloc(1, 0x200);
        sprintf(args, "Arguments:\n"
                        "\tSOCKET s = 0x%zx\n"
                        "\tsockaddr* addr = 0x%p\n"
                        "\tint* addrlen = 0x%p\n"
                        "Current process name: ", s, addr, addrlen);
        ArgsAndDetails = getMainInfo(buffer, args);
        free(args);
        free(buffer);
    }
    SOCKET returnVal = OldAccept(s, addr, addrlen);
    if(ArgsAndDetails == ""){
        entranceWatchdog = false;
        return returnVal;
    }
    char retStr[0x30];
    sprintf_s(retStr, "Return value: (SOCKET) %#zx\n", returnVal);
    char outputArgVal[0x100];
    sprintf_s(outputArgVal, "After execution:\n"
                            "\tshort addr->sin_family = %d / 0x%hx\n"
                            "\tULONG addr->sin_addr.s_addr = %lu / 0x%lx\n"
                            "\tshort addr->sin_port = %d / 0x%hx\n", ((sockaddr_in*)addr)->sin_family,
              ((sockaddr_in*)addr)->sin_family, ((sockaddr_in*)addr)->sin_addr.s_addr,
              ((sockaddr_in*)addr)->sin_addr.s_addr, ((sockaddr_in*)addr)->sin_port,
              ((sockaddr_in*)addr)->sin_port);
    getLastInfoAndWrite(ArgsAndDetails, retStr, outputArgVal);
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
        // 记录内存内容的文件，其为二进制文件，格式如下：
        // 一个内存块的记录包含地址、大小、内容三部分，地址8字节，大小4字节，后面为内容
        memoryCap = new fstream("./hookLog/memoryCapture.dat", ios::binary | ios::out | ios::trunc);
        memset(lastHookbuffer, 0, 0x400);
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
        DetourAttach(&(PVOID&)OldCloseHandle, (void*)NewCloseHandle);
        DetourAttach(&(PVOID&)OldRegCreateKeyEx, (void*)NewRegCreateKeyEx);
        DetourAttach(&(PVOID&)OldRegSetValueEx, (void*)NewRegSetValueEx);
        DetourAttach(&(PVOID&)OldRegDeleteValue, (void*)NewRegDeleteValue);
        DetourAttach(&(PVOID&)OldRegCloseKey, (void*)NewRegCloseKey);
        DetourAttach(&(PVOID&)OldRegOpenKeyEx, (void*)NewRegOpenKeyEx);
        DetourAttach(&(PVOID&)OldRegDeleteKeyEx, (void*)NewRegDeleteKeyEx);
        DetourAttach(&(PVOID&)OldSend, (void*)NewSend);
        DetourAttach(&(PVOID&)OldRecv, (void*)NewRecv);
        DetourAttach(&(PVOID&)OldConnect, (void*)NewConnect);
        DetourAttach(&(PVOID&)OldBind, (void*)NewBind);
        DetourAttach(&(PVOID&)OldSocket, (void*)NewSocket);
        DetourAttach(&(PVOID&)OldAccept, (void*)NewAccept);
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
        DetourDetach(&(PVOID&)OldCloseHandle, (void*)NewCloseHandle);
        DetourDetach(&(PVOID&)OldRegCreateKeyEx, (void*)NewRegCreateKeyEx);
        DetourDetach(&(PVOID&)OldRegSetValueEx, (void*)NewRegSetValueEx);
        DetourDetach(&(PVOID&)OldRegDeleteValue, (void*)NewRegDeleteValue);
        DetourDetach(&(PVOID&)OldRegCloseKey, (void*)NewRegCloseKey);
        DetourDetach(&(PVOID&)OldRegOpenKeyEx, (void*)NewRegOpenKeyEx);
        DetourDetach(&(PVOID&)OldRegDeleteKeyEx, (void*)NewRegDeleteKeyEx);
        DetourDetach(&(PVOID&)OldSend, (void*)NewSend);
        DetourDetach(&(PVOID&)OldRecv, (void*)NewRecv);
        DetourDetach(&(PVOID&)OldConnect, (void*)NewConnect);
        DetourDetach(&(PVOID&)OldBind, (void*)NewBind);
        DetourDetach(&(PVOID&)OldSocket, (void*)NewSocket);
        DetourDetach(&(PVOID&)OldAccept, (void*)NewAccept);
        DetourTransactionCommit();
        logCounter = 0;
        memoryCap->close();
        break;
    }
    }
    return TRUE;
}

