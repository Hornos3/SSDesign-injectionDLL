#include "winInfo.h"
#include <Psapi.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <assert.h>
#include <QStringList>
#include <QDebug>

#define STACK_INFO_LEN  1024

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "dbghelp.lib")

extern std::vector<module> modules;

WCHAR* getCurrentProcessName(){
    WCHAR* outString = (WCHAR*)calloc(sizeof(WCHAR), MAX_PATH);
    DWORD processID = getProcessID();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processID);
    if(hProcess == nullptr){
        free(outString);
        return nullptr;
    }
    DWORD length = MAX_PATH;
    BOOL success = QueryFullProcessImageName(hProcess, 0, outString, &length);
    if(success)
        return outString;
    free(outString);
    return nullptr;
}

DWORD getProcessID(){
    return GetCurrentProcessId();
}

bool QueryValue(const std::string& ValueName, const std::string& szModuleName,
                std::string& RetStr)
{
    bool bSuccess = FALSE;
    BYTE* m_lpVersionData = NULL;
    DWORD  m_dwLangCharset = 0;
    CHAR* tmpstr = NULL;
    do
    {
        if (!ValueName.size() || !szModuleName.size())
        { break; }
        DWORD dwHandle;
        // 判断系统能否检索到指定文件的版本信息
        //针对包含了版本资源的一个文件，判断容纳 文件版本信息需要一个多大的缓冲区
        //返回值说明Long，容纳文件的版本资源所需的缓冲区长度。如文件不包含版本信息，则返回一个0值。会设置GetLastError参数表
        DWORD dwDataSize = ::GetFileVersionInfoSizeA((LPCSTR)szModuleName.c_str(),
                           &dwHandle);
        if (dwDataSize == 0)
        { break; }
        //std::nothrow:在内存不足时，new (std::nothrow)并不抛出异常，而是将指针置NULL。
        m_lpVersionData = new (std::nothrow) BYTE[dwDataSize];// 分配缓冲区
        if (NULL == m_lpVersionData)
        { break; }
        // 检索信息
        //从支持版本标记的一个模块里获取文件版本信息
        if (!::GetFileVersionInfoA((LPCSTR)szModuleName.c_str(), dwHandle, dwDataSize,
                                   (void*)m_lpVersionData))
        { break; }
        UINT nQuerySize;
        DWORD* pTransTable;
        if (!::VerQueryValueA(m_lpVersionData, "\\VarFileInfo\\Translation",
                              (void**)&pTransTable, &nQuerySize))
        {
            break;
        }
        //MAKELONG 将两个16位的数联合成一个无符号的32位数
        m_dwLangCharset = MAKELONG(HIWORD(pTransTable[0]), LOWORD(pTransTable[0]));
        if (m_lpVersionData == NULL)
        { break; }
        tmpstr = new (std::nothrow) CHAR[128];// 分配缓冲区
        if (NULL == tmpstr)
        {
            break;
        }
        sprintf_s(tmpstr, 128, "\\StringFileInfo\\%08lx\\%s", m_dwLangCharset,
                  ValueName.c_str());
        LPVOID lpData;
        // 调用此函数查询前需要先依次调用函数GetFileVersionInfoSize和GetFileVersionInfo
        if (::VerQueryValueA((void*)m_lpVersionData, tmpstr, &lpData, &nQuerySize))
        { RetStr = (char*)lpData; }
        bSuccess = TRUE;
    } while (FALSE);
    // 销毁缓冲区
    if (m_lpVersionData)
    {
        delete[] m_lpVersionData;
        m_lpVersionData = NULL;
    }
    if (tmpstr)
    {
        delete[] tmpstr;
        tmpstr = NULL;
    }
    return bSuccess;
}

//获取文件说明
bool GetFileDescription(const std::string& szModuleName, std::string& RetStr)
{
    return QueryValue("FileDescription", szModuleName, RetStr);
}

//获取文件版本
bool GetFileVersion(const std::string& szModuleName, std::string& RetStr)
{
    return QueryValue("FileVersion", szModuleName, RetStr);
}
//获取内部名称
bool  GetInternalName(const std::string& szModuleName, std::string& RetStr)
{
    return QueryValue("InternalName", szModuleName, RetStr);
}

//获取公司名称
bool  GetCompanyName(const std::string& szModuleName, std::string& RetStr)
{
    return QueryValue("CompanyName", szModuleName, RetStr);
}

//获取版权
bool GetLegalCopyright(const std::string& szModuleName, std::string& RetStr)
{
    return QueryValue("LegalCopyright", szModuleName, RetStr);
}

//获取原始文件名
bool GetOriginalFilename(const std::string& szModuleName, std::string& RetStr)
{
    return QueryValue("OriginalFilename", szModuleName, RetStr);
}

//获取产品名称
bool GetProductName(const std::string& szModuleName, std::string& RetStr)
{
    return QueryValue("ProductName", szModuleName, RetStr);

}

//获取产品版本
bool GetProductVersion(const std::string& szModuleName, std::string& RetStr)
{
    return QueryValue("ProductVersion", szModuleName, RetStr);
}

// 获取所有加载的模块名及其基地址
void getAllLoadedModules(){
    QString paramInfo;
    DWORD processID = getProcessID();
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    HMODULE hmodules[0x100];
    DWORD spaceNeeded = 0;
    PROCESS_BASIC_INFORMATION* pbi64 = (PROCESS_BASIC_INFORMATION*)calloc(1, sizeof(PROCESS_BASIC_INFORMATION));
    unsigned long returnLen = 0;
    // 获取进程基本信息
    if(NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi64, sizeof(PROCESS_BASIC_INFORMATION), &returnLen) < 0)
        printf("Failed to query process information.\n");
    // 获取进程PEB
    PEB* pebInfo = (PEB*)calloc(1, sizeof(PEB));
    size_t PEBbytesRead = 0;
    if(ReadProcessMemory(hProcess, pbi64->PebBaseAddress, pebInfo, sizeof(PEB), &PEBbytesRead) < 0)
        printf("Failed to read PEB of current process.\n");
    // 获取ProcessParameters
    RTL_USER_PROCESS_PARAMETERS* procParams = (RTL_USER_PROCESS_PARAMETERS*)calloc(1, sizeof(RTL_USER_PROCESS_PARAMETERS));
    size_t procParamsBytesRead = 0;
    if(ReadProcessMemory(hProcess, pebInfo->ProcessParameters,
                         procParams, sizeof(RTL_USER_PROCESS_PARAMETERS), &procParamsBytesRead) >= 0){
        // 获取ProcessParameters.CommandLine.Buffer
        wchar_t* PPCB = (wchar_t*)calloc(2, procParams->CommandLine.Length + 2);
        size_t PPCBbytesRead = 0;
        if(ReadProcessMemory(hProcess, procParams->CommandLine.Buffer, PPCB, procParams->CommandLine.Length + 2, &PPCBbytesRead) < 0)
            printf("Failed to read ProcessParameters.CommandLine.Buffer.\n");
        else{
            paramInfo = QString::fromWCharArray(PPCB);
//            wprintf(L"%s", PPCB);
        }
    }else
        printf("Failed to read process parameters.\n");
    // 读取PEB中的LDR
    _PEB_LDR_DATA* LDRdata = (_PEB_LDR_DATA*)calloc(1, sizeof(_PEB_LDR_DATA));
    size_t ldrBytesRead = 0;
    if(ReadProcessMemory(hProcess, pebInfo->Ldr,
                         LDRdata, sizeof(_PEB_LDR_DATA), &ldrBytesRead) < 0)
        printf("Failed to read LDR.\n");
    // 循环读取LDR_ENTRY
    auto ldrNextEntry = LDRdata->InMemoryOrderModuleList.Flink;
    LDR_DATA_TABLE_ENTRY* LDRentry = (LDR_DATA_TABLE_ENTRY*)calloc(1, sizeof(LDR_DATA_TABLE_ENTRY));
    while(true){
        module newModule;
        size_t LDRentryBytesRead = 0;
        if(ReadProcessMemory(hProcess, ldrNextEntry,
                             LDRentry, sizeof(LDR_DATA_TABLE_ENTRY), &LDRentryBytesRead) < 0){
            printf("Failed to read LDR entry.\n");
            break;
        }
        if(ldrNextEntry == LDRdata->InMemoryOrderModuleList.Flink->Blink)
            break;
        // 读取dll文件名
        wchar_t* dllName = (wchar_t*)calloc(1, LDRentry->FullDllName.Length + 2);
        size_t dllNameBytesRead = 0;
        if(ReadProcessMemory(hProcess, LDRentry->FullDllName.Buffer,
                             dllName, LDRentry->FullDllName.Length + 2, &dllNameBytesRead) < 0){
            printf("Failed to read module name.\n");
            break;
        }
        newModule.moduleName = QString::fromWCharArray(dllName);
        if(newModule.moduleName.contains("designMain.exe"))
            return;
        // wprintf(L"%s\n", newModule.moduleName.toStdWString().c_str());
        // 读取基址
        uint64_t baseAddress = (uint64_t)LDRentry->Reserved2[0];    // 基地址
        uint64_t entryPoint = (uint64_t)LDRentry->Reserved2[1];     // 入口地址
        uint64_t moduleSize = (uint64_t)LDRentry->DllBase;          // 大小
        newModule.moduleBase = baseAddress;
        newModule.moduleSize = moduleSize;
        newModule.entryPoint = entryPoint;
//        printf("%zx\n", entryPoint);
        modules.push_back(newModule);
        ldrNextEntry = ldrNextEntry->Flink;
    }

//    char info[0x200];

//    printf("%llu", modules.size());

    EnumProcessModulesEx(hProcess, hmodules, sizeof(hmodules), &spaceNeeded, LIST_MODULES_ALL);
    // printf("%lu\n", GetLastError());
    // printf("%lu\n", spaceNeeded);
    for(int i=0; i<spaceNeeded / sizeof(HMODULE); i++){
        wchar_t moduleName[0x1000] = {0};
        GetModuleFileName(hmodules[i], moduleName, 0x1000);
        // wprintf(L"%s\n", moduleName);
        modules[i].fullPath = QString::fromWCharArray(moduleName);

    }

    std::ofstream processInfo("./hookLog/processList.txt", std::ios::trunc);
    for(int i=0; i<modules.size(); i++){
        char info[0x1000] = {0};
        QString fullName = modules[i].fullPath;
        auto layer = fullName.split("\\");
        QString fileName = layer.last();
        layer.removeLast();
        QString folderPath = layer.join("\\");
        sprintf_s(info, "%s 0x%016zx 0x%016zx 0x%016zx %s\n", fileName.toStdString().c_str(),
                  modules[i].moduleBase, modules[i].entryPoint, modules[i].moduleSize, folderPath.toStdString().c_str());
        // puts(info);
        processInfo.write(info, strlen(info));
    }
    processInfo.close();
}

QString getModeleNameThroughAddr(uint64_t address){
    for(int i=0; i<modules.size(); i++){
        if(address > modules[i].moduleBase && address < modules[i].moduleBase + modules[i].moduleSize)
            return modules[i].moduleName;
    }
    return "";
}

QString ShowTraceStack(char* szBriefInfo)
{
    static const int MAX_STACK_FRAMES = 50;
    void *pStack[MAX_STACK_FRAMES];
    static char szStackInfo[STACK_INFO_LEN * MAX_STACK_FRAMES];
    static char szFrameInfo[STACK_INFO_LEN];
    std::vector<QString> dllChain;

    HANDLE process = GetCurrentProcess();
    SymInitialize(process, NULL, TRUE);
    WORD frames = CaptureStackBackTrace(0, MAX_STACK_FRAMES, pStack, NULL);
    strcpy(szStackInfo, szBriefInfo == NULL ? "stack traceback:\n" : szBriefInfo);

    for (WORD i = 0; i < frames; ++i) {
        DWORD64 address = (DWORD64)(pStack[i]);

        DWORD64 displacementSym = 0;
        char buffer[sizeof(SYMBOL_INFO)+MAX_SYM_NAME * sizeof(TCHAR)];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        // DWORD displacementLine = 0;
        IMAGEHLP_LINE64 line;
        line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

        if (SymFromAddr(process, address, &displacementSym, pSymbol))// &&
            // SymGetLineFromAddr64(process, address, &displacementLine, &line))
        {
//            snprintf(szFrameInfo, sizeof(szFrameInfo), "\t%s() at %s:%lu(0x%llx)\n",
//                pSymbol->Name, line.FileName, line.LineNumber, pSymbol->Address);
            snprintf(szFrameInfo, sizeof(szFrameInfo), "\t%s() at 0x%llx\n",
                pSymbol->Name, pSymbol->Address);
            QString module = getModeleNameThroughAddr(pSymbol->Address);
            if(dllChain.empty() || module != dllChain.back())
                dllChain.push_back(module);
        }
        else
        {
            // snprintf(szFrameInfo, sizeof(szFrameInfo), "\terror: %lu\n", GetLastError());
        }
        // strcat(szStackInfo, szFrameInfo);
    }

    // printf("%s", szStackInfo); // 输出到控制台，也可以打印到日志文件中
    QString chainInfo = "module call chain: ";
    for(int i=0; i<dllChain.size() - 1; i++){
        chainInfo += dllChain[i];
        chainInfo += "->";
    }
    chainInfo += dllChain[dllChain.size() - 1];
    return chainInfo + "\n";
}
