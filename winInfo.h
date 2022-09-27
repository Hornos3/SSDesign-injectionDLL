#ifndef WININFO_H
#define WININFO_H

#include <windows.h>
#include <string>
#include <QString>
#include <fstream>
#include <dbghelp.h>

WCHAR* getCurrentProcessName();
DWORD getProcessID();

typedef struct module{
    QString moduleName;
    QString fullPath;
    uint64_t moduleBase;
    uint64_t moduleSize;
    uint64_t entryPoint;
}module;

bool GetFileDescription(const std::string& szModuleName, std::string& RetStr);
bool GetFileVersion(const std::string& szModuleName, std::string& RetStr);
bool GetInternalName(const std::string& szModuleName, std::string& RetStr);
bool GetCompanyName(const std::string& szModuleName, std::string& RetStr);
bool GetLegalCopyright(const std::string& szModuleName, std::string& RetStr);
bool GetOriginalFilename(const std::string& szModuleName, std::string& RetStr);
bool GetProductName(const std::string& szModuleName, std::string& RetStr);
bool GetProductVersion(const std::string& szModuleName, std::string& RetStr);
void getAllLoadedModules();
QString ShowTraceStack(char* szBriefInfo);
QString getModeleNameThroughAddr(uint64_t address);

#endif // WININFO_H
