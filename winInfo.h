#ifndef WININFO_H
#define WININFO_H

#include <windows.h>
#include <string>

WCHAR* getCurrentProcessName();
DWORD getProcessID();

bool GetFileDescription(const std::string& szModuleName, std::string& RetStr);
bool GetFileVersion(const std::string& szModuleName, std::string& RetStr);
bool GetInternalName(const std::string& szModuleName, std::string& RetStr);
bool GetCompanyName(const std::string& szModuleName, std::string& RetStr);
bool GetLegalCopyright(const std::string& szModuleName, std::string& RetStr);
bool GetOriginalFilename(const std::string& szModuleName, std::string& RetStr);
bool GetProductName(const std::string& szModuleName, std::string& RetStr);
bool GetProductVersion(const std::string& szModuleName, std::string& RetStr);

#endif // WININFO_H
