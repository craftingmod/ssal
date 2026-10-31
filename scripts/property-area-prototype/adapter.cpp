#include <windows.h>
#include <new>
#include "system_properties/prop_area.h"
size_t prop_area::pa_size_=128*1024;
size_t prop_area::pa_data_size_=128*1024-sizeof(prop_area);
prop_area* prop_area::map_prop_area_rw(const char* path,const char*,bool*) {
 HANDLE f=CreateFileA(path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(f==INVALID_HANDLE_VALUE) return nullptr;
 HANDLE m=CreateFileMappingA(f,nullptr,PAGE_READWRITE,0,(DWORD)pa_size_,nullptr);
 void* p=m?MapViewOfFile(m,FILE_MAP_ALL_ACCESS,0,0,0):nullptr;
 if(m) CloseHandle(m); CloseHandle(f);
 return p?new(p) prop_area(0x504f5250,0xfc6ed0ab):nullptr;
}
prop_area* prop_area::map_prop_area(const char* path) {
 HANDLE f=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(f==INVALID_HANDLE_VALUE) return nullptr;
 LARGE_INTEGER size; if(!GetFileSizeEx(f,&size) || size.QuadPart!=pa_size_) { CloseHandle(f); return nullptr; }
 HANDLE m=CreateFileMappingA(f,nullptr,PAGE_READONLY,0,0,nullptr);
 void* p=m?MapViewOfFile(m,FILE_MAP_READ,0,0,0):nullptr;
 if(m) CloseHandle(m); CloseHandle(f);
 auto a=static_cast<prop_area*>(p);
 if(a && (a->magic()!=0x504f5250 || a->version()!=0xfc6ed0ab)) { UnmapViewOfFile(a); return nullptr; }
 return a;
}
