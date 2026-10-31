#include <windows.h>
#include <cassert>
#include <cstring>
#include <iostream>
#include "system_properties/prop_area.h"

static const char* value(prop_area* a,const char* n) { auto p=a->find(n); return p ? p->value : nullptr; }
int main(int argc,char** argv) {
 if(argc!=2) return 2;
 std::string base=argv[1], a=base+"\\guest-area", b=base+"\\host-sentinel";
 auto guest=prop_area::map_prop_area_rw(a.c_str(),nullptr,nullptr);
 auto host=prop_area::map_prop_area_rw(b.c_str(),nullptr,nullptr);
 if(!guest || !host) return 3;
 assert(!prop_area::map_prop_area_rw(a.c_str(),nullptr,nullptr));
 assert(guest->add("demo.name",9,"guest",5));
 assert(host->add("demo.name",9,"host",4));
 assert(guest->add("demo.only",9,"private",7));
 assert(!host->find("demo.only"));
 assert(!strcmp(value(guest,"demo.name"),"guest"));
 assert(!strcmp(value(host,"demo.name"),"host"));
 assert(!guest->find("missing"));
 prop_area::unmap_prop_area(&guest); prop_area::unmap_prop_area(&host);
 guest=prop_area::map_prop_area(a.c_str()); host=prop_area::map_prop_area(b.c_str());
 assert(guest && host && !strcmp(value(guest,"demo.name"),"guest"));
 assert(!strcmp(value(host,"demo.name"),"host") && !host->find("demo.only"));
 prop_area::unmap_prop_area(&guest); prop_area::unmap_prop_area(&host);
 std::cout << "PASS: AOSP add/find and serialized files survive remapping; sentinel remains independent\n";
}
