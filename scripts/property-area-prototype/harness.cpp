#include <windows.h>
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
#include "property_info_serializer/property_info_serializer.h"
#include "property_info_parser/property_info_parser.h"
#include "system_properties/prop_area.h"

static const char* value(prop_area* a,const char* n) { auto p=a->find(n); return p ? p->value : nullptr; }
static prop_area* select_area(const android::properties::PropertyInfoArea* info,
                              const char* name, prop_area* guest, prop_area* private_area) {
 const char *context=nullptr, *type=nullptr;
 info->GetPropertyInfo(name, &context, &type);
 if (!context) return nullptr;
 if (!strcmp(context,"u:object_r:ssal_demo_prop:s0")) return guest;
 if (!strcmp(context,"u:object_r:ssal_private_prop:s0")) return private_area;
 return nullptr;
}
int main(int argc,char** argv) {
 if(argc!=2) return 2;
 std::string base=argv[1], a=base+"\\guest-area", b=base+"\\host-sentinel", c=base+"\\private-area";
 auto guest=prop_area::map_prop_area_rw(a.c_str(),nullptr,nullptr);
 auto host=prop_area::map_prop_area_rw(b.c_str(),nullptr,nullptr);
 auto private_area=prop_area::map_prop_area_rw(c.c_str(),nullptr,nullptr);
 if(!guest || !host || !private_area) return 3;
 assert(!prop_area::map_prop_area_rw(a.c_str(),nullptr,nullptr));
 assert(host->add("demo.name",9,"host",4));
 assert(!host->find("demo.only"));
 assert(!strcmp(value(host,"demo.name"),"host"));
 assert(!guest->find("missing"));
 using namespace android::properties;
 std::vector<PropertyInfoEntry> entries;
 entries.emplace_back("demo.", "u:object_r:ssal_demo_prop:s0", "string", false);
 entries.emplace_back("demo.only", "u:object_r:ssal_private_prop:s0", "string", true);
 std::string blob, error;
 assert(BuildTrie(entries, "u:object_r:default_prop:s0", "string", &blob, &error));
 const auto* info=reinterpret_cast<const PropertyInfoArea*>(blob.data());
 assert(select_area(info,"demo.name",guest,private_area)->add("demo.name",9,"guest",5));
 assert(select_area(info,"demo.only",guest,private_area)->add("demo.only",9,"private",7));
 const char *context=nullptr, *type=nullptr;
 info->GetPropertyInfo("demo.name", &context, &type);
 assert(context && !strcmp(context,"u:object_r:ssal_demo_prop:s0"));
 assert(!strcmp(value(guest,"demo.name"),"guest"));
 info->GetPropertyInfo("demo.only", &context, &type);
 assert(context && !strcmp(context,"u:object_r:ssal_private_prop:s0"));
 assert(!strcmp(value(private_area,"demo.only"),"private"));
 assert(select_area(info,"demo.name",guest,private_area)==guest);
 assert(select_area(info,"demo.only",guest,private_area)==private_area);
 assert(!select_area(info,"unknown",guest,private_area));
 assert(!guest->find("demo.only") && !private_area->find("demo.name"));
 prop_area::unmap_prop_area(&guest); prop_area::unmap_prop_area(&host); prop_area::unmap_prop_area(&private_area);
 guest=prop_area::map_prop_area(a.c_str()); host=prop_area::map_prop_area(b.c_str());
 private_area=prop_area::map_prop_area(c.c_str());
 assert(guest && host && private_area && !strcmp(value(guest,"demo.name"),"guest"));
 assert(!strcmp(value(private_area,"demo.only"),"private") && !guest->find("demo.only"));
 assert(!strcmp(value(select_area(info,"demo.only",guest,private_area),"demo.only"),"private"));
 assert(!strcmp(value(host,"demo.name"),"host") && !host->find("demo.only"));
 prop_area::unmap_prop_area(&guest); prop_area::unmap_prop_area(&host); prop_area::unmap_prop_area(&private_area);
 std::cout << "PASS: AOSP add/find and serialized files survive remapping; sentinel remains independent\n";
}
