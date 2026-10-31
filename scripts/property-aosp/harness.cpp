#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include "property_info_serializer/property_info_serializer.h"
#include "property_info_parser/property_info_parser.h"
using namespace android::properties;
int main(int argc,char** argv){
 if(argc<3){std::cerr<<"usage: harness queries-file contexts...\n";return 2;}
 std::vector<PropertyInfoEntry> entries; std::vector<std::string> errors;
 for(int i=2;i<argc;i++){std::ifstream in(argv[i],std::ios::binary);if(!in){std::cerr<<"missing "<<argv[i]<<"\n";return 2;}std::string data((std::istreambuf_iterator<char>(in)),{});ParsePropertyInfoFile(data,true,&entries,&errors);for(auto& e:errors)std::cout<<"ERROR\t"<<i-2<<"\t"<<e<<"\n";}
 for(auto& e:entries) std::cout<<"ENTRY\t"<<e.name<<"\t"<<e.context<<"\t"<<(e.exact_match?"exact":"prefix")<<"\t"<<e.type<<"\n";
 std::string blob,error;if(!BuildTrie(entries,"u:object_r:default_prop:s0","string",&blob,&error)){std::cout<<"BUILD_ERROR\t"<<error<<"\n";return 0;}
 std::cout<<"BUILD_OK\t"<<blob.size()<<"\n";
 auto area=reinterpret_cast<const PropertyInfoArea*>(blob.data());
 for(uint32_t i=0;i<area->num_contexts();i++)std::cout<<"CONTEXT\t"<<area->context(i)<<"\n";
 std::ifstream q(argv[1]);std::string name;while(std::getline(q,name)){if(!name.empty()&&name.back()=='\r')name.pop_back();const char *c=nullptr,*t=nullptr;area->GetPropertyInfo(name.c_str(),&c,&t);std::cout<<"LOOKUP\t"<<name<<"\t"<<(c?c:"")<<"\t"<<(t?t:"")<<"\n";}
}
