#pragma once
#include <string>
#include <vector>
#include <cctype>
namespace android::base {
inline std::vector<std::string> Split(const std::string& s,const std::string& d) { std::vector<std::string> v; size_t p=0,n; while((n=s.find(d,p))!=std::string::npos){v.push_back(s.substr(p,n-p));p=n+d.size();}v.push_back(s.substr(p));return v; }
inline std::string Trim(const std::string& s){size_t a=0,b=s.size();while(a<b&&std::isspace((unsigned char)s[a]))a++;while(b>a&&std::isspace((unsigned char)s[b-1]))b--;return s.substr(a,b-a);}
inline bool StartsWith(const std::string& s,const std::string& p){return s.rfind(p,0)==0;}
inline std::string Join(const std::vector<std::string>& v,const std::string& d){std::string s;for(size_t i=0;i<v.size();i++){if(i)s+=d;s+=v[i];}return s;}
}
