//utility functions, mostly string handling
//if you are looking for PAM module example code, then look in pam_module.c


#ifndef PAMIHOSTS_UTIL_H
#define PAMIHOSTS_UTIL_H

#include "common.h"

#define StrLen(str) ( str ? strlen(str) : 0 )


//Get items from the MatchList, and use them as fnmatch patterns, returning  TRUE
//if we find one that maches
int ItemMatches(const char *Item, const char *MatchList);
int ItemListMatches(const char *ItemList, const char *MatchList);

//either opens a file or, if the system supports it and the file has
//an mmap: prefix, opens a shared mem-map
FILE *OpenFileOrMMap(const char *Path);

void strlwr(char *Str);
char *VCatStr(char *Dest, const char *Str1,  va_list args);
char *MCatStr(char *Dest, const char *Str1,  ...);
char *MCopyStr(char *Dest, const char *Str1,  ...);
char *CatStr(char *Dest, const char *Src);
char *CopyStr(char *Dest, const char *Src);
void StripTrailingWhitespace(char *str);
void StripLeadingWhitespace(char *str);
void StripQuotes(char *Str);
const char *GetTok(const char *In, const char *Delim, char **Token);
unsigned long StrtoIP(const char *Str);
int IsIPAddress(const char *Str);
int IsIP4Address(const char *Str);
char *LookupHostIP(const char *Host);
char *LookupIPHost(const char *IP);
int CheckIPLists(const char *Path, const char *Rhost, const char *IP, const char *MAC, const char *Region, char **MatchingList);
int CheckDNSList(const char *Domain, const char *IP, char **MatchingList);
void Destroy(void *Item);

#endif
