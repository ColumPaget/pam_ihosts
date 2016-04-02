//utility functions, mostly string handling
//if you are looking for PAM module example code, then look in pam_module.c

#include "utility.h"
#include <fnmatch.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>


void strlwr(char *Str)
{
char *ptr;

if (Str)
{
for (ptr=Str; *ptr != '\0'; ptr++) *ptr=tolower(*ptr);
}
}

//Get items from the MatchList, and use them as fnmatch patterns, returning  TRUE
//if we find one that matches. However, if the match pattern starts with '!', then
//return TRUE if the match fails
int ItemMatches(const char *Item, const char *MatchList)
{
const char *ptr, *mptr;
char *Match=NULL;
int result=FALSE;

if (StrLen(Item) ==0) return(FALSE);
ptr=GetTok(MatchList, ",", &Match);
while (ptr)
{
  mptr=Match;
  if (*mptr=='!') mptr++;
  if (fnmatch(mptr, Item, 0)==0)
  {
  	if (*Match!='!')
		{
    result=TRUE;
    break;
		}
  }
  else if (*Match=='!')
  {
    result=TRUE;
    break;
  }
  ptr=GetTok(ptr, ",", &Match);
}

Destroy(Match);

return(result);
}



//call 'ItemMatches' for each item in the list 'ItemList'
int ItemListMatches(const char *ItemList, const char *MatchList)
{
char *Item=NULL;
const char *ptr;
int result=FALSE;

ptr=GetTok(ItemList, " ", &Item);
while (ptr)
{
  if (ItemMatches(Item, MatchList))
  {
    result=TRUE;
    break;
  }
  ptr=GetTok(ptr, " ", &Item);
}

Destroy(Item);

return(result);
}



#ifndef va_copy
#define va_copy(dest, src) (dest) = (src) 
#endif

char *VCatStr(char *Dest, const char *Str1,  va_list args)
{
//initialize these to keep valgrind happy
size_t len=0;
char *ptr=NULL;
const char *sptr=NULL;


if (Dest !=NULL)
{
len=StrLen(Dest);
ptr=Dest;
}
else
{
 len=10;
 ptr=(char *) calloc(10,1);
}

if (! Str1) return(ptr);
for (sptr=Str1; sptr !=NULL; sptr=va_arg(args,const char *))
{
len+=StrLen(sptr)+1;
len=len*2;


ptr=(char *) realloc(ptr,len);
if (ptr && sptr) strcat(ptr,sptr);
}

return(ptr);
}


char *MCatStr(char *Dest, const char *Str1,  ...)
{
char *ptr=NULL;
va_list args;

va_start(args,Str1);
ptr=VCatStr(Dest,Str1,args);
va_end(args);

return(ptr);
}


char *MCopyStr(char *Dest, const char *Str1,  ...)
{
char *ptr=NULL;
va_list args;

ptr=Dest;
if (ptr) *ptr='\0';
va_start(args,Str1);
ptr=VCatStr(ptr,Str1,args);
va_end(args);

return(ptr);
}

char *CatStr(char *Dest, const char *Src)
{
return(MCatStr(Dest,Src,NULL));
}


char *CopyStr(char *Dest, const char *Src)
{
return(MCopyStr(Dest,Src,NULL));
}

void StripTrailingWhitespace(char *str)
{
size_t len;
char *ptr;

len=StrLen(str);
if (len==0) return;
for(ptr=str+len-1; (ptr >= str) && isspace(*ptr); ptr--) *ptr='\0';
}


void StripLeadingWhitespace(char *str)
{
char *ptr, *start=NULL;

if (! str) return;
for(ptr=str; *ptr !='\0'; ptr++)
{
  if ((! start) && (! isspace(*ptr))) start=ptr;
}

if (!start) start=ptr;
 memmove(str,start,ptr+1-start);
}



void StripQuotes(char *Str)
{
int len;
char *ptr, StartQuote='\0';

ptr=Str;
while (isspace(*ptr)) ptr++;

if ((*ptr=='"') || (*ptr=='\''))
{
  StartQuote=*ptr;
  len=StrLen(ptr);
  if ((len > 0) && (StartQuote != '\0') && (ptr[len-1]==StartQuote))
  {
    if (ptr[len-1]==StartQuote) ptr[len-1]='\0';
    memmove(Str,ptr+1,len);
  }
}

}



//I don't trust strtok, it's not reentrant, and this handles quotes
const char *GetTok(const char *In, const char *Delims, char **Token)
{
char quot='\0';
const char *ptr;
int i=0;

*Token=realloc(*Token,258);
//When input is exhausted return null
if ((! In) || (*In=='\0')) return(NULL);

for (ptr=In; *ptr != '\0'; ptr++)
{
	if (*ptr=='\0') break;

	if (quot != '\0') 
	{
		if (*ptr==quot) quot='\0';
	}
	else if ((*ptr=='"') || (*ptr=='\'')) quot=*ptr;
	else if (strchr(Delims, *ptr)) break;
	else 
	{
		if (*ptr=='\\') ptr++;
		(*Token)[i]=*ptr;
		i++;
	}
	if (i > 256) break;
}

(*Token)[i]='\0';
StripQuotes(*Token);

//if it's not '\0', then it must be a delim, so go past it
if (*ptr !='\0') ptr++;

//Don't return null if ptr=='\0' here, because there's probably
//still something in Token
return(ptr);
}


unsigned long StrtoIP(const char *Str)
{
struct sockaddr_in sa;
if (inet_aton(Str,&sa.sin_addr)) return(sa.sin_addr.s_addr);
return(0);
}



//this handles both IP4 and IP6 addresses. It counts dots or colons and 
//checks for hex chars
int IsIPAddress(const char *Str)
{
const char *ptr;
int dot_count=0, colon_count=0;
int AllowDot=FALSE, IP6=FALSE;

if (! Str) return(FALSE);

for (ptr=Str; *ptr != '\0'; ptr++)
{
	switch (*ptr)
	{
  case '.':
    if (! AllowDot) return(FALSE);
    if (IP6) return(FALSE);
    dot_count++;
    AllowDot=FALSE;
	break;
	
	case ':':
    colon_count++;
    IP6=TRUE;
	break;

	case 'a':
	case 'b':
	case 'c':
	case 'd':
	case 'e':
	case 'f':
	case 'A':
	case 'B':
	case 'C':
	case 'D':
	case 'E':
	case 'F':
	if (dot_count > 0) return(FALSE);
	break;

	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	break;

	default:
    return(FALSE);
	break;
	}
}

if ((dot_count > 0) && (colon_count > 0)) return(FALSE);

if (dot_count == 3) return(TRUE);
if (colon_count > 1) return(TRUE);

return(FALSE);
}



char *LookupHostIP(const char *Host)
{
struct hostent *hostdata;

   hostdata=gethostbyname(Host);
   if (!hostdata)
   {
     return(NULL);
   }

//inet_ntoa shouldn't need this cast to 'char *', but it emitts a warning
//without it
return((char *) inet_ntoa(*(struct in_addr *) *hostdata->h_addr_list));
}




//either opens a file or, if the system supports it and the file has
//an mmap: prefix, opens a shared mem-map
FILE *OpenFileOrMMap(const char *Path)
{
char *ptr, *map=NULL;
int fd;
struct stat Stat;
FILE *f=NULL;

if (! StrLen(Path)) return(NULL);

ptr=Path;
if (strncmp(ptr,"mmap:",5)==0)
{
  ptr+=5;
  fd=open(ptr, O_RDONLY);
  if (fd > -1)
  {
  fstat(fd,&Stat);
  map=mmap(NULL,Stat.st_size,PROT_READ,MAP_SHARED,fd,0);
  if (map) f=fmemopen(map, Stat.st_size, "r");
  close(fd);
  }
}

if (! f) f=fopen(ptr, "r");

return(f);
}




int CheckIPFile(const char *Path, const char *Rhost, const char *IP, const char *MAC, const char *Region)
{
FILE *f;
char *Line=NULL;
int result=FALSE;

Line=(char *) calloc(1,256);
f=OpenFileOrMMap(Path);
if (f)
{
	while (fgets(Line,255,f))
	{
		StripTrailingWhitespace(Line);
		if (strcasecmp(Line,IP)==0)
		{
		result=TRUE;
		break;
		}	
		
		if (strcasecmp(Line,MAC)==0)
		{
		result=TRUE;
		break;
		}
			
		if (strcasecmp(Line,Rhost)==0)
		{
		result=TRUE;
		break;
		}
	}
fclose(f);
}

Destroy(Line);

return(result);
}



int CheckIPLists(const char *FileList, const char *Rhost, const char *IP, const char *MAC, const char *Region, char **MatchingLists)
{
char *Path=NULL, *ptr;
int result=FALSE;

ptr=GetTok(FileList,",",&Path);
while (ptr)
{
StripLeadingWhitespace(Path);
StripTrailingWhitespace(Path);
result=CheckIPFile(Path,Rhost,IP,MAC,Region);
if (result) 
{
	*MatchingLists=MCatStr(*MatchingLists, Path, " ", NULL);
	break;
}
ptr=GetTok(ptr,",",&Path);
}

Destroy(Path);
return(result);
}


int CheckDNSList(const char *Domains, const char *IP, char **MatchingLists)
{
char *Tempstr=NULL, *Reversed=NULL, *Token=NULL, *ptr;
struct hostent *hinfo;
char *Quads[4];
int i=0, len, result=FALSE;

ptr=GetTok(IP,".",&Token);
while (ptr && (i < 4))
{
  Quads[i]=CopyStr(NULL, Token);
  i++;
  ptr=GetTok(ptr,".",&Token);
}


if (i == 4)
{
	for (i=3; i > -1; i--)
	{
	Reversed=MCatStr(Reversed,Quads[i],".",NULL);
	}
	
	ptr=GetTok(Domains,",",&Token);
	while (ptr)
	{
		Tempstr=MCopyStr(Tempstr,Reversed,Token,NULL);
		hinfo=gethostbyname(Tempstr);
		if (hinfo)
		{
			result=TRUE;
			//syslog(LOG_INFO, "pam_ihosts: host [%s] in dns blacklist [%s] response=[%s]",IP,Domain,IPtoStr(* (uint32_t *) hinfo->h_addr_list[0]));
			syslog(LOG_INFO, "pam_ihosts: host [%s] in dns list [%s]",IP,Token);
			*MatchingLists=MCatStr(*MatchingLists, Token, " ", NULL);
		}
	ptr=GetTok(ptr,",",&Token);
	}
}

Destroy(Reversed);
Destroy(Tempstr);
Destroy(Token);

return(result);
}


void Destroy(void *Item)
{
if (Item) free(Item);
}
