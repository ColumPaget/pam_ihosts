//utility functions, mostly string handling
//if you are looking for PAM module example code, then look in pam_module.c

#include "utility.h"
#include <fnmatch.h>
#include <arpa/inet.h>


//Get items from the MatchList, and use them as fnmatch patterns, returning  TRUE
//if we find one that matches. However, if the match pattern starts with '!', then
//return TRUE if the match fails
int ItemMatches(const char *Item, const char *MatchList)
{
const char *ptr, *mptr;
char *Match=NULL;
int result=FALSE;

if (StrLen(Item) ==0) return(FALSE);
ptr=GetTok(MatchList, ',', &Match);
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
  ptr=GetTok(ptr, ',', &Match);
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

ptr=GetTok(ItemList, ' ', &Item);
while (ptr)
{
  if (ItemMatches(Item, MatchList))
  {
    result=TRUE;
    break;
  }
  ptr=GetTok(ptr, ' ', &Item);
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
const char *GetTok(const char *In, char Delim, char **Token)
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
	else if (*ptr==Delim) break;
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


void Destroy(void *Item)
{
if (Item) free(Item);
}
