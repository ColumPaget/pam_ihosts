#include "common.h"
#include "utility.h"
#include <syslog.h>
#include <inttypes.h>

//Define which PAM interfaces we provide. In this case we are
//only going to provide an account interface, i.e. one 
//that decides if a login in allowed or not, *after* authentication
//Many programs will interpret a 'DENY' result here to mean that the 
//account has expired, so expect to see that in your logs
#define PAM_SM_ACCOUNT

// We do not supply these
/*
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION
*/

// Include PAM headers 
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define FLAG_SYSLOG  1
#define FLAG_ALLOW 4
#define FLAG_DENYALL 8
#define FLAG_LOGPASS 16
#define FLAG_FAILS 32

typedef struct
{
int Flags;
char *User;
char *AllowedMACs;
char *AllowedIPs;
char *AllowedRegions;
char *AllowedDevices;
char *BlackLists;
char *WhiteLists;
char *RegionFiles;
char *Script;
} TSettings;



void TSettingsDestroy(TSettings *Settings)
{
if (! Settings) return;

Destroy(Settings->User);
Destroy(Settings->AllowedMACs);
Destroy(Settings->AllowedIPs);
Destroy(Settings->AllowedRegions);
Destroy(Settings->AllowedDevices);
Destroy(Settings->BlackLists);
Destroy(Settings->WhiteLists);
Destroy(Settings->RegionFiles);
Destroy(Settings->Script);
free(Settings);
} 






/*
afrinic|ZA|ipv4|41.0.0.0|2097152|20071126|allocated
afrinic|EG|ipv4|41.32.0.0|1048576|20091105|allocated
afrinic|ZA|ipv4|41.48.0.0|524288|20091211|allocated
afrinic|ZA|ipv4|41.56.0.0|65536|20100125|allocated
afrinic|ZA|ipv4|41.57.0.0|16384|20110121|allocated
afrinic|ZW|ipv4|41.57.64.0|4096|20111215|allocated
afrinic|LR|ipv4|41.57.80.0|4096|20120118|allocated
afrinic|KE|ipv4|41.57.96.0|4096|20120309|allocated
*/



int IP6Compare(const char *IP, const char *Subnet, int NetMask)
{
const char *iptr, *sptr;
char *iOctet=NULL, *sOctet=NULL;
int val;

iptr=GetTok(IP,":.",&iOctet);
sptr=GetTok(Subnet,":.",&sOctet);
while (iptr && sptr && (NetMask > 0))
{
	if (NetMask > 7)
	{
		if (strtol(iOctet,NULL,16) != strtol(sOctet,NULL,16)) return(FALSE);
	}
	else
	{
		switch (NetMask)
		{
			case 1: val=1; break;
			case 2: val=3; break;
			case 3: val=7; break;
			case 4: val=15; break;
			case 5: val=31; break;
			case 6: val=63; break;
			case 7: val=127; break;
		}
		
		if ((strtol(iOctet,NULL,16) & val) != (strtol(sOctet,NULL,16) & val)) return(FALSE);
	}
	NetMask-=16;
	iptr=GetTok(iptr,":.",&iOctet);
	sptr=GetTok(sptr,":.",&sOctet);
}

Destroy(iOctet);
Destroy(sOctet);
return(TRUE);
}


char *RegionFileLookup(char *RetStr, const char *pam_service, const char *Path, const char *IPStr)
{
FILE *F;
char *Tempstr=NULL, *Registrar=NULL, *Country=NULL, *Type=NULL, *Subnet=NULL, *Token=NULL;
const char *ptr;
int result=FALSE;
uint32_t IP, Mask, val;

IP=StrtoIP(IPStr);
Tempstr=realloc(Tempstr, 256);
F=fopen(Path, "r");
if (F)
{
	while (fgets(Tempstr,255,F))
	{
		ptr=GetTok(Tempstr,"|",&Registrar);
		ptr=GetTok(ptr,"|",&Country);
		ptr=GetTok(ptr,"|",&Type);
		ptr=GetTok(ptr,"|",&Subnet);

		if (*Subnet != '*')
		{
		if (strcmp(Type,"ipv4")==0)
		{
			ptr=GetTok(ptr,"|",&Token);
			val=atoi(Token);
			//'val' is number of assigned IPs. Netmask is this -1
			Mask=htonl(~(val-1));

			if ((IP & Mask) == StrtoIP(Subnet))
			{
				RetStr=MCopyStr(RetStr,Registrar,":",Country,NULL);
				break;
			}
		}
		else if (strcmp(Type,"ipv6")==0) 
		{
			ptr=GetTok(ptr,"|",&Token);
			if (IP6Compare(IPStr, Subnet, atoi(Token)))
			{
				RetStr=MCopyStr(RetStr,Registrar,":",Country,NULL);
				break;
			}
		}
		}
	}
	fclose(F);
}
else
{
	openlog(pam_service,0,LOG_AUTH);
	syslog(LOG_ERR, "pam_ihosts ERROR: Failed to open region file %s", Path);
	closelog();
}


Destroy(Registrar);
Destroy(Tempstr);
Destroy(Country);
Destroy(Subnet);
Destroy(Token);
Destroy(Type);

return(RetStr);
}


char *RegionLookup(char *RetStr, const char *pam_service, const char *IP, const char *RegionFileList)
{
char *Path=NULL;
const char *ptr;

if (strncmp(IP,"127.",4)==0) return(CopyStr(RetStr,"local"));
if (strncmp(IP,"192.168.",8)==0) return(CopyStr(RetStr,"local"));
if (strncmp(IP,"10.",3)==0) return(CopyStr(RetStr,"local"));
if (fnmatch(IP,"172.1[6-9].*")==0) return(CopyStr(RetStr,"local"));
if (fnmatch(IP,"172.2?.*")==0) return(CopyStr(RetStr,"local"));
if (strncmp(IP,"172.30.",7)==0) return(CopyStr(RetStr,"local"));
if (strncmp(IP,"172.31.",7)==0) return(CopyStr(RetStr,"local"));


ptr=GetTok(RegionFileList,",",&Path);
while (ptr)
{
	RetStr=RegionFileLookup(RetStr, pam_service, Path, IP);
	if (StrLen(RetStr)) break;

ptr=GetTok(ptr,",",&Path);
}

Destroy(Path);

return(RetStr);
}



void ParseSettingLine(TSettings *Settings, const char *Line)
{
const char *ptr;

		if (! StrLen(Line)) return;
		ptr=Line;


		if (strcmp(ptr,"syslog")==0) Settings->Flags |= FLAG_SYSLOG;
		else if (strncmp(ptr,"user=",5)==0) Settings->User=CopyStr(Settings->User, ptr+5);
		else if (strncmp(ptr,"allow-dev=",10)==0) Settings->AllowedDevices=MCatStr(Settings->AllowedDevices, ptr+10,",",NULL);
		else if (strncmp(ptr,"allow-device=",13)==0) Settings->AllowedDevices=MCatStr(Settings->AllowedDevices, ptr+13,",",NULL);
		else if (strncmp(ptr,"allow-mac=",10)==0) Settings->AllowedMACs=MCatStr(Settings->AllowedMACs, ptr+10,",",NULL);
		else if (strncmp(ptr,"allow-ip=",9)==0) Settings->AllowedIPs=MCatStr(Settings->AllowedIPs, ptr+9,",",NULL);
		else if (strncmp(ptr,"allow-region=",13)==0) Settings->AllowedRegions=MCatStr(Settings->AllowedRegions, ptr+13,",",NULL);
		else if (strncmp(ptr,"allow-devs=",10)==0) Settings->AllowedDevices=MCatStr(Settings->AllowedDevices, ptr+11,",",NULL);
		else if (strncmp(ptr,"allow-devices=",13)==0) Settings->AllowedDevices=MCatStr(Settings->AllowedDevices, ptr+14,",",NULL);
		else if (strncmp(ptr,"allow-macs=",11)==0) Settings->AllowedMACs=MCatStr(Settings->AllowedMACs, ptr+11,",",NULL);
		else if (strncmp(ptr,"allow-ips=",10)==0) Settings->AllowedIPs=MCatStr(Settings->AllowedIPs, ptr+10,",",NULL);
		else if (strncmp(ptr,"allow-regions=",14)==0) Settings->AllowedRegions=MCatStr(Settings->AllowedRegions, ptr+14,",",NULL);
		else if (strncmp(ptr,"region-files=",13)==0) Settings->RegionFiles=MCatStr(Settings->RegionFiles, ptr+13,",",NULL);
		else if (strncmp(ptr,"blacklist=",10)==0) Settings->BlackLists=MCatStr(Settings->BlackLists, ptr+10,",",NULL);
		else if (strncmp(ptr,"whitelist=",10)==0) Settings->WhiteLists=MCatStr(Settings->WhiteLists, ptr+10,",",NULL);
		else if (strncmp(ptr,"script=",7)==0) Settings->Script=MCopyStr(Settings->Script, ptr+7, NULL);
}


void LoadConfigFile(TSettings *Settings, const char *pam_service, const char *Path)
{
char *Tempstr=NULL;
FILE *F;

Tempstr=realloc(Tempstr, 1025);
F=fopen(Path,"r");
if (F)
{
	while (fgets(Tempstr,1024,F))
	{
		StripTrailingWhitespace(Tempstr);
		ParseSettingLine(Settings, Tempstr);
	}
	fclose(F);
}
else
{
	openlog(pam_service,0,LOG_AUTH);
	syslog(LOG_ERR, "pam_ihosts ERROR: Failed to open config file %s",Path);
	closelog();
}

Destroy(Tempstr);
}


TSettings *ParseSettings(int argc, const char *argv[], const char *pam_service)
{
TSettings *Settings;
const char *ptr;
int i;

	Settings=(TSettings *) calloc(1,sizeof(TSettings));
	for (i=0; i < argc; i++)
	{
		ptr=argv[i];
		if (strncmp(ptr,"conf-file=",10)==0) LoadConfigFile(Settings,pam_service, ptr+10);
		else ParseSettingLine(Settings, argv[i]);
	}

	strlwr(Settings->AllowedMACs);
return(Settings);
}


int GetHostARP(const char *pam_service, const char *IP, char **Device, char **MAC)
{
char *Tempstr=NULL, *Token=NULL;
int result=FALSE;
const char *ptr;
FILE *F;

Tempstr=realloc(Tempstr, 256);
F=fopen("/proc/net/arp","r");
if (F)
{
	*Device=CopyStr(*Device,"remote");
	*MAC=CopyStr(*MAC,"remote");
	//Read Title Line
	fgets(Tempstr,255,F);

	while (fgets(Tempstr,255,F))
	{
		StripTrailingWhitespace(Tempstr);
		ptr=GetTok(Tempstr," ",&Token);
		if (strcmp(Token,IP)==0)
		{
			while (isspace(*ptr)) ptr++;
			ptr=GetTok(ptr," ",&Token);

			while (isspace(*ptr)) ptr++;
			ptr=GetTok(ptr," ",&Token);

			while (isspace(*ptr)) ptr++;
			ptr=GetTok(ptr," ",MAC);
			strlwr(*MAC);

			while (isspace(*ptr)) ptr++;
			ptr=GetTok(ptr," ",&Token);

			while (isspace(*ptr)) ptr++;
			ptr=GetTok(ptr," ",Device);

			result=TRUE;
		}
	}
fclose(F);
}
else
{
	openlog(pam_service,0,LOG_AUTH);
	syslog(LOG_ERR, "pam_ihosts ERROR: Failed to open /proc/net/arp. Mac and Device checking disabled.");
	closelog();
}

Destroy(Tempstr);
Destroy(Token);

return(result);
}


int CheckHostPermissions(TSettings *Settings, const char *pam_service, const char *pam_user, const char *pam_rhost, const char *IP, const char *Device, const char *MAC, const char *Region, char **Lists)
{
int PamResult=PAM_PERM_DENIED;

	//Wrong user, so return
	if (StrLen(Settings->User) && (! ItemMatches(pam_user, Settings->User))) return(PAM_IGNORE);

	//Any of these can be overridden by 'deny' rules or blocklists
	if (StrLen(Settings->AllowedIPs) && ItemMatches(IP, Settings->AllowedIPs)) PamResult=PAM_IGNORE;
	else if (StrLen(Settings->AllowedMACs) && ItemMatches(MAC, Settings->AllowedMACs)) PamResult=PAM_IGNORE;
	else if (StrLen(Region) && StrLen(Settings->AllowedRegions) && ItemMatches(Region, Settings->AllowedRegions)) PamResult=PAM_IGNORE;

	if (StrLen(Settings->WhiteLists) && CheckIPLists(Settings->WhiteLists, pam_rhost, IP, MAC, Region, Lists)) PamResult=PAM_IGNORE;
	if (StrLen(Settings->BlackLists) && CheckIPLists(Settings->BlackLists, pam_rhost, IP, MAC, Region, Lists)) PamResult=PAM_PERM_DENIED;

	return(PamResult);
}


void RunScript(TSettings *Settings, const char *Error, const char *Region, const char *Device, const char *PamUser, const char *PamHost, const char *PamMAC)
{
char *Tempstr=NULL;

if (! StrLen(Settings->Script)) return;
Tempstr=MCopyStr(Tempstr,Settings->Script," '",Error,"' '",PamUser,"' '",PamHost, "' '", PamMAC,"' '", Device,"' '",Region,"'",NULL);
system(Tempstr);

Destroy(Tempstr);
}



int ConsiderHost(TSettings *Settings, const char *pam_service, const char *pam_user, const char *pam_rhost)
{
char *MAC=NULL, *Device=NULL, *Region=NULL, *IP=NULL, *Lists=NULL;
int PamResult=PAM_PERM_DENIED;

	Lists=CopyStr(Lists,"");

	syslog(LOG_NOTICE, "pam_ihosts user=[%s] rhost=[%s]",pam_user, pam_rhost);
	if (! StrLen(pam_rhost)) return(PAM_PERM_DENIED);
	if (! IsIPAddress(pam_rhost)) IP=CopyStr(IP, LookupHostIP(pam_rhost));
	else IP=CopyStr(IP, pam_rhost);

	GetHostARP(pam_service, IP, &Device, &MAC);
	if (StrLen(Settings->RegionFiles)) Region=RegionLookup(Region, pam_service, IP, Settings->RegionFiles);

	PamResult=CheckHostPermissions(Settings, pam_service, pam_user, pam_rhost, IP, Device, MAC, Region, &Lists);

	if (Settings->Flags & FLAG_SYSLOG)
	{
			openlog(pam_service,0,LOG_AUTH);
			if (PamResult==PAM_PERM_DENIED) syslog(LOG_NOTICE, "pam_ihosts DENY: user=[%s] rhost=[%s] ip=[%s] device=[%s] mac=[%s] region=[%s] inlist=[%s]",pam_user, pam_rhost, IP, Device, MAC, Region, Lists);
			else syslog(LOG_NOTICE, "pam_ihosts ALLOW: user=[%s] rhost=[%s] ip=[%s] device=[%s] mac=[%s] region=[%s] lists=[%s]",pam_user, pam_rhost, IP, Device, MAC, Region, Lists);
			closelog();
	}

	if (PamResult==PAM_PERM_DENIED) RunScript(Settings, "DENY", Region, Device, pam_user, pam_rhost, MAC);
	else RunScript(Settings, "ALLOW", Region, Device, pam_user, pam_rhost, MAC);

	Destroy(Region);
	Destroy(Device);
	Destroy(MAC);
	Destroy(IP);

 	return(PamResult);
}


// PAM entry point for 'account management'. This decides whether a user
// who has already been authenticated by pam_sm_authenticate should be
// allowed to log in (it considers other things than the users password)
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	char *Tempstr=NULL, *FoundFiles=NULL;
	const char *ptr;
	int PamResult=PAM_IGNORE, val;
	TSettings *Settings;

	//These are defined as 'const char' because they passwd to us from the parent
	//library. When we called pam_get_<whatever> the pam library passes pointers
	//to strings in it's own code. Thus we must not change or free them
	const char *pam_user = NULL, *pam_rhost=NULL, *pam_service=NULL;

	if (pam_get_item(pamh, PAM_SERVICE, (const void **) &pam_service) != PAM_SUCCESS) 
	{
			openlog("pam_ihosts",0,LOG_AUTH);
			syslog(LOG_ERR, "ERROR: Failed to get pam_service");
			closelog();
			return(PAM_IGNORE);
	}

	//get the user. If something goes wrong we return PAM_IGNORE. This tells
	//pam that our module failed in some way, so ignore it. Perhaps we should
	//return PAM_PERM_DENIED to deny login, but this runs the risk of a broken
	//module preventing anyone from logging into the system!
	if ((pam_get_user(pamh, &pam_user, NULL) != PAM_SUCCESS) || (pam_user == NULL))
	{
			openlog(pam_service,0,LOG_AUTH);
			syslog(LOG_ERR, "pam_ihosts ERROR: Failed to get pam_user");
			closelog();
			return(PAM_IGNORE);
	}
	
	
	if (pam_get_item(pamh, PAM_RHOST, (const void **) &pam_rhost) != PAM_SUCCESS)
	{
			openlog(pam_service,0,LOG_AUTH);
			syslog(LOG_ERR, "pam_ihosts ERROR: Failed to get pam_rhost");
			closelog();
			return(PAM_IGNORE);
	}
	
	Settings=ParseSettings(argc, argv, pam_service);
	PamResult=ConsiderHost(Settings, pam_service, pam_user, pam_rhost);

	Destroy(Settings);
	Destroy(Tempstr);

  return(PamResult);
}



// PAM entry point for authentication. This function gets called by pam when
//a login occurs. argc and argv work just like argc and argv for the 'main' 
//function of programs, except they pass in the options defined for this
//module in the pam configuration files in /etc/pam.conf or /etc/pam.d/
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	return(PAM_IGNORE);
}




//We do not provide any of the below functions, we could just leave them out
//but apparently it's considered good practice to supply them and return
//'PAM_IGNORE'

//PAM entry point for starting sessions. This is called after a user has 
//passed all authentication. It allows a PAM module to perform certain tasks
//on login, like recording the login occured, or printing a message of the day
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	return(PAM_IGNORE);
}


//PAM entry point for ending sessions. This is called when a user logs out
//It allows a PAM module to perform certain tasks on logout
//like recording the logout occured, or clearing up temporary files
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return(PAM_IGNORE);
}


//PAM entry point for setting 'credentials' or properties of the user
//If our module stores or produces extra information about a user (e.g.
//a kerberous ticket or geolocation value) then it will pass this information
//to a PAM aware program in this call
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	return(PAM_IGNORE);
}

// PAM entry point for changing passwords. If our module stores passwords
// then this will be called whenever one needs changing
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return(PAM_IGNORE);
}


//I couldn't find any documentation on this. I think it notifies PAM of our
//module name
#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_ihosts");
#endif
