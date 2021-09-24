/* 
 *  (c) 2013-2016 bugficks
 *
 *  (c) 2015-2017 zoelechat @ SamyGO
 *
 *  (c) 2021 MrB
 *
 *  License: GPLv3
 *
 */
 
///		Usage: samyGOso -n enlightenment -l -r libKeyrouterRemap.so [--args -f <keymaps_folder> -e <envvar>]
///			
///		args:	-f: path to the folder containing the remap scripts
///				-e: environement variable required by the remap scripts
///			
///		ex: samyGOso -n enlightenment -r -l $SODIR/libKeyrouterRemap.so --args -f $SYSROOT/etc/keymaps -e SYSROOT=$SYSROOT -e PATH=$PATH -e HOME=$HOME
 
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define LIB_VERSION		"v1.0.1"
#define LIB_TV_MODELS	"T"
#define LIB_ISSUE		">>> SamyGO " LIB_TV_MODELS " lib" LIB_NAME " " LIB_VERSION " - (c) zoelechat 2017, MrB 2021 <<<\n"

#define LOG(...)				SGO_LOGI(__VA_ARGS__)

#define AADBG_LOG(FMT, ...)     SGO_LOG(eSGO_LOG_DEBUG, SGO_LOG_TAG, "AADBG", FMT, __VA_ARGS__)
#define HOOK_LOG(L, ...)    SGO_LOG(L, SGO_LOG_TAG, "HOOK", __VA_ARGS__)
#define DYNSYM_LOG(L, ...)    SGO_LOG(L, SGO_LOG_TAG, "DYNSYM", __VA_ARGS__)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <samygo/common.h>
#include <samygo/logging.h>
#include <samygo/samyGOso.h>
#include <samygo/aadbg.h>

#include <samygo/hook_util.h>
#include <samygo/hook.c>

#include <stdarg.h>
#include <string>

char keymaps_folder[1024] = "/opt/SamyGO/etc/keymaps";

/**
* @struct _Ecore_Event_Key
* Contains information about an Ecore keyboard event.
*/
struct _Ecore_Event_Key
 {
	const char      *keyname; /**< The key name */
	const char      *key; /**< The key symbol */
	const char      *string;
	const char      *compose; /**< final string corresponding to the key symbol composed */
	unsigned int     window; /**< The main window where event happened */
	unsigned int     root_window; /**< The root window where event happened */
	unsigned int     event_window; /**< The child window where event happened */
	
	unsigned int     timestamp; /**< Time when the event occurred */
	unsigned int     modifiers; /**< The combination of modifiers key (SHIFT,CTRL,ALT,..)*/
	
	int              same_screen; /**< same screen flag */

	unsigned int     keycode; /**< Key scan code numeric value @since 1.10 */

	void            *data; /**< User data associated with an Ecore_Event_Key @since 1.10 */

	void			*dev; /**< The Efl_Input_Device that originated the event @since 1.19 */
 };

HOOK_IMPL(int, _event_filter_tv, int a1, int a2, int type, _Ecore_Event_Key* event)
{
	//SGO_LOGI("%s: type=%d\n", __func__, type);	
	
	int r = 1;
	
	#define ECORE_EVENT_KEY_DOWN 	141
	#define ECORE_EVENT_KEY_UP 		142
	
	if( type == ECORE_EVENT_KEY_DOWN )
	{
		SGO_LOGI("%s: key=%d(%s)\n", __func__, event->key, event->keyname);	
		
		char fname[1024];	
		snprintf(fname, 1024, "%s/%s", keymaps_folder, event->keyname);
			
		if( access( fname, F_OK ) != -1 )
		{				
			pid_t pid = fork();
			if (pid == 0)	// child thread
			{
				SGO_LOGI("<%s> running script: %s\n", __func__, fname);
				
				execl(fname, fname);
				exit(0);
			}
			else if (pid == -1)			
				SGO_LOGI("<%s> fork failed\n", __func__);
			
			return 0;
		}		
	}
		
	HOOK_DISPATCH_R(r, _event_filter_tv, a1, a2, type, event);
	
	return r;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef int (*_e_keyrouter_tv_add_handlers_t)();

int lib_init(void *h, const char *libpath)
{
	SGO_LOGD("<%s> h: %p, libpath: %s\n", __func__, h, libpath);
	
	if(!sgo_lib_check_close(h))
	{
		SGO_LOGI("<%s> Injecting once is enough!\n", __func__);
		return 1;
	}
			
	char *argv[LIB_ARGC_MAX];
	int argc = sgo_getArgCArgV( libpath, argv );
	int opt = 0;
	
	// parse args
	while ( (opt = getopt(argc, argv, "f:e:")) != -1 )
	{		
		switch(opt)
		{
			case 'f':				
				snprintf(keymaps_folder, 1024, "%s", optarg);
				break;
				
			case 'e':				
				putenv(strdup(optarg));
				SGO_LOGI("<%s> env variable set: %s\n", __func__, optarg);
				break;
			
			default:
				break;
		}
	}
	
	SGO_LOGI("<%s> keymaps folder is %s\n", __func__, keymaps_folder);

	// get address of function 'e_keyrouter_tv_change_key_event'	
	void* handle = dlopen("/usr/lib/enlightenment/modules/e-mod-tizen-keyrouter-tv/linux-gnueabi-armv7l-ver-autocannoli-0.20/module.so", RTLD_NOW);
	if (handle == NULL) {
		SGO_LOGI("dlopen() failed: %s\n", dlerror());
		return 1;
	}
	
	uint32_t addr = (uint32_t)dlsym(handle, "_e_keyrouter_tv_add_handlers");	
	if(addr == 0)
	{
		SGO_LOGI("dlsym() failed: %s\n", dlerror());
		return 1;
	}
	
	SGO_LOGI("_e_keyrouter_tv_add_handlers=0x%08X\n", addr);
	
	// patch _e_keyrouter_tv_add_handlers to return _event_filter_tv address
	const uintptr_t pagesize = getpagesize();
	mprotect((void*)SGO_ALIGN_DOWN(addr, pagesize), pagesize * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
	
	uint32_t oldbytes = 0, i;
	for( i = 1; i < 50; i += 2 )
	{
		//SGO_LOGI("bytes=%02X %02X\n", ((uint8_t*)addr)[i], ((uint8_t*)addr)[i + 1]);
		
		if( ((uint8_t*)addr)[i] == 0x79 && ((uint8_t*)addr)[i + 1] == 0x44 )
		{
			i += 2;
			oldbytes = *(uint32_t*)(addr + i);
			SGO_LOGI("[addr:0x%08X]=0x%08X\n", addr + i, oldbytes);		// oldbytes=0x682F5965
			*(uint32_t*)(addr + i) = 0xbdf84608;	// MOV             R0, R1  ++++  POP             {R3-R7,PC}						
			cacheflush(addr + i, 4);
			break;
		}
	}
	
	if( i >= 50 )
	{
		SGO_LOGI("code to patch not found!\n");
		return 1;
	}
		
	// get _event_filter_tv address and restore original bytes
	uint32_t _event_filter_tv = ((_e_keyrouter_tv_add_handlers_t)addr)();
	*(uint32_t*)(addr + i) = oldbytes;
	cacheflush(addr + i, 4);
	
	SGO_LOGI("_event_filter_tv=0x%08X\n", _event_filter_tv );
	
	dlclose(handle);
			
    mprotect((void*)SGO_ALIGN_DOWN(_event_filter_tv, pagesize), pagesize * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
	
	hijack_start(&__symhook__event_filter_tv, (void*)_event_filter_tv, (void*)hook__event_filter_tv);
	
	SGO_LOGI(">>> Init done\n");
	
	return 0;
}

int lib_deinit(void *h)
{
	SGO_LOGD("<%s> h: %p \n", __func__, h);
	
	hijack_stop(&__symhook__event_filter_tv);

	SGO_LOGI("<<< Deinit done\n");	
	
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
