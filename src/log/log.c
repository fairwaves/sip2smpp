#include "log.h"

static pthread_mutex_t* P_MUTEX   = NULL;
static Loglevel log_choice        = LOG_INFO;

static void _p_printf_init(const void *p_funcion);

int (*printf_function)(const char *restrict, ...) = &printf;

char* str_loglevel[]={
	"NONE",
	LOG_CONSOLE_STR,
	LOG_DEBUG_STR,
	LOG_INFO_STR,
	LOG_NOTICE_STR,
	LOG_WARNING_STR,
	LOG_ERROR_STR,
	LOG_CRIT_STR,
	LOG_ALERT_STR
};

int str_to_loglevel(const char *name){
    if(strncmp(name, LOG_CONSOLE_STR, 7) == 0){
        return (int) LOG_CONSOLE;
    }
    if(strncmp(name, LOG_DEBUG_STR, 5) == 0){
        return (int) LOG_DEBUG;
    }
    if(strncmp(name, LOG_INFO_STR, 4) == 0){
        return (int) LOG_INFO;
    }
    if(strncmp(name, LOG_NOTICE_STR, 6) == 0){
        return (int) LOG_NOTICE;
    }
    if(strncmp(name, LOG_WARNING_STR, 7) == 0){
        return (int) LOG_WARNING;
    }
    if(strncmp(name, LOG_ERROR_STR, 5) == 0){
        return (int) LOG_ERROR;
    }
    if(strncmp(name, LOG_CRIT_STR, 4) == 0){
        return (int) LOG_CRIT;
    }
    if(strncmp(name, LOG_ALERT_STR, 5) == 0){
        return (int) LOG_ALERT;
    }
    return (int) 0;
}

/**
 * \brief	This function allow to init LOG_SCREEN function.
 *
 * \param	p_function	This parameter is a pointer function used for LOG_SCREEN (by default printf)
 */
static void _p_printf_init(const void *p_function){
	if(p_function){
		printf_function = (int (*)(const char *restrict, ...))p_function;
	}else{
		printf_function = &printf;
	}
	return;
}

/**
 * \brief	Display every LOG level more smaller l.
 *
 * \param	l : This parameter is the Loglevel choice
 */
void log2display(Loglevel l){
	log_choice = l;
	return;
}

/**
 * \brief Get the log_choice variable. This variable is define by log2display function.
 *
 * \return Loglevel   the log_choice variable
 *
 */
Loglevel log_get_display(void){
  return log_choice;
}


/**
 * \brief	This function allow to init the log system.
 *
 * \param	p_function	The parameter is pointer of function to display log (NULL : by default is printf).
 */
int log_init(const void *p_function){
	if(P_MUTEX == NULL){
		P_MUTEX = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
		pthread_mutex_init(P_MUTEX,NULL);
	}else{
		ERROR(LOG_FILE | LOG_SCREEN,"MUTEX is not init");
		return -1;
	}
	_p_printf_init(p_function);
	INFO(LOG_SCREEN,"Logging initialized");
	return 0;
}

/**
 * \brief	This function allow to destroy the log system.
 */
int log_destroy(void){
	if(P_MUTEX){
		pthread_mutex_destroy(P_MUTEX);
		free(P_MUTEX);
		P_MUTEX = NULL;
	}
	INFO(LOG_SCREEN,"Logging destroy");
	return 0;
}

/**
 * \brief	It is the main LOG function. It allow to display and/or save the LOG in a file.
 *
 * \param	lvl	This parameter is the level LOG define for this information (LOG_CONSOLE,LOG_DEBUG,LOG_INFO,LOG_NOTICE,LOG_WARNING,LOG_ERROR,LOG_CRIT,LOG_ALERT)
 * \param	display	This parameter allow to set the display flags (LOG_SCREEN and/or LOG_FILE)
 * \param	tid	This parameter is thread ID
 * \param	pid	This parameter is processus ID
 * \param	func	This parameter is function name
 * \param	file	This parameter is file name
 * \param	line	This parameter is line number
 * \param	buff	This parameter is buffer of log
 */
void log_hook(Loglevel lvl, pthread_t tid, pid_t pid, const char* func, const char* file, unsigned int line, const char* buff){
	if(P_MUTEX) pthread_mutex_lock(P_MUTEX);
	//if( (lvl >= LOG_CONSOLE || lvl <= LOG_ALERT) && buff){
	if(lvl >= LOG_CONSOLE && lvl <= LOG_ALERT && log_choice >= lvl && buff){
		if(tid != 0){
			printf_function("%s [%lx/%u] [%s,%s:%d] %s\n",str_loglevel[lvl],tid,pid,file,func,line,buff);
		}else{
			printf_function("%s [%u] [%s,%s:%d] %s\n",str_loglevel[lvl],pid,file,func,line,buff);
		}
	}
	if(P_MUTEX) pthread_mutex_unlock(P_MUTEX);
	return;
}


/*
//sample
int main(){

	log_init("test.log",NULL);

	log2display(LOG_NONE);

	CONSOLE(LOG_SCREEN,	"test log CONSOLE");
	DEBUG(	LOG_SCREEN,	"test log DEBUG %d",5);
	INFO(	LOG_SCREEN,	"test log INFO %s, %d","add test",5);
	NOTICE(	LOG_SCREEN,	"test log NOTICE");
	WARNING(LOG_SCREEN,	"test log WARNING");
	ERROR(	LOG_SCREEN,	"test log ERROR");
	CRIT(	LOG_SCREEN,	"test log CRIT");
	ALERT(	LOG_SCREEN,	"test log ALERT");


	CONSOLE(LOG_FILE,	"test log CONSOLE %s","In file only");
	DEBUG(	LOG_FILE,	"test log DEBUG %d",5);
	INFO(	LOG_FILE,	"test log INFO %s, %d","add test",5);
	NOTICE(	LOG_FILE,	"test log NOTICE");
	WARNING(LOG_FILE,	"test log WARNING");
	ERROR(	LOG_FILE,	"test log ERROR");
	CRIT(	LOG_FILE,	"test log CRIT");
	ALERT(	LOG_FILE,	"test log ALERT");

	CONSOLE(LOG_FILE | LOG_SCREEN,	"test log CONSOLE %s","In file and screen");

	log_destroy();

	return 0;
}
*/

