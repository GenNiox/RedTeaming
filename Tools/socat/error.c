/* source: error.c */
/* Copyright Gerhard Rieger and contributors (see file CHANGES) */
/* Published under the GNU General Public License V.2, see file COPYING */

/* the logging subsystem */

#include "config.h"
#include "sysincludes.h"

#include "mytypes.h"
#include "compat.h"
#include "utils.h"
#include "vsnprintf_r.h"
#include "snprinterr.h"

#include "error.h"
#include "sycls.h"


/* translate MSG level to SYSLOG level */
int syslevel[] = {
   LOG_DEBUG,
   LOG_INFO,
   LOG_NOTICE,
   LOG_WARNING,
   LOG_ERR,
   LOG_CRIT };

struct diag_opts {
   const char *progname;
   int msglevel;
   int exitlevel;
   int syslog;
   FILE *logfile;
   int logfacility;
   bool micros;
   int exitstatus;	/* pass signal number to error exit */
   bool withhostname;	/* in custom logs add hostname */
   char *hostname;
   bool signalsafe;
} ;


static void _diag_exit(int status);


struct diag_opts diagopts =
  { NULL, E_ERROR, E_ERROR, 0, NULL, LOG_DAEMON, false, 0, false, NULL, true } ;

static void msg2(
#if HAVE_CLOCK_GETTIME
		 struct timespec *now,
#elif HAVE_PROTOTYPE_LIB_gettimeofday
		 struct timeval *now,
#else
		 time_t *now,
#endif
		 int level, int exitcode, int handler, const char *text);
static void _msg(int level, const char *buff, const char *syslp);

sig_atomic_t diag_in_handler;	/* !=0 indicates to msg() that in signal handler */
sig_atomic_t diag_immediate_msg;	/* !=0 prints messages even from within signal handler instead of deferring them */
sig_atomic_t diag_immediate_exit;	/* !=0 calls exit() from diag_exit() even when in signal handler. For system() */

static struct wordent facilitynames[] = {
   {"auth",     (void *)LOG_AUTH},
#ifdef LOG_AUTHPRIV
   {"authpriv", (void *)LOG_AUTHPRIV},
#endif
#ifdef LOG_CONSOLE
   {"console",	(void *)LOG_CONSOLE},
#endif
   {"cron",     (void *)LOG_CRON},
   {"daemon",   (void *)LOG_DAEMON},
#ifdef LOG_FTP
   {"ftp",      (void *)LOG_FTP},
#endif
   {"kern",     (void *)LOG_KERN},
   {"local0",   (void *)LOG_LOCAL0},
   {"local1",   (void *)LOG_LOCAL1},
   {"local2",   (void *)LOG_LOCAL2},
   {"local3",   (void *)LOG_LOCAL3},
   {"local4",   (void *)LOG_LOCAL4},
   {"local5",   (void *)LOG_LOCAL5},
   {"local6",   (void *)LOG_LOCAL6},
   {"local7",   (void *)LOG_LOCAL7},
   {"lpr",      (void *)LOG_LPR},
   {"mail",     (void *)LOG_MAIL},
   {"news",     (void *)LOG_NEWS},
#ifdef LOG_SECURITY
   {"security",	(void *)LOG_SECURITY},
#endif
   {"syslog",   (void *)LOG_SYSLOG},
   {"user",     (void *)LOG_USER},
   {"uucp",     (void *)LOG_UUCP}
} ;

/* serialize message for sending from signal handlers */
struct sermsg {
   int severity;
#if HAVE_CLOCK_GETTIME
   struct timespec ts;
#else
   struct timeval tv;
#endif
} ;

static int diaginitialized;
static int diag_sock_send = -1;
static int diag_sock_recv = -1;
static int diag_msg_avail = 0;	/* !=0: messages from within signal handler may be waiting */


static int diag_sock_pair(void) {
   int handlersocks[2];

   if (socketpair(AF_UNIX, SOCK_DGRAM, 0, handlersocks) < 0) {
      diag_sock_send = -1;
      diag_sock_recv = -1;
      return -1;
   }
   diag_sock_send = handlersocks[1];
   diag_sock_recv = handlersocks[0];
#if !defined(MSG_DONTWAIT)
   fcntl(diag_sock_send, F_SETFL, O_NONBLOCK);
   fcntl(diag_sock_recv, F_SETFL, O_NONBLOCK);
#endif
   return 0;
}

static int diag_init(void) {
   if (diaginitialized) {
      return 0;
   }
   diaginitialized = 1;
   /* gcc with GNU libc refuses to set this in the initializer */
   diagopts.logfile = stderr;
   if (diagopts.signalsafe) {
      if (diag_sock_pair() < 0) {
	 return -1;
      }
   }
   return 0;
}
#define DIAG_INIT ((void)(diaginitialized || diag_init()))


void diag_set(char what, const char *arg) {
   switch (what) {
   case 'I':
      if (diagopts.signalsafe) {
	 if (diag_sock_send >= 0) { Close(diag_sock_send); diag_sock_send = -1; }
	 if (diag_sock_recv >= 0) { Close(diag_sock_recv); diag_sock_recv = -1; }
      }
      diagopts.signalsafe = false;
      return;
   }

   DIAG_INIT;
   switch (what) {
      const struct wordent *keywd;

   case 'y': diagopts.syslog = true;
      if (arg && arg[0]) {
	 if ((keywd =
	      keyw(facilitynames, arg,
		   sizeof(facilitynames)/sizeof(struct wordent))) == NULL) {
	    Error1("unknown syslog facility \"%s\"", arg);
	 } else {
	    diagopts.logfacility = (int)(size_t)keywd->desc;
	 }
      }
      openlog(diagopts.progname, LOG_PID, diagopts.logfacility);
      if (diagopts.logfile != NULL && diagopts.logfile != stderr) {
	 fclose(diagopts.logfile);
      }
      diagopts.logfile = NULL;
      break;
   case 'f':
      if (diagopts.logfile != NULL && diagopts.logfile != stderr) {
	 fclose(diagopts.logfile);
      }
      if ((diagopts.logfile = fopen(arg, "a")) == NULL) {
	  Error2("cannot open log file \"%s\": %s", arg, strerror(errno));
      }
      break;
   case 's':
      if (diagopts.logfile != NULL && diagopts.logfile != stderr) {
	 fclose(diagopts.logfile);
      }
      diagopts.logfile = stderr; break;	/* logging to stderr is default */
   case 'p': diagopts.progname = arg;
      openlog(diagopts.progname, LOG_PID, diagopts.logfacility);
      break;
   case 'd': --diagopts.msglevel; break;
   case 'u': diagopts.micros = true; break;
   default: msg(E_ERROR, "unknown diagnostic option %c", what);
   }
}

void diag_set_int(char what, int arg) {
   DIAG_INIT;
   switch (what) {
   case 'D': diagopts.msglevel = arg; break;
   case 'e': diagopts.exitlevel = arg; break;
   case 'x': diagopts.exitstatus = arg; break;
   case 'h': diagopts.withhostname = arg;
      if ((diagopts.hostname = getenv("HOSTNAME")) == NULL) {
	 struct utsname ubuf;
	 uname(&ubuf);
	 diagopts.hostname = strdup(ubuf.nodename);
      }
      break;
   default: msg(E_ERROR, "unknown diagnostic option %c", what);
   }
}

int diag_get_int(char what) {
   DIAG_INIT;
   switch (what) {
   case 'y': return diagopts.syslog;
   case 's': return diagopts.logfile == stderr;
   case 'd': case 'D': return diagopts.msglevel;
   case 'e': return diagopts.exitlevel;
   }
   return -1;
}

const char *diag_get_string(char what) {
   DIAG_INIT;
   switch (what) {
   case 'p': return diagopts.progname;
   }
   return NULL;
}

/* make sure that the diag_sock fds do not have this num */
int diag_reserve_fd(int fd) {
   DIAG_INIT;
   if (diag_sock_send == fd) {
      diag_sock_send = Dup(fd);
      Close(fd);
   }
   if (diag_sock_recv == fd) {
      diag_sock_recv = Dup(fd);
      Close(fd);
   }
   return 0;
}

/* call this after a fork() from the child process to separate master/parent
   sockets from child sockets */
int diag_fork() {
   Close(diag_sock_send);
   Close(diag_sock_recv);
   if (diagopts.signalsafe) {
      return diag_sock_pair();
   }
   return 0;
}

/* Linux and AIX syslog format:
Oct  4 17:10:37 hostname socat[52798]: D signal(13, 1)
*/
void msg(int level, const char *format, ...) {
   struct diag_dgram diag_dgram;
   va_list ap;

   /* does not perform a system call if nothing todo, thanks diag_msg_avail */

   diag_dgram._errno = errno;	/* keep for passing from signal handler to sock.
				   reason is that strerror is definitely not
				   async-signal-safe */
   DIAG_INIT;

   /* in normal program flow (not in signal handler) */
   /* first flush the queue of datagrams from the socket */
   if (diag_msg_avail && !diag_in_handler) {
      diag_msg_avail = 0;	/* _before_ flush to prevent inconsistent state when signal occurs inbetween */
      diag_flush();
   }

   if (level < diagopts.msglevel)  { return; }
   va_start(ap, format);

   /* we do only a minimum in the outer parts which may run in a signal handler
      these are: get actual time, level, serialized message  and write them to socket
   */
   diag_dgram.op = DIAG_OP_MSG;
#if HAVE_CLOCK_GETTIME
   clock_gettime(CLOCK_REALTIME, &diag_dgram.now);
#elif HAVE_PROTOTYPE_LIB_gettimeofday
   gettimeofday(&diag_dgram.now, NULL);
#else
   diag_dgram.now = time(NULL);
#endif
   diag_dgram.level = level;
   diag_dgram.exitcode = diagopts.exitstatus;
   vsnprintf_r(diag_dgram.text, sizeof(diag_dgram.text), format, ap);
   if (diagopts.signalsafe && diag_in_handler && !diag_immediate_msg) {
      send(diag_sock_send, &diag_dgram, sizeof(diag_dgram)-TEXTLEN + strlen(diag_dgram.text)+1,
	   0 	/* for canonical reasons */
#ifdef MSG_DONTWAIT
	   |MSG_DONTWAIT
#endif
#ifdef MSG_NOSIGNAL
	   |MSG_NOSIGNAL
#endif
	   );
      diag_msg_avail = 1;
      va_end(ap);
      return;
   }

   msg2(&diag_dgram.now, diag_dgram.level, diagopts.exitstatus, 0, diag_dgram.text);
   va_end(ap); return;
}

void msg2(
#if HAVE_CLOCK_GETTIME
	  struct timespec *now,
#elif HAVE_PROTOTYPE_LIB_gettimeofday
	  struct timeval *now,
#else
	  time_t *now,
#endif
	  int level,		/* E_INFO... */
	  int exitcode,		/* on exit use this exit code */
	  int handler,		/* message comes from signal handler */
	  const char *text) {
   time_t epoch;
   unsigned long micros;
#if HAVE_STRFTIME
   struct tm struct_tm;
#endif
#define MSGLEN 512
   char buff[MSGLEN+2], *bufp = buff, *syslp;
   size_t bytes;

#if HAVE_CLOCK_GETTIME
   epoch = now->tv_sec;
#elif HAVE_PROTOTYPE_LIB_gettimeofday
   epoch = now->tv_sec;
#else
   epoch = *now;
#endif
   /*! consider caching instead of recalculating many times per second */
#if HAVE_STRFTIME
   bytes = strftime(bufp, 20, "%Y/%m/%d %H:%M:%S", localtime_r(&epoch, &struct_tm));
#else
   bytes = snprintf(bufp, 11, F_time, epoch);
#endif
   bufp += bytes;
   *bufp = '\0';
   if (diagopts.micros) {
#if HAVE_CLOCK_GETTIME
      micros = now->tv_nsec/1000;
#elif HAVE_PROTOTYPE_LIB_gettimeofday
      micros = now->tv_usec;
#else
      micros = 0;
#endif
      bufp += sprintf(bufp, ".%06lu ", micros);
   } else {
      *bufp++ = ' ';
      *bufp = '\0';
   }

   if (diagopts.withhostname) {
      bytes = snprintf(bufp, MSGLEN-(bufp-buff), "%s ", diagopts.hostname);
      if (bytes >= MSGLEN-(bufp-buff))
	 bytes = MSGLEN-(bufp-buff)-1;
      bufp += bytes;
   }
   bytes = snprintf(bufp, MSGLEN-(bufp-buff), "%s["F_pid"] ", diagopts.progname, getpid());
   if (bytes >= MSGLEN-(bufp-buff))
      bytes = MSGLEN-(bufp-buff)-1;
   bufp += bytes;
   syslp = bufp; 	/* syslog prefixes with time etc.itself */
   if (bufp < buff+MSGLEN)
      *bufp++ = "DINWEF"[level];
#if 0 /* only for debugging socat */
   if (handler)  bufp[-1] = tolower((unsigned char)bufp[-1]); /* for debugging, low chars indicate messages from signal handlers */
#endif
   if (bufp < buff+MSGLEN)
      *bufp++ = ' ';
   strncpy(bufp, text, MSGLEN-(bufp-buff));
   bufp = strchr(bufp, '\0');
   strcpy(bufp, "\n");
   _msg(level, buff, syslp);
   if (level >= diagopts.exitlevel) {
      if (E_NOTICE >= diagopts.msglevel) {
	 if ((syslp - buff) + 16 > MSGLEN+1)
	    syslp = buff + MSGLEN - 15;
	 snprintf_r(syslp, 16, "N exit(%d)\n", exitcode?exitcode:(diagopts.exitstatus?diagopts.exitstatus:1));
	 _msg(E_NOTICE, buff, syslp);
      }
      exit(exitcode?exitcode:(diagopts.exitstatus?diagopts.exitstatus:1));
   }
}


static void _msg(int level, const char *buff, const char *syslp) {
   if (diagopts.syslog) {
      /* prevent format string attacks (thanks to CoKi) */
      syslog(syslevel[level], "%s", syslp);
   }
   if (diagopts.logfile) {
      fputs(buff, diagopts.logfile); fflush(diagopts.logfile);
   }
}


/* handle the messages in the queue */
void diag_flush(void) {
   struct diag_dgram recv_dgram;
   char exitmsg[20];

   if (!diagopts.signalsafe) {
      return;
   }

   while (recv(diag_sock_recv, &recv_dgram, sizeof(recv_dgram)-1,
	       0 	/* for canonical reasons */
#ifdef MSG_DONTWAIT
	       |MSG_DONTWAIT
#endif
	       ) > 0) {
      recv_dgram.text[TEXTLEN-1] = '\0';
      switch (recv_dgram.op) {
      case DIAG_OP_EXIT:
	 /* we want the actual time, not when this dgram was sent */
#if HAVE_CLOCK_GETTIME
	 clock_gettime(CLOCK_REALTIME, &recv_dgram.now);
#elif HAVE_PROTOTYPE_LIB_gettimeofday
	 gettimeofday(&recv_dgram.now, NULL);
#else
	 recv_dgram.now = time(NULL);
#endif
	 if (E_NOTICE >= diagopts.msglevel) {
	    snprintf_r(exitmsg, sizeof(exitmsg), "exit(%d)", recv_dgram.exitcode?recv_dgram.exitcode:1);
	    msg2(&recv_dgram.now, E_NOTICE, recv_dgram.exitcode?recv_dgram.exitcode:1, 1, exitmsg);
	 }
	 exit(recv_dgram.exitcode?recv_dgram.exitcode:1);
      case DIAG_OP_MSG:
	 if (recv_dgram._errno) {
	    /* there might be a %m control in the string (glibc compatible,
	       replace with strerror(...errno) ) */
	    char text[TEXTLEN];
	    errno = recv_dgram._errno;
	    snprinterr(text, TEXTLEN, recv_dgram.text);
	    msg2(&recv_dgram.now, recv_dgram.level, recv_dgram.exitcode, 1, text);
	 } else {
	    msg2(&recv_dgram.now, recv_dgram.level, recv_dgram.exitcode, 1, recv_dgram.text);
	 }
	 break;
      }
   }
}


/* use a new log output file descriptor that is dup'ed from the current one.
   this is useful when socat logs to stderr but fd 2 should be redirected to
   serve other purposes */
int diag_dup(void) {
   int newfd;

   DIAG_INIT;
   if (diagopts.logfile == NULL) {
      return -1;
   }
   newfd = dup(fileno(diagopts.logfile));
   if (diagopts.logfile != stderr) {
      fclose(diagopts.logfile);
   }
   if (newfd >= 0) {
      diagopts.logfile = fdopen(newfd, "w");
   }
   return newfd;
}


/* this function is kind of async-signal-safe exit(). When invoked from signal
   handler it defers exit. */
void diag_exit(int status) {
   struct diag_dgram diag_dgram;

   if (diag_in_handler && !diag_immediate_exit) {
      diag_dgram.op = DIAG_OP_EXIT;
      diag_dgram.exitcode = status;
      send(diag_sock_send, &diag_dgram, sizeof(diag_dgram)-TEXTLEN,
	   0 	/* for canonical reasons */
#ifdef MSG_DONTWAIT
	   |MSG_DONTWAIT
#endif
#ifdef MSG_NOSIGNAL
	   |MSG_NOSIGNAL
#endif
	   );
      return;
   }
   _diag_exit(status);
}

static void _diag_exit(int status) {
   Exit(status);
}


/* a function that appears to the application like select() but that also
   monitors the diag socket diag_sock_recv and processes its messages.
   Do not call from within a signal handler. */
int diag_select(int nfds, fd_set *readfds, fd_set *writefds,
		 fd_set *exceptfds, struct timeval *timeout) {
   int result;
   fd_set save_readfds, save_writefds, save_exceptfds;

   if (readfds)   { memcpy(&save_readfds,   readfds,   sizeof(*readfds)); }
   if (writefds)  { memcpy(&save_writefds,  writefds,  sizeof(*writefds)); }
   if (exceptfds) { memcpy(&save_exceptfds, exceptfds, sizeof(*exceptfds)); }

   while (1) {
      FD_SET(diag_sock_recv, readfds);
      result = Select(nfds, readfds, writefds,
		       exceptfds, timeout);
     if (!FD_ISSET(diag_sock_recv, readfds)) {
	 /* select terminated not due to diag_sock_recv, normalt continuation */
	 break;
      }
      diag_flush();
      if (readfds)   { memcpy(readfds,   &save_readfds,   sizeof(*readfds)); }
      if (writefds)  { memcpy(writefds,  &save_writefds,  sizeof(*writefds)); }
      if (exceptfds) { memcpy(exceptfds, &save_exceptfds, sizeof(*exceptfds)); }
   }
   return result;
}

