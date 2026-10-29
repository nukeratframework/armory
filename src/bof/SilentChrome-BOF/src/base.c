#include <windows.h>
#include "bofdefs.h"
#include "beacon.h"
#ifndef bufsize
#define bufsize 16384
#endif

char * output __attribute__((section (".data"))) = 0;
WORD currentoutsize __attribute__((section (".data"))) = 0;

#ifdef BOF
int bofstart();
void internal_printf(const char* format, ...);
void printoutput(BOOL done);
#endif
#ifdef BOF
int bofstart()
{
    output = (char*)MSVCRT$calloc(bufsize, 1);
    currentoutsize = 0;
    return 1;
}

void internal_printf(const char* format, ...){
    int buffersize = 0;
    int transfersize = 0;
    char * curloc = NULL;
    char* intBuffer = NULL;
    va_list args;
    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (buffersize == -1)
        return;

    intBuffer = (char*)intAlloc(buffersize);
    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize, format, args);
    va_end(args);
    if(buffersize + currentoutsize < bufsize)
    {
        MSVCRT$memcpy(output+currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    }
    else
    {
        curloc = intBuffer;
        while(buffersize > 0)
        {
            transfersize = bufsize - currentoutsize;
            if(buffersize < transfersize)
            {
                transfersize = buffersize;
            }
            MSVCRT$memcpy(output+currentoutsize, curloc, transfersize);
            currentoutsize += transfersize;
            if(currentoutsize == bufsize)
            {
                printoutput(FALSE);
            }
            curloc += transfersize;
            buffersize -= transfersize;
        }
    }
    intFree(intBuffer);
}

void printoutput(BOOL done)
{
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    MSVCRT$memset(output, 0, bufsize);
    if(done) {MSVCRT$free(output); output=NULL;}
}
#else
#define internal_printf printf
#define printoutput
#define bofstart
#endif

