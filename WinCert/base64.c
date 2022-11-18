/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#include "WinCerti.h"

/* GLOBALS ********************************************************************/

static CHAR BeginHeader[] = { '-','-','-','-','-','B','E','G','I','N', ' ' };
static CHAR EndFooter[] = { '-','-','-','-','-','E','N','D',' ' };
static CHAR MinusSeq[] = { '-','-','-','-','-' };

static const BYTE ModTable[4] = { 0, 0, 1, 2 };
static const CHAR ValTable[] = {
    /* 00: */ 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    /* 10: */ 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    /* 20: */ 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    /* 30: */ 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    /* 40: */ 64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    /* 50: */ 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    /* 60: */ 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    /* 70: */ 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
};

/* FUNCTIONS ******************************************************************/

//
// The following characters are considered spaces:
// \t  0x09  Horizontal Tab
// \n  0x0A  Newline(Line Feed)
// \v  0x0B  Vertical Tab
// \f  0x0C  Formfeed Page Break
// \r  0x0D  Carriage Return
//
#define IsSpace(c) ((c) >= 0x09 && (c) <= 0x0D)

#ifdef DEBUG
#define _ASSUME(x) ASSERT(x)
#else
#define _ASSUME(x) __assume(x)
#endif

_Must_inspect_result_
NTSTATUS
Base64Decode(
    _In_ PCCHAR In,
    _In_ SIZE_T Count,
    _In_ BOOLEAN Strict,
    _Out_ PBLOB Data
    )
{
    PCCHAR end = In + Count;
    SIZE_T len = 0;
    PCCHAR pc;
    NTSTATUS Status;
    PBYTE out;
    BYTE x;
    ULONG v;

    for (pc = In; pc < end; pc++) {
        if (*pc > sizeof(ValTable) || ValTable[*pc] == 64) {

            DWORD x;

            //
            // The character is not a valid base64 character -
            // but spaces we can ignore.
            //
            if (IsSpace(*pc))
                continue;

            //
            // Since the decoding is done modulu 4 we need to see
            // that we have anough padding of '='.
            //
            // N.B. The equal sign is considered legal only at the end
            // of the string.
            //
            x = len % 4;

            //
            // A single char can not represent a single octect
            //
            if (x > 1) {
                if (!Strict)
                    break;

                //
                // We need to look for the padding '=' sign(s)
                //
                x = 4 - x;
                while (x && pc < end) {
                    if (!IsSpace(*pc)) {
                        if (*pc != '=')
                            break;

                        x--;
                    }

                    pc++;
                }
            }

            if (x == 0)
                break;

            return STATUS_BAD_DATA;
        }

        len++;
    }

    end = pc;

    ASSERT((len % 4) != 1);

    //
    // Allocate the output buffer
    //
    Status = BlobAlloc(Data, ((len / 4) * 3) + ModTable[len % 4]);
    if (!NT_SUCCESS(Status))
        return Status;

    pc = In;
    x = 0;
    v = 0;
    out = Data->pBlobData;
    while (pc < end) {
        if (!IsSpace(*pc)) {
            switch (x++) {
            case 0:
                v = (ValTable[*pc] << 18);
                break;

            case 1:
                v |= (ValTable[*pc] << 12);
                break;

            case 2:
                v |= (ValTable[*pc] << 6);
                break;

            case 3:
                v |= ValTable[*pc];
                x = 0;
                *out++ = ((PBYTE)&v)[2];
                *out++ = ((PBYTE)&v)[1];
                *out++ = ((PBYTE)&v)[0];
                break;

            default: _ASSUME(0);
            }
        }

        pc++;
    }

    ASSERT(x == 0 || x == 2 || x == 3);

    if (x >= 2) {
        *out++ = ((PBYTE)&v)[2];

        if (x == 3) {
            *out++ = ((PBYTE)&v)[1];
        }
    }

    return STATUS_SUCCESS;
}

_Must_inspect_result_
PCCHAR
Base64Header(
    _In_reads_(Count) PCCHAR In,
    _In_ SIZE_T Count,
    _In_ BOOLEAN Begin,
    _Out_opt_ PCHAR* Start
    )
{
    DWORD len;
    const CHAR* seq;
    const CHAR* pc = In;
    const CHAR* end = In + Count;

    if (Begin) {
        seq = BeginHeader;
        len = sizeof(BeginHeader);
    }
    else {
        seq = EndFooter;
        len = sizeof(EndFooter);
    }

    for (;; pc++) {

        //
        // Progress until we find the first character of the sequence
        //
        for (;;) {
            if ((pc + len) > end)
                return NULL;

            if (*pc == *seq)
                break;

            pc++;
        }

        //
        // If we did not at the sequence yet resume from the start
        //
        if (strncmp(pc, seq, len) == 0)
            break;
    }

    if (Start) {
        *Start = (PCHAR)pc;
    }

    pc += len;

    //
    // Skip all characters until the minus sequence
    //
    while ((pc + sizeof(MinusSeq)) <= end) {
        if (memcmp(pc, MinusSeq, sizeof(MinusSeq)) == 0)
            return (PCCHAR)pc + sizeof(MinusSeq);

        pc++;
    }

    return NULL;
}
