/*++ BUILD Version: 0001    Increment this if a change has global effects

Copyright (c) 2022 Yaron Aronsohn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Module Name:

    blob.h

Description:

    Include file for BLOB struc definitions and helper routines.

Revision:

    Rev     Date        Programmer          Revision History

    --*/
#ifndef _BLOB_H_
#define _BLOB_H_

#ifndef _tagBLOB_DEFINED
//
// N.B. Regardless of the field names, this structure is defined
// in a compatible way to the one defined in WTypesbase.h to ensure
// binary compatibility.
//
#define _tagBLOB_DEFINED
#define _BLOB_DEFINED
#define _LPBLOB_DEFINED
typedef struct _BLOB {
    ULONG cbSize;
    PBYTE pBlobData;
} BLOB, *LPBLOB;
#endif // _tagBLOB_DEFINED

typedef BLOB* PBLOB;

#ifdef __cplusplus
#define REFBLOB const BLOB &

__inline int IsEqualBLOB(REFBLOB blob1, REFBLOB blob2)
{
    if (blob1.cbSize != blob2.cbSize)
        return FALSE;

    return !memcmp(blob1.pBlobData, blob2.pBlobData, blob1.cbSize);
}

__inline bool operator==(REFBLOB blob1, REFBLOB blob2)
{
    return !!IsEqualBLOB(blob1, blob2);
}

__inline bool operator!=(REFBLOB blob1, REFBLOB blob2)
{
    return !(blob1 == blob2);
}

__inline void ProgressBlob(BLOB& blob, ULONG count)
{
    count = min(count, blob.cbSize);
    blob.pBlobData += count;
    blob.cbSize -= count;
}

__inline int BlobSkip(BLOB& blob, UCHAR value)
{
    if (blob.cbSize < 1 || blob.pBlobData[0] != value)
        return false;

    ProgressBlob(blob, 1);
    return true;
}

#define BlobSkipBlob(blob1, blob2) \
    ProgressBlob(blob1, (blob2).cbSize)

__inline int IsNilBlob(REFBLOB blob)
{
    return blob.cbSize == 0 && blob.pBlobData == NULL;
}
#else
#define REFBLOB const BLOB *

__inline int IsEqualBLOB(REFBLOB blob1, REFBLOB blob2)
{
    if (blob1->cbSize != blob2->cbSize)
        return FALSE;

    return !memcmp(blob1->pBlobData, blob2->pBlobData, blob1->cbSize);
}

__inline void ProgressBlob(BLOB* blob, ULONG count)
{
    count = min(count, blob->cbSize);
    blob->pBlobData += count;
    blob->cbSize -= count;
}

__inline int BlobSkip(BLOB* blob, UCHAR value)
{
    if (blob->cbSize < 1 || blob->pBlobData[0] != value)
        return FALSE;

    ProgressBlob(blob, 1);
    return TRUE;
}

#define BlobSkipBlob(blob1, blob2) \
    ProgressBlob(blob1, (blob2)->cbSize)

__inline int IsNilBlob(REFBLOB blob)
{
    return blob->cbSize == 0 && blob->pBlobData == NULL;
}
#endif

#ifndef EXTERN_C
#ifdef __cplusplus
#define EXTERN_C    extern "C"
#else
#define EXTERN_C    extern
#endif
#endif

#ifdef INITBLOB
#define DEFINE_BLOB(name, b, ...) \
    static const BYTE name##_data[] = { b, __VA_ARGS__ }; \
    EXTERN_C const BLOB name = { (ULONG)sizeof(name##_data), (PBYTE)name##_data };
#else
#define DEFINE_BLOB(name, b, ...) \
    EXTERN_C const BLOB name;
#endif

#endif // _BLOB_H_
