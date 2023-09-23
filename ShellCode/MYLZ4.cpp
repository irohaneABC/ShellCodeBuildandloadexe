#pragma once

#include"TOOL.h"


#ifndef FZName_H_
#define FZName_H_   
#include "MYLZ4.h"
#endif



int LZ4_decompress_generic(
	const char* source,
	char* dest,
	int inputSize,
	int outputSize,         /* If endOnInput==endOnInputSize, this value is the max size of Output Buffer. */
	int endOnInput,         /* endOnOutputSize,*/
	int prefix64k,          /* noPrefix,*/
	int partialDecoding,    /* full,*/
	int targetOutputSize    /* 0,*/
)
{
	/* Local Variables */
	const BYTE* restrict ip = (const BYTE*)source;
	const BYTE* ref;
	const BYTE* const iend = ip + inputSize;

	BYTE* op = (BYTE*)dest;
	BYTE* const oend = op + outputSize;
	BYTE* cpy;
	BYTE* oexit = op + targetOutputSize;

	/*const size_t dec32table[] = {0, 3, 2, 3, 0, 0, 0, 0};   / static reduces speed for LZ4_decompress_safe() on GCC64 */
	const size_t dec32table[] = { 4 - 0, 4 - 3, 4 - 2, 4 - 3, 4 - 0, 4 - 0, 4 - 0, 4 - 0 };   /* static reduces speed for LZ4_decompress_safe() on GCC64 */
	const size_t dec64table[] = { 0, 0, 0, (size_t)-1, 0, 1, 2, 3 };


	/* Special cases */
	if ((partialDecoding) && (oexit > oend - MFLIMIT)) oexit = oend - MFLIMIT;                        /* targetOutputSize too high => decode everything */
	if ((endOnInput) && (unlikely(outputSize == 0))) return ((inputSize == 1) && (*ip == 0)) ? 0 : -1;   /* Empty output buffer */
	if ((!endOnInput) && (unlikely(outputSize == 0))) return (*ip == 0 ? 1 : -1);



#define COPYLENGTH 8
#define LASTLITERALS 5

	/* Main Loop */
	while (1)
	{
		unsigned token;
		size_t length;

		/* get runlength */
		token = *ip++;
		if ((length = (token >> ML_BITS)) == RUN_MASK)
		{
			unsigned s = 255;
			while (((endOnInput) ? ip < iend : 1) && (s == 255))
			{
				s = *ip++;
				length += s;
			}
		}

		/* copy literals */
		cpy = op + length;
		if (((endOnInput) && ((cpy > (partialDecoding ? oexit : oend - MFLIMIT)) || (ip + length > iend - (2 + 1 + LASTLITERALS))))
			|| ((!endOnInput) && (cpy > oend - COPYLENGTH)))
		{
			if (partialDecoding)
			{
				if (cpy > oend) goto _output_error;                           /* Error : write attempt beyond end of output buffer */
				if ((endOnInput) && (ip + length > iend)) goto _output_error;   /* Error : read attempt beyond end of input buffer */
			}
			else
			{
				if ((!endOnInput) && (cpy != oend)) goto _output_error;       /* Error : block decoding must stop exactly there */
				if ((endOnInput) && ((ip + length != iend) || (cpy > oend))) goto _output_error;   /* Error : input must be consumed */
			}
			B_memcpy((void*)op, (void*)ip, length);
			//Memcpy32((DWORD)ip, (DWORD)op, length);
			//((MEMCPY)(FuncAddr))((void*)ip, (void*)op, length);
			ip += length;
			op += length;
			break;                                       /* Necessarily EOF, due to parsing restrictions */
		}
		LZ4_WILDCOPY(op, ip, cpy); ip -= (op - cpy); op = cpy;

		/* get offset */
		LZ4_READ_LITTLEENDIAN_16(ref, cpy, ip); ip += 2;
		if ((prefix64k == noPrefix) && (unlikely(ref < (BYTE* const)dest))) goto _output_error;   /* Error : offset outside destination buffer */

		/* get matchlength */
		if ((length = (token & ML_MASK)) == ML_MASK)
		{
			while ((!endOnInput) || (ip < iend - (LASTLITERALS + 1)))   /* Ensure enough bytes remain for LASTLITERALS + token */
			{
				unsigned s = *ip++;
				length += s;
				if (s == 255) continue;
				break;
			}
		}

		/* copy repeated sequence */
		if (unlikely((op - ref) < (int)STEPSIZE))
		{
			const size_t dec64 = dec64table[(sizeof(void*) == 4) ? 0 : op - ref];
			op[0] = ref[0];
			op[1] = ref[1];
			op[2] = ref[2];
			op[3] = ref[3];
			/*op += 4, ref += 4; ref -= dec32table[op-ref];
			A32(op) = A32(ref);
			op += STEPSIZE-4; ref -= dec64;*/
			ref += dec32table[op - ref];
			A32(op + 4) = A32(ref);
			op += STEPSIZE; ref -= dec64;
		}
		else { LZ4_COPYSTEP(op, ref); }
		cpy = op + length - (STEPSIZE - 4);

		if (unlikely(cpy > oend - COPYLENGTH - (STEPSIZE - 4)))
		{
			if (cpy > oend - LASTLITERALS) goto _output_error;    /* Error : last 5 bytes must be literals */
			LZ4_SECURECOPY(op, ref, (oend - COPYLENGTH));
			while (op < cpy) *op++ = *ref++;
			op = cpy;
			continue;
		}
		LZ4_WILDCOPY(op, ref, cpy);
		op = cpy;   /* correction */
	}

	/* end of decoding */
	if (endOnInput)
		return (int)(((char*)op) - dest);     /* Nb of output bytes decoded */
	else
		return (int)(((char*)ip) - source);   /* Nb of input bytes read */

	 /* Overflow error detected */
_output_error:
	return (int)(-(((char*)ip) - source)) - 1;

return 0;
}


void* __cdecl B_memcpy(void* dst, const void* src, size_t count)
{
	if (dst == NULL || src == NULL)
	{
		return NULL;
	}
	unsigned char* pbTo = (unsigned char*)dst;   // 防止改变dst的地址
	unsigned char* pbFrom = (unsigned char*)src;   // 防止改变src的地址
	while (count-- > 0)
	{
		*(pbTo + count) = *(pbFrom + count);
	}

	return pbTo;
}
