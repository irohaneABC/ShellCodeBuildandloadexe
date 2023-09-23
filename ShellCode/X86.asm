
.386
.model flat, c
public GetPc32
;.data
 

.code                          ;此为代码区

							
GetPc32 PROC						;GetPc 获取的地址必须使用硬编码 这里只把 EAX 减去硬编码大小
	mov eax,[esp]
	and eax,0FFFFF000h
	ret
GetPc32 endp


GetImageBase32 PROC
	assume fs:nothing
	mov eax, fs:[30h]
	mov eax,[eax+08h]
	ret
GetImageBase32 endp

GetLdrModuleBase32 PROC					;LDR链表
	assume fs:nothing
	push esi
	mov esi, dword ptr fs : [30h]		; esi = PEB的地址
	mov esi, [esi + 0Ch]				 ; esi = 指向PEB_LDR_DATA结构的指针
	pop esi
	ret
GetLdrModuleBase32 endp

;获取Kernel32Base
GetKernel32Base32 PROC
	
	push esi
	assume fs:nothing
	mov esi, dword ptr fs : [30h]   ; esi = PEB的地址
	mov esi, [esi + 0Ch]            ; esi = 指向PEB_LDR_DATA结构的指针
	mov esi, [esi + 1Ch]            ; esi = 模块链表指针InInit...List
	mov esi, [esi]                   ; esi = 访问链表中的第二个条目
	mov esi, [esi + 08h]            ; esi = 获取Kernel32.dll基址（注1）
	mov eax, esi
	pop esi
	ret

GetKernel32Base32 endp


;内存拷贝
Memcpy32 PROC

	push ebp
	mov ebp,esp
	sub esp,50h

	mov ecx, [ebp+10h]	;	第三个参数大小
	mov esi, [ebp+0ch]	;	第二个参数 源地址
	mov edi, [ebp+8h]	;	第一个参数 目标地址
	rep movsb;

	add esp,50h
	mov esp,ebp
	pop ebp

	ret ;


Memcpy32 endp



;设置内存位0
SetMemZero32 PROC

	push ebp
	mov ebp,esp
	sub esp,50h

	mov edi,[ebp+8h]
	xor eax,eax
	mov ecx,[ebp+0ch]
	cld
	rep stosb

	add esp,50h
	mov esp,ebp
	pop ebp
	ret;

SetMemZero32 endp

;是否被调试
Debug_PEBBegingDebug PROC

	xor eax,eax							;清除eax
	mov eax, fs:[ 0x30 ];               ;获取PEB
    mov al, byte ptr ds : [eax + 0x2 ]  ;获取Peb.BegingDebugged
    
Debug_PEBBegingDebug endp


end