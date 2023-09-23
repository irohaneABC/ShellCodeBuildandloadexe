;命令行 ml64 /c %(filename).asm
;输出 %(filename).obj;%(Outputs)

;AddTowSum_64.asm
ExitProcess PROTO

public GetPc64

.code




GetPc64 proc

   ;mov rax,[rbp+40h]
   mov rax,[rsp]
   mov rbx,0FFFFFFFFFFFFF000h
   and rax,rbx
   ret

GetPc64 endp

ProcFunA PROC



ProcFunA endp



;是否被调试
Debug_PEBBegingDebug PROC

	xor rax,rax							;清除eax
	mov rax, gs:[60h];               ;获取PEB
    mov rax, [rax + 2h ]  ;获取Peb.BegingDebugged
    
Debug_PEBBegingDebug endp


;返回TEB
GetTeb64 PROC
    mov rax,gs:[30h]
    ret
GetTeb64 endp

;返回PEB
GetPeb64 PROC
    mov rax,gs:[60h]
    ret
GetPeb64 endp

;返回PEBLdr
GetPebLdr64 proc
    call GetPeb64
    add eax,18h
    mov eax,[eax]
    ret
GetPebLdr64 endp



; 返回 加载基址
GetImageBase64 proc

    mov rax, GS:[30h] 
    mov rax, [rax + 60h] 
    mov rax, [rax + 10h] 
    ret
GetImageBase64 endp


;返回Kernel32.dll
GetModuleBase64 proc

    push RSI
    mov RSI,gs:[60h]                ;esi = PEB地址
    mov RSI,[RSI+18h]              ;指向PEB_LDR_DATA 结构体
    mov RSI,[RSI+30h]              ;模块链表指针，InInit...List
    mov RAX,RSI
    pop RSI
    ret
GetModuleBase64 endp



;内存拷贝  des src size
Mymemcpy64 proc
    push rbp
    mov rbp,rsp
    sub rsp,50h

    push rcx
    push rdx
    mov rcx,r8
    pop rsi
    pop rdi
    
    rep movsb

    add rsp,50h
    mov rsp,rbp
    pop rbp

    ret
Mymemcpy64 endp

;设置内存为0
MySetMemZero64 proc

    mov rdi,rcx
    xor rax,rax
    mov rcx,r8
    cld
    rep stosb

MySetMemZero64 endp


end