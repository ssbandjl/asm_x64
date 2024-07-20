;c03_mbr.asm
;主引导扇区程序
;2021-08-31，李忠

;-------------------------------------------------------------------------------
%include "..\common\global_defs.wid"
;-------------------------------------------------------------------------------
SECTION  mbr  vstart=0x00007c00
         xor ax, ax
         mov ds, ax
         mov es, ax
         mov ss, ax
         mov sp, 0x7c00

         ;以下从硬盘逻辑1扇区装入内核加载器
         push dword 0
         push dword LDR_START_SECTOR                  ;传输的起始逻辑扇区号（1)
         push word LDR_PHY_ADDR >> 4                  ;压入缓冲区的逻辑段地址
         push word 0                                  ;压入缓冲区的起始偏移量
         push word 0x0001                             ;传输的扇区数
         push word 0x0010                             ;地址结构尺寸及保留字节
         mov si, sp
         mov ah, 0x42                                 ;INT 13H扩展读功能
         mov dl, 0x80                                 ;主盘
         int 0x13                                     ;成功则CF=0,AH=0；失败则CF=1且AH=错误代码
         mov bp, msg0
         mov di, msg1 - msg0
         jc go_err                                    ;读磁盘失败，显示信息并停机

         push ds

         mov cx, LDR_PHY_ADDR >> 4                    ;切换到加载器所在的段地址
         mov ds, cx

         cmp dword [0], 'lizh'                        ;检查加载器有效标志
         mov bp, msg1
         mov di, mend - msg1
         jnz go_err                                   ;加载器不存在，显示信息并停机

         ;以下判断整个程序有多大
         mov eax, [4]                                 ;核心程序尺寸
         xor edx, edx
         mov ecx, 512                                 ;512字节每扇区
         div ecx

         or edx, edx
         jnz @1                                       ;未除尽，因此结果比实际扇区数少1
         dec eax                                      ;已经读了一个扇区，扇区总数减1
   @1:
         or eax, eax                                  ;考虑实际长度≤512个字节的情况
         jz go_ldr                                    ;EAX=0 ?

         ;读取剩余的扇区
         pop ds                                       ;为传递磁盘地址结构做准备

         mov word [si + 2], ax                        ;重新设置要读取的逻辑扇区数
         mov word [si + 4], 512                       ;重新设置下一个段内偏移量
         inc dword [si + 8]                           ;起始逻辑扇区号加一
         mov ah, 0x42                                 ;INT 13H扩展读功能
         mov dl, 0x80                                 ;主盘
         int 0x13                                     ;成功则CF=0,AH=0；失败则CF=1且AH=错误代码

         mov bp, msg0
         mov di, msg1 - msg0
         jc go_err                                    ;读磁盘失败，显示信息并停机

  go_ldr:
         mov sp, 0x7c00                               ;恢复栈的初始状态

         mov ax, LDR_PHY_ADDR >> 4
         mov ds, ax
         mov es, ax

         push ds
         push word [8]
         retf                                         ;进入加载器执行

  go_err:
         mov ah, 0x03                                 ;获取光标位置
         mov bh, 0x00
         int 0x10

         mov cx, di
         mov ax, 0x1301                               ;写字符串，光标移动
         mov bh, 0
         mov bl, 0x07                                 ;属性：常规黑底白字
         int 0x10                                     ;显示字符串

         cli
         hlt

;-------------------------------------------------------------------------------
         msg0             db "Disk error.",0x0d,0x0a
         msg1             db "Missing loader.",0x0d,0x0a
         mend:
;-------------------------------------------------------------------------------
         times 510-($-$$) db 0
                          db 0x55,0xaa
