;c03_ldr.asm:内核加载器，李忠，2021-7-18
;-------------------------------------------------------------------------------
%include "..\common\global_defs.wid"
;===============================================================================
section loader
  marker       dd "lizh"                              ;内核加载器有效标志  +00
  length       dd ldr_end                             ;内核加载器的长度    +04
  entry        dd start                               ;内核加载器的入口点  +08

  msg0         db "MouseHero x64 course learning.",0x0d,0x0a

  arch0        db "x64 available(64-bit processor installed).",0x0d,0x0a
  arch1        db "x64 not available(64-bit processor not installed).",0x0d,0x0a

  brand_msg    db "Processor:"
      brand    times 48  db 0
               db  0x0d,0x0a

  cpu_addr     db "Physical address size:"
     paddr     times 3 db ' '
               db ","
               db "Linear address size:"
     laddr     times 3 db ' '
               db 0x0d,0x0a

  protect      db "Protect mode has been entered to prepare for IA-32e mode.",0x0d,0x0a,0

  ia_32e       db "IA-32e mode(aka,long mode) is active.Specifically,"
               db "compatibility mode.",0x0d,0x0a,0
;-------------------------------------------------------------------------
 no_ia_32e:
         mov ah, 0x03                                 ;获取光标位置
         mov bh, 0x00
         int 0x10

         mov bp, arch1
         mov cx, brand_msg - arch1
         mov ax, 0x1301                               ;写字符串，光标移动
         mov bh, 0
         mov bl, 0x07                                 ;属性：红底亮白字
         int 0x10                                     ;显示字符串

         cli
         hlt

  start:
         mov ah, 0x03                                 ;获取光标位置
         mov bh, 0x00
         int 0x10

         mov bp, msg0
         mov cx, arch0 - msg0
         mov ax, 0x1301                               ;写字符串，光标移动
         mov bh, 0
         mov bl, 0x4f                                 ;属性：红底亮白字
         int 0x10                                     ;显示字符串

         mov eax, 0x80000000                          ;返回处理器支持的最大扩展功能号
         cpuid
         cmp eax, 0x80000000                          ;支持大于0x80000000的功能号？
         jbe no_ia_32e                                ;不支持，转no_ia_32e处执行

         mov eax, 0x80000001                          ;返回扩展的签名和特性标志位
         cpuid                                        ;EDX包含扩展特性标志位
         bt edx, 29                                   ;EDX的位29是IA-32e模式支持标志
         ;注意：在VirtualBox虚拟机上，操作系统的版本如果不选择64位，则此标志检测失败。
         jnc no_ia_32e                                ;不支持，转no_ia_32e处执行

         mov ah, 0x03                                 ;获取光标位置
         mov bh, 0x00
         int 0x10

         mov bp, arch0
         mov cx, arch1 - arch0
         mov ax, 0x1301                               ;写字符串，光标移动
         mov bh, 0
         mov bl, 0x07                                 ;属性：黑底白字
         int 0x10                                     ;显示字符串

         ;显示处理器商标信息
         mov eax, 0x80000000
         cpuid                                        ;返回最大支持的扩展功能号
         cmp eax, 0x80000004
         jb .no_brand

         mov eax, 0x80000002
         cpuid
         mov [brand + 0x00], eax
         mov [brand + 0x04], ebx
         mov [brand + 0x08], ecx
         mov [brand + 0x0c], edx

         mov eax, 0x80000003
         cpuid
         mov [brand + 0x10], eax
         mov [brand + 0x14], ebx
         mov [brand + 0x18], ecx
         mov [brand + 0x1c], edx

         mov eax, 0x80000004
         cpuid
         mov [brand + 0x20], eax
         mov [brand + 0x24], ebx
         mov [brand + 0x28], ecx
         mov [brand + 0x2c], edx

         mov ah, 0x03                                 ;获取光标位置
         mov bh, 0x00
         int 0x10

         mov bp, brand_msg
         mov cx, cpu_addr - brand_msg
         mov ax, 0x1301                               ;写字符串，光标移动
         mov bh, 0
         mov bl, 0x07                                 ;属性：黑底白字
         int 0x10                                     ;显示字符串

 .no_brand:
         ;获取当前系统的物理内存布局信息（使用INT 0x15,E820功能。俗称E820内存）
         push es

         mov bx, SDA_PHY_ADDR >> 4                    ;切换到系统数据区
         mov es, bx
         mov word [es:0x16], 0
         xor ebx, ebx                                 ;首次调用int 0x15时必须为0
         mov di, 0x18                                 ;系统数据区内的偏移
 .mlookup:
         mov eax, 0xe820
         mov ecx, 32
         mov edx, 'PAMS'
         int 0x15
         add di, 32
         inc word [es:0x16]
         or ebx, ebx
         jnz .mlookup

         pop es

         ;获取和存储处理器的物理/虚拟地址尺寸信息
         mov eax, 0x80000000                          ;返回最大支持的扩展功能号
         cpuid
         cmp eax, 0x80000008
         mov ax, 0x3024                               ;设置默认的处理器物理/逻辑地址位数36和48
         jb .no_plsize

         mov eax,0x80000008                           ;处理器线性/物理地址尺寸
         cpuid

 .no_plsize:
         ;保存物理和虚拟地址尺寸到系统数据区
         push ds
         mov bx, SDA_PHY_ADDR >> 4                    ;切换到系统数据区
         mov ds, bx
         mov word [0], ax                             ;记录处理器的物理/虚拟地址尺寸
         pop ds

         ;准备显示存储器的物理地址尺寸信息
         push ax                                      ;备份AX（中的虚拟地址部分）

         and ax, 0x00ff                               ;保留物理地址宽度部分
         mov si, 2
         mov bl, 10
 .re_div0:
         div bl
         add ah, 0x30
         mov [paddr + si], ah
         dec si
         and ax, 0x00ff
         jnz .re_div0

         ;准备显示处理器的虚拟地址尺寸信息
         pop ax

         shr ax, 8                                    ;保留线性地址宽度部分
         mov si, 2
         mov bl, 10
 .re_div1:
         div bl
         add ah, 0x30
         mov [laddr + si], ah
         dec si
         and ax, 0x00ff
         jnz .re_div1

         ;显示处理器的物理/虚拟地址尺寸信息
         mov ah, 0x03                                 ;获取光标位置
         mov bh, 0x00
         int 0x10

         mov bp, cpu_addr
         mov cx, protect - cpu_addr
         mov ax, 0x1301                               ;写字符串，光标移动
         mov bh, 0
         mov bl, 0x07                                 ;属性：黑底白字
         int 0x10                                     ;显示字符串

         ;以下开始进入保护模式，为IA-32e模式做必要的准备工作
         mov ax, GDT_PHY_ADDR >> 4                    ;计算GDT所在的逻辑段地址
         mov ds, ax

         ;跳过0#号描述符的槽位
         ;创建1#描述符，保护模式下的代码段描述符
         mov dword [0x08], 0x0000ffff                 ;基地址为0，界限0xFFFFF，DPL=00
         mov dword [0x0c], 0x00cf9800                 ;4KB粒度，代码段描述符，向上扩展

         ;创建2#描述符，保护模式下的数据段和堆栈段描述符
         mov dword [0x10], 0x0000ffff                 ;基地址为0，界限0xFFFFF，DPL=00
         mov dword [0x14], 0x00cf9200                 ;4KB粒度，数据段描述符，向上扩展

         ;创建3#描述符，64位模式下的代码段描述符。为进入64位提前作准备，其L位是1
         mov dword [0x18], 0x0000ffff                 ;基地址为0，界限0xFFFFF，DPL=00
         mov dword [0x1c], 0x00af9800                 ;4KB粒度，L=1，代码段描述符，向上扩展


         ;记录GDT的基地址和界限值
         mov ax, SDA_PHY_ADDR >> 4                    ;切换到系统数据区
         mov ds, ax

         mov word [2], 31                             ;描述符表的界限
         mov dword [4], GDT_PHY_ADDR                  ;GDT的线性基地址

         ;加载描述符表寄存器GDTR
         lgdt [2]

         in al, 0x92                                  ;南桥芯片内的端口
         or al, 0000_0010B
         out 0x92, al                                 ;打开A20

         cli                                          ;中断机制尚未工作

         mov eax, cr0
         or eax, 1
         mov cr0, eax                                 ;设置PE位

         ;以下进入保护模式... ...
         jmp 0x0008: dword LDR_PHY_ADDR + flush       ;16位的描述符选择子：32位偏移
                                                      ;清流水线并串行化处理器
         [bits 32]
  flush:
         mov eax, 0x0010                              ;加载数据段(4GB)选择子
         mov ds, eax
         mov es, eax
         mov fs, eax
         mov gs, eax
         mov ss, eax                                  ;加载堆栈段(4GB)选择子
         mov esp, 0x7c00                              ;堆栈指针

         ;显示信息，表明我们正在保护模式下为进入IA-32e模式做准备
         mov ebx, protect + LDR_PHY_ADDR
         call put_string_flat32

         ;以下加载系统核心程序
         mov edi, CORE_PHY_ADDR

         mov eax, COR_START_SECTOR
         mov ebx, edi                                 ;起始地址
         call read_hard_disk_0                        ;以下读取程序的起始部分（一个扇区）

         ;以下判断整个程序有多大
         mov eax, [edi]                               ;核心程序尺寸
         xor edx, edx
         mov ecx, 512                                 ;512字节每扇区
         div ecx

         or edx, edx
         jnz @1                                       ;未除尽，因此结果比实际扇区数少1
         dec eax                                      ;已经读了一个扇区，扇区总数减1
   @1:
         or eax, eax                                  ;考虑实际长度≤512个字节的情况
         jz pge                                       ;EAX=0 ?

         ;读取剩余的扇区
         mov ecx, eax                                 ;32位模式下的LOOP使用ECX
         mov eax, COR_START_SECTOR
         inc eax                                      ;从下一个逻辑扇区接着读
   @2:
         call read_hard_disk_0
         inc eax
         loop @2                                      ;循环读，直到读完整个内核

   pge:
         ;回填内核加载的位置信息（物理/线性地址）到内核程序头部
         mov dword [CORE_PHY_ADDR + 0x08], CORE_PHY_ADDR
         mov dword [CORE_PHY_ADDR + 0x0c], 0

         ;准备打开分页机制。先确定分页模式（4级或者5级）
         ;cmp [sda_phy_addr],57                        ;要求使用5级分页吗？
         ;jz to_5level_page                            ;转5级分页代码

         ;以下为内核创建4级分页系统，只包含基本部分，覆盖低端1MB物理内存

         ;>>>>>>>>>>>>>>>>>>>>>>>>>1.创建内核4级头表>>>>>>>>>>>>>>>>>>>>>>>>>>
         mov ebx, PML4_PHY_ADDR                       ;4级头表的物理地址

         ;4级头表的内容清零
         mov ecx, 1024
         xor esi, esi
   .cls0:
         mov dword [ebx + esi], 0
         add esi, 4
         loop .cls0

         ;在4级头表内创建指向4级头表自己的表项
         mov dword [ebx + 511 * 8], PML4_PHY_ADDR | 3 ;添加属性位
         mov dword [ebx + 511 * 8 + 4], 0

         ;在4级头表内创建与低端2MB内存对应的4级头表项。
         ;即，与线性地址范围：0x0000000000000000--0x00000000001FFFFF对应的4级头表项
         ;此表项为保证低端2MB物理内存（含内核）在开启分页之后及映射到高端之前可正常访问
         mov dword [ebx + 0 * 8], PDPT_PHY_ADDR | 3   ;页目录指针表的物理地址及属性
         mov dword [ebx + 0 * 8 + 4], 0

         ;将页目录指针表的内容清零
         mov ebx, PDPT_PHY_ADDR

         mov ecx, 1024
         xor esi, esi
   .cls1:
         mov dword [ebx + esi], 0
         add esi, 4
         loop .cls1

         ;在页目录指针表内创建与低端2MB内存对应的表项。
         ;即，与线性地址范围：0x0000000000000000--0x00000000001FFFFF对应的表项
         mov dword [ebx + 0 * 8], PDT_PHY_ADDR | 3    ;页目录表的物理地址及属性
         mov dword [ebx + 0 * 8 + 4], 0

         ;将页目录表的内容清零
         mov ebx, PDT_PHY_ADDR

         mov ecx, 1024
         xor esi, esi
   .cls2:
         mov dword [ebx + esi], 0
         add esi, 4
         loop .cls2

         ;在页目录表内创建与低端2MB内存对应的表项。
         ;即，与线性地址范围：0x0000000000000000--0x00000000001FFFFF对应的表项
         mov dword [ebx + 0 * 8], 0 | 0x83            ;2MB页的物理地址及属性
         mov dword [ebx + 0 * 8 + 4], 0


         ;在4级头表内创建与线性地址范围0xFFFF800000000000--0xFFFF8000001FFFFF对应的
         ;4级头表项，将内核映射到高端。内核进入IA-32e模式后应当工作在线性地址高端。
         mov ebx, PML4_PHY_ADDR

         mov dword [ebx + 256 * 8], PDPT_PHY_ADDR | 3 ;页目录指针表的物理地址及属性
         mov dword [ebx + 256 * 8 + 4], 0

         ;在4级头表的高一半预先创建额外的254个头表项
         mov eax, 257
         mov edx, COR_PDPT_ADDR | 3                   ;从这个地址开始是内核的254个页目录指针表
   .fill_pml4:
         mov dword [ebx + eax * 8], edx
         mov dword [ebx + eax * 8 + 4], 0
         add edx, 0x1000
         inc eax
         cmp eax, 510
         jbe .fill_pml4

         ;将预分配的所有页目录指针表都统统清零
         mov eax, COR_PDPT_ADDR
   .zero_pdpt:
         mov dword [eax], 0                           ;相当于将所有页目录指针项清零
         add eax, 4
         cmp eax, COR_PDPT_ADDR + 0x1000 * 254        ;内核所有页目录指针表的结束位置
         jb .zero_pdpt

         ;令CR3寄存器指向4级头表（保护模式下的32位CR3）
         mov eax, PML4_PHY_ADDR                       ;PCD=PWT=0
         mov cr3, eax

         ;开启物理地址扩展PAE
         mov eax, cr4
         bts eax, 5
         mov cr4, eax

         ;设置型号专属寄存器IA32_EFER.LME，允许IA_32e模式
         mov ecx, 0x0c0000080                         ;指定型号专属寄存器IA32_EFER
         rdmsr
         bts eax, 8                                   ;设置LME位
         wrmsr

         ;开启分页功能
         mov eax, cr0
         bts eax, 31                                  ;置位CR0.PG
         mov cr0, eax

         ;打印IA_32e激活信息
         mov ebx, ia_32e + LDR_PHY_ADDR
         call put_string_flat32

         ;通过远返回方式进入64位模式的内核
         push word 0x0018                             ;已定义为常量CORE_CODE64_SEL
         mov eax, dword [CORE_PHY_ADDR + 4]
         add eax, CORE_PHY_ADDR
         push eax
         retf

;-----------------------------------------------------------------------
;带光标跟随的字符串显示例程。只运行在32位保护模式下，且使用平坦模型。
put_string_flat32:                                    ;显示0终止的字符串并移动光标
                                                      ;输入：EBX=字符串的线性地址

         push ebx
         push ecx

  .getc:
         mov cl, [ebx]
         or cl, cl                                    ;检测串结束标志（0）
         jz .exit                                     ;显示完毕，返回
         call put_char
         inc ebx
         jmp .getc

  .exit:
         pop ecx
         pop ebx

         ret                                          ;段内返回

;-------------------------------------------------------------------------------
put_char:                                             ;在当前光标处显示一个字符,并推进光标。
                                                      ;仅用于段内调用
                                                      ;输入：CL=字符ASCII码
         pushad

         ;以下取当前光标位置
         mov dx, 0x3d4
         mov al, 0x0e
         out dx, al
         inc dx                                       ;0x3d5
         in al, dx                                    ;高字
         mov ah, al

         dec dx                                       ;0x3d4
         mov al, 0x0f
         out dx, al
         inc dx                                       ;0x3d5
         in al, dx                                    ;低字
         mov bx, ax                                   ;BX=代表光标位置的16位数
         and ebx, 0x0000ffff                          ;准备使用32位寻址方式访问显存

         cmp cl, 0x0d                                 ;回车符？
         jnz .put_0a
         mov ax, bx
         mov bl, 80
         div bl
         mul bl
         mov bx, ax
         jmp .set_cursor

  .put_0a:
         cmp cl, 0x0a                                 ;换行符？
         jnz .put_other
         add bx, 80
         jmp .roll_screen

  .put_other:                                         ;正常显示字符
         shl bx, 1
         mov [0xb8000 + ebx], cl

         ;以下将光标位置推进一个字符
         shr bx, 1
         inc bx

  .roll_screen:
         cmp bx, 2000                                 ;光标超出屏幕？滚屏
         jl .set_cursor

         push ebx

         cld
         mov esi, 0xb80a0                             ;小心！32位模式下movsb/w/d
         mov edi, 0xb8000                             ;使用的是esi/edi/ecx
         mov ecx, 960
         rep movsd
         mov ebx, 3840                                ;清除屏幕最底一行
         mov ecx, 80                                  ;32位程序应该使用ECX
  .cls:
         mov word[0xb8000 + ebx], 0x0720
         add ebx, 2
         loop .cls

         pop ebx
         sub ebx, 80

  .set_cursor:
         mov dx, 0x3d4
         mov al, 0x0e
         out dx, al
         inc dx                                       ;0x3d5
         mov al, bh
         out dx, al
         dec dx                                       ;0x3d4
         mov al, 0x0f
         out dx, al
         inc dx                                       ;0x3d5
         mov al, bl
         out dx, al

         popad

         ret
;-------------------------------------------------------------------------
read_hard_disk_0:                                     ;从硬盘读取一个逻辑扇区
                                                      ;EAX=逻辑扇区号
                                                      ;EBX=目标缓冲区地址
                                                      ;返回：EBX=EBX+512
         push eax
         push ecx
         push edx

         push eax

         mov dx, 0x1f2
         mov al, 1
         out dx, al                                   ;读取的扇区数

         inc dx                                       ;0x1f3
         pop eax
         out dx, al                                   ;LBA地址7~0

         inc dx                                       ;0x1f4
         mov cl, 8
         shr eax, cl
         out dx, al                                   ;LBA地址15~8

         inc dx                                       ;0x1f5
         shr eax, cl
         out dx, al                                   ;LBA地址23~16

         inc dx                                       ;0x1f6
         shr eax, cl
         or al, 0xe0                                  ;第一硬盘  LBA地址27~24
         out dx, al

         inc dx
                                                      ;0x1f7
         mov al, 0x20                                 ;读命令
         out dx, al

  .waits:
         in al, dx
         test al, 8
         jz .waits                                   ;不忙，且硬盘已准备好数据传输

         mov ecx, 256                                 ;总共要读取的字数
         mov dx, 0x1f0
  .readw:
         in ax, dx
         mov [ebx], ax
         add ebx, 2
         loop .readw

         pop edx
         pop ecx
         pop eax

         ret

;-------------------------------------------------------------------------------
section trail
  ldr_end:
