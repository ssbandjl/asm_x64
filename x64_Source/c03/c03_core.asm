;c03_core.asm:简易内核，李忠，2021-9-3

%include "..\common\global_defs.wid"

;===============================================================================
section core_header                               ;内核程序头部
  length       dd core_end                        ;#0：内核程序的总长度（字节数）
  init_entry   dd init                            ;#4：内核入口点
  position     dq 0                               ;#8：内核加载的虚拟（线性）地址

;===============================================================================
section core_data                                 ;内核数据段
  welcome      db "Executing in 64-bit mode.", 0x0d, 0x0a, 0

;===============================================================================
section core_code                                 ;内核代码段

%include "..\common\core_utils64.wid"             ;引入内核用到的例程

         bits 64

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
general_interrupt_handler:                        ;通用中断处理过程
         iretq

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
general_exception_handler:                        ;通用异常处理过程
                                                  ;在24行0列显示红底白字的错误信息
        mov r15, [rel position]
        lea rbx, [r15 + exceptm]
        mov dh, 24
        mov dl, 0
        mov r9b, 0x4f
        call put_cstringxy64                      ;位于core_utils64.wid

        cli
        hlt                                       ;停机且不接受外部硬件中断

  exceptm      db "A exception raised,halt.", 0   ;发生异常时的错误信息

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
general_8259ints_handler:                         ;通用的8259中断处理过程
         push rax

         mov al, 0x20                             ;中断结束命令EOI
         out 0xa0, al                             ;向从片发送
         out 0x20, al                             ;向主片发送

         pop rax

         iretq

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
init:    ;初始化内核的工作环境

         ;将GDT的线性地址映射到虚拟内存高端的相同位置。
         ;处理器不支持64位立即数到内存地址的操作，所以用两条指令完成。
         mov rax, UPPER_GDT_LINEAR                ;GDT的高端线性地址
         mov qword [SDA_PHY_ADDR + 4], rax        ;注意：必须是扩高地址

         lgdt [SDA_PHY_ADDR + 2]                  ;只有在64位模式下才能加载64位线性地址部分

         ;将栈映射到高端，否则，压栈时依然压在低端，并和低端的内容冲突。
         ;64位模式下不支持源操作数为64位立即数的加法操作。
         mov rax, 0xffff800000000000              ;或者加上UPPER_LINEAR_START
         add rsp,rax                              ;栈指针必须转换为高端地址且必须是扩高地址

         ;准备让处理器从虚拟地址空间的高端开始执行（现在依然在低端执行）
         mov rax, 0xffff800000000000              ;或者使用常量UPPER_LINEAR_START
         add [rel position], rax                  ;内核程序的起始位置数据也必须转换成扩高地址

         ;内核的起始地址 + 标号.to_upper的汇编地址 = 标号.to_upper所在位置的运行时扩高地址
         mov rax, [rel position]
         add rax, .to_upper
         jmp rax                                  ;绝对间接近转移，从此在高端执行后面的指令

  .to_upper:
         ;初始化中断描述符表IDT，并为32个异常以及224个中断安装门描述符

         ;为32个异常创建通用处理过程的中断门
         mov r9, [rel position]
         lea rax, [r9 + general_exception_handler];得到通用异常处理过程的线性地址
         call make_interrupt_gate                 ;位于core_utils64.wid

         xor r8, r8
  .idt0:
         call mount_idt_entry                     ;位于core_utils64.wid
         inc r8
         cmp r8, 31
         jle .idt0

         ;创建并安装对应于其它中断的通用处理过程的中断门
         lea rax, [r9 + general_interrupt_handler];得到通用中断处理过程的线性地址
         call make_interrupt_gate                 ;位于core_utils64.wid

         mov r8, 32
  .idt1:
         call mount_idt_entry                     ;位于core_utils64.wid
         inc r8
         cmp r8, 255
         jle .idt1

         mov rax, UPPER_IDT_LINEAR                ;中断描述符表IDT的高端线性地址
         mov rbx, UPPER_SDA_LINEAR                ;系统数据区SDA的高端线性地址
         mov qword [rbx + 0x0e], rax
         mov word [rbx + 0x0c], 256 * 16 - 1

         lidt [rbx + 0x0c]                        ;只有在64位模式下才能加载64位线性地址部分

         ;初始化8259中断控制器，包括重新设置中断向量号
         call init_8259

         ;创建并安装16个8259中断处理过程的中断门，向量0x20--0x2f
         lea rax, [r9 + general_8259ints_handler] ;得到通用8259中断处理过程的线性地址
         call make_interrupt_gate                 ;位于core_utils64.wid

         mov r8, 0x20
  .8259:
         call mount_idt_entry                     ;位于core_utils64.wid
         inc r8
         cmp r8, 0x2f
         jle .8259

         sti                                      ;开放硬件中断

         ;在64位模式下显示的第一条信息!
         mov r15, [rel position]
         lea rbx, [r15 + welcome]
         call put_string64                        ;位于core_utils64.wid

  .halt:
        hlt
        jmp .halt


;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
core_end:
