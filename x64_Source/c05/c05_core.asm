;c05_core.asm:支持多处理器和高级可编程中断控制器的内核
;李忠，2020-7-6

%include "..\common\global_defs.wid"

;===============================================================================
section core_header                               ;内核程序头部
  length       dd core_end                        ;#0：内核程序的总长度（字节数）
  init_entry   dd init                            ;#4：内核入口点
  position     dq 0                               ;#8：内核加载的虚拟（线性）地址

;===============================================================================
section core_data                                 ;内核数据段
  acpi_error    db "ACPI is not supported or data error.", 0x0d, 0x0a, 0

  num_cpus     db 0                               ;逻辑处理器数量
  cpu_list     times 256 db 0                     ;Local APIC ID的列表
  lapic_addr   dd 0                               ;Local APIC的物理地址

  ioapic_addr  dd 0                               ;I/O APIC的物理地址
  ioapic_id    db 0                               ;I/O APIC ID

  clocks_1ms   dd 0                               ;处理器在1ms内经历的时钟数

  welcome      db "Executing in 64-bit mode.", 0x0d, 0x0a, 0
  tss_ptr      dq 0                               ;任务状态段TSS从此处开始

  sys_entry    dq get_screen_row
               dq get_cmos_time
               dq put_cstringxy64
               dq create_process
               dq get_current_pid
               dq terminate_process

  pcb_ptr      dq 0                               ;进程控制块PCB首节点的线性地址
  cur_pcb      dq 0                               ;当前任务的PCB线性地址

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
         call put_cstringxy64                     ;位于core_utils64.wid

         cli
         hlt                                      ;停机且不接受外部硬件中断

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
rtm_interrupt_handle:                             ;实时时钟中断处理过程（任务切换）
         push r8
         push rax
         push rbx

         ;mov al, 0x20                             ;中断结束命令EOI
         ;out 0xa0, al                             ;向8259A从片发送
         ;out 0x20, al                             ;向8259A主片发送

         mov al, 0x0c                             ;寄存器C的索引。且开放NMI
         out 0x70, al
         in al, 0x71                              ;读一下RTC的寄存器C，否则只发生一次中断
                                                  ;此处不考虑闹钟和周期性中断的情况

         ;除非是NMI、SMI、INIT、ExtINT、SIPI或者INIT-Deassert引发的中断，中断处理过程必须
         ;包含一条写EOI寄存器的指令
         mov r8, LAPIC_START_ADDR                ;给Local APIC发送中断结束命令EOI
         mov dword [r8 + 0xb0], 0

         ;以下开始执行任务切换
         ;任务切换的原理是，它发生在所有任务的全局空间。在任务A的全局空间执行任务
         ;切换，切换到任务B，实际上也是从任务B的全局空间返回任务B的私有空间。

         ;从PCB链表中寻找就绪的任务。
         mov r8, [rel cur_pcb]                    ;定位到当前任务的PCB节点
         cmp r8, 0                                ;系统中尚未确立当前任务？
         jz .return                               ;是。未找到就绪任务（节点），返回
  .again:
         mov r8, [r8 + 280]                       ;取得下一个节点
         cmp r8, [rel cur_pcb]                    ;是否转一圈回到当前节点？
         jz .return                               ;是。未找到就绪任务（节点），返回
         cmp qword [r8 + 16], 0                   ;是就绪任务（节点）？
         jz .found                                ;是。转任务切换
         jmp .again

  .found:
         mov rax, [rel cur_pcb]                   ;取得当前任务的PCB（线性地址）
         cmp qword [rax + 16], 2                  ;当前任务有可能已经被标记为终止。
         jz .restore

         ;保存当前任务的状态以便将来恢复执行
         mov rbx, cr3
         mov [rax + 56], rbx

         mov qword [rax + 16], 0                  ;置任务状态为就绪
         ;mov [rax + 64], rax                     ;不需设置，将来恢复执行时从栈中弹出
         ;mov [rax + 72], rbx                     ;不需设置，将来恢复执行时从栈中弹出
         mov [rax + 80], rcx
         mov [rax + 88], rdx
         mov [rax + 96], rsi
         mov [rax + 104], rdi
         mov [rax + 112], rbp
         mov [rax + 120], rsp
         ;mov [rax + 128], r8                     ;不需设置，将来恢复执行时从栈中弹出
         mov [rax + 136], r9
         mov [rax + 144], r10
         mov [rax + 152], r11
         mov [rax + 160], r12
         mov [rax + 168], r13
         mov [rax + 176], r14
         mov [rax + 184], r15
         mov rbx, [rel position]
         lea rbx, [rbx + .return]
         mov [rax + 192], rbx                     ;RIP为中断返回点
         mov [rax + 200], cs
         mov [rax + 208], ss
         pushfq
         pop qword [rax + 232]

  .restore:
         ;恢复新任务的状态
         mov [rel cur_pcb], r8                    ;将新任务设置为当前任务
         mov qword [r8 + 16], 1                   ;置任务状态为忙

         mov rax, [r8 + 32]                       ;取PCB中的RSP0
         mov rbx, [rel tss_ptr]
         mov [rbx + 4], rax                       ;置TSS的RSP0

         mov rax, [r8 + 56]
         mov cr3, rax                             ;切换地址空间

         mov rax, [r8 + 64]
         mov rbx, [r8 + 72]
         mov rcx, [r8 + 80]
         mov rdx, [r8 + 88]
         mov rsi, [r8 + 96]
         mov rdi, [r8 + 104]
         mov rbp, [r8 + 112]
         mov rsp, [r8 + 120]
         mov r9, [r8 + 136]
         mov r10, [r8 + 144]
         mov r11, [r8 + 152]
         mov r12, [r8 + 160]
         mov r13, [r8 + 168]
         mov r14, [r8 + 176]
         mov r15, [r8 + 184]
         push qword [r8 + 208]                    ;SS
         push qword [r8 + 120]                    ;RSP
         push qword [r8 + 232]                    ;RFLAGS
         push qword [r8 + 200]                    ;CS
         push qword [r8 + 192]                    ;RIP

         mov r8, [r8 + 128]                       ;恢复R8的值

         iretq                                    ;转入新任务局部空间执行

  .return:
         pop rbx
         pop rax
         pop r8

         iretq

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
append_to_pcb_link:                               ;在PCB链上追加任务控制块
                                                  ;输入：R11=PCB线性基地址
         push rax
         push rbx

         cli

         mov rbx, [rel pcb_ptr]                   ;取得链表首节点的线性地址
         or rbx, rbx
         jnz .not_empty                           ;链表非空，转.not_empty
         mov [r11], r11                           ;唯一的节点：前驱是自己
         mov [r11 + 280], r11                     ;后继也是自己
         mov [rel pcb_ptr], r11                   ;这是头节点
         jmp .return

  .not_empty:
         mov rax, [rbx]                           ;取得头节点的前驱节点的线性地址
         ;此处，RBX=头节点；RAX=头节点的前驱节点；R11=追加的节点
         mov [rax + 280], r11                     ;前驱节点的后继是追加的节点
         mov [r11 + 280], rbx                     ;追加的节点的后继是头节点
         mov [r11], rax                           ;追加的节点的前驱是头节点的前驱
         mov [rbx], r11                           ;头节点的前驱是追加的节点

  .return:
         sti

         pop rbx
         pop rax

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
get_current_pid:                                  ;返回当前任务（进程）的标识
         mov rax, [rel cur_pcb]
         mov rax, [rax + 8]

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
terminate_process:                                ;终止当前任务
         cli                                      ;执行流改变期间禁止时钟中断引发的任务切换

         mov rax, [rel cur_pcb]                   ;定位到当前任务的PCB节点
         mov qword [rax + 16], 2                  ;状态=终止

         jmp rtm_interrupt_handle                 ;强制任务调度，交还处理器控制权

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
create_process:                                   ;创建新的任务
                                                  ;输入：R8=程序的起始逻辑扇区号
         push rax
         push rbx
         push rcx
         push rdx
         push rsi
         push rdi
         push rbp
         push r8
         push r9
         push r10
         push r11
         push r12
         push r13
         push r14
         push r15

         ;首先在地址空间的高端（内核）创建任务控制块PCB
         mov rcx, 512                             ;任务控制块PCB的尺寸
         call core_memory_allocate                ;在虚拟地址空间的高端（内核）分配内存

         mov r11, r13                             ;以下，R11专用于保存PCB线性地址

         mov qword [r11 + 24], USER_ALLOC_START   ;填写PCB的下一次可分配线性地址域

         ;从当前活动的4级头表复制并创建新任务的4级头表。
         call copy_current_pml4
         mov [r11 + 56], rax                      ;填写PCB的CR3域，默认PCD=PWT=0

         ;以下，切换到新任务的地址空间，并清空其4级头表的前半部分。不过没有关系，
         ;我们正在地址空间的高端执行，可正常执行内核代码并访问内核数据，毕竟所有
         ;任务的高端（全局）部分都相同。同时，当前使用的栈位于地址空间高端的栈。
         mov r15, cr3                             ;保存控制寄存器CR3的值
         mov cr3, rax                             ;切换到新4级头表映射的新地址空间

         ;清空当前4级头表的前半部分（对应于任务的局部地址空间）
         mov rax, 0xffff_ffff_ffff_f000           ;当前活动4级头表自身的线性地址
         mov rcx, 256
  .clsp:
         mov qword [rax], 0
         add rax, 8
         loop .clsp

         mov rax, cr3                             ;刷新TLB
         mov cr3, rax

         mov rcx, 4096 * 16                       ;为TSS的RSP0开辟栈空间
         call core_memory_allocate                ;必须是在内核的空间中开辟
         mov [r11 + 32], r14                      ;填写PCB中的RSP0域的值

         mov rcx, 4096 * 16                       ;为用户程序开辟栈空间
         call user_memory_allocate
         mov [r11 + 120], r14                     ;用户程序执行时的RSP。

         mov qword [r11 + 16], 0                  ;任务状态=就绪

         ;以下开始加载用户程序
         mov rcx, 512                             ;在私有空间开辟一个缓冲区
         call user_memory_allocate
         mov rbx, r13
         mov rax, r8                              ;用户程序起始扇区号
         call read_hard_disk_0

         mov [r13 + 16], r13                      ;在程序中填写它自己的起始线性地址
         mov r14, r13
         add r14, [r13 + 8]
         mov [r11 + 192], r14                     ;在PCB中登记程序的入口点线性地址

         ;以下判断整个程序有多大
         mov rcx, [r13]                           ;程序尺寸
         test rcx, 0x1ff                          ;能够被512整除吗？
         jz .y512
         shr rcx, 9                               ;不能？凑整。
         shl rcx, 9
         add rcx, 512
  .y512:
         sub rcx, 512                             ;减去已经读的一个扇区长度
         jz .rdok
         call user_memory_allocate
         ;mov rbx, r13
         shr rcx, 9                               ;除以512，还需要读的扇区数
         inc rax                                  ;起始扇区号
  .b1:
         call read_hard_disk_0
         inc rax
         loop .b1                                 ;循环读，直到读完整个用户程序

  .rdok:
         mov qword [r11 + 200], USER_CODE64_SEL   ;新任务的代码段选择子
         mov qword [r11 + 208], USER_STACK64_SEL  ;新任务的栈段选择子

         pushfq
         pop qword [r11 + 232]

         call generate_process_id
         mov [r11 + 8], rax                       ;记录当前任务的标识

         call append_to_pcb_link                  ;将PCB添加到进程控制块链表尾部

         mov cr3, r15                             ;切换到原任务的地址空间

         pop r15
         pop r14
         pop r13
         pop r12
         pop r11
         pop r10
         pop r9
         pop r8
         pop rbp
         pop rdi
         pop rsi
         pop rdx
         pop rcx
         pop rbx
         pop rax

         ret
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
syscall_procedure:                                ;系统调用的处理过程
         ;RCX和R11由处理器使用，保存RIP和RFLAGS的内容；RBP和R15由此例程占用。如
         ;有必要，请用户程序在调用syscall前保存它们，在系统调用返回后自行恢复。
         mov rbp, rsp
         mov r15, [rel tss_ptr]
         mov rsp, [r15 + 4]                       ;使用TSS的RSP0作为安全栈

         sti

         mov r15, [rel position]
         add r15, [r15 + rax * 8 + sys_entry]
         call r15

         cli
         mov rsp, rbp                             ;还原到用户程序的栈
         o64 sysret
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
         ;----------------------------------------------------------------------
         ;安装系统服务所需要的代码段和栈段描述符
         sub rsp, 16                              ;开辟16字节的空间操作GDT和GDTR
         sgdt [rsp]
         xor rbx, rbx
         mov bx, [rsp]                            ;得到GDT的界限值
         inc bx                                   ;得到GDT的长度（字节数）
         add rbx, [rsp + 2]
         ;以下，处理器不支持从64位立即数到内存之间的传送!!!
         mov dword [rbx], 0x0000ffff
         mov dword [rbx + 4], 0x00cf9200          ;数据段描述符，DPL=00
         mov dword [rbx + 8], 0                   ;保留的描述符槽位
         mov dword [rbx + 12], 0
         mov dword [rbx + 16], 0x0000ffff         ;数据段描述符，DPL=11
         mov dword [rbx + 20], 0x00cff200
         mov dword [rbx + 24], 0x0000ffff         ;代码段描述符，DPL=11
         mov dword [rbx + 28], 0x00aff800

         ;安装任务状态段TSS的描述符
         mov rcx, 104                             ;TSS的标准长度
         call core_memory_allocate
         mov [rel tss_ptr], r13
         mov rax, r13
         call make_tss_descriptor
         mov qword [rbx + 32], rsi                ;TSS描述符的低64位
         mov qword [rbx + 40], rdi                ;TSS描述符的高64位

         add word [rsp], 48                       ;4个段描述符和1个TSS描述符的总字节数
         lgdt [rsp]
         add rsp, 16                              ;恢复栈平衡

         mov cx, 0x0040                           ;TSS描述符的选择子
         ltr cx

         ;为快速系统调用SYSCALL和SYSRET准备参数
         mov ecx, 0x0c0000080                     ;指定型号专属寄存器IA32_EFER
         rdmsr
         bts eax, 0                               ;设置SCE位，允许SYSCALL指令
         wrmsr

         mov ecx, 0xc0000081                      ;STAR
         mov edx, (RESVD_DESC_SEL << 16) | CORE_CODE64_SEL
         xor eax, eax
         wrmsr

         mov ecx, 0xc0000082                      ;LSTAR
         mov rax, [rel position]
         lea rax, [rax + syscall_procedure]       ;只用EAX部分
         mov rdx, rax
         shr rdx, 32                              ;使用EDX部分
         wrmsr

         mov ecx, 0xc0000084                      ;FMASK
         xor edx, edx
         mov eax, 0x00047700                      ;要求TF=IF=DF=AC=0；IOPL=00
         wrmsr

         ;以下初始化高级可编程中断控制器APIC。在计算机启动后，BIOS已经对LAPIC和IOAPIC做了
         ;初始化并创建了相关的高级配置和电源管理接口（ACPI）表项。可以从中获取多处理器和
         ;APIC信息。英特尔架构的个人计算机（IA-PC）从1MB物理内存中搜索获取；启用可扩展固件
         ;接口（EFI或者叫UEFI）的计算机需使用EFI传递的EFI系统表指针定位相关表格并从中获取
         ;多处理器和APIC信息。为简单起见，我们采用前一种传统的方式。请注意虚拟机的配置！

         ;ACPI申领的内存区域已经保存在我们的系统数据区（SDA），以下将其读出。此内存区可能
         ;位于分页系统尚未映射的部分，故以下先将这部分内存进行一一映射（线性地址=物理地址）
         cmp word [SDA_PHY_ADDR + 0x16], 0
         jz .acpi_err                             ;不正确的ACPI数据，可能不支持ACPI
         mov rsi, SDA_PHY_ADDR + 0x18             ;系统数据区：地址范围描述结构的起始地址
  .looking:
         cmp dword [rsi + 16], 3                  ;3:ACPI申领的内存（AddressRangeACPI）
         jz .looked
         add rsi, 32                              ;32:每个地址范围描述结构的长度
         loop .looking

  .acpi_err:
         mov r15, [rel position]
         lea rbx, [r15 + acpi_error]
         call put_string64                        ;位于core_utils64_mp.wid
         cli
         hlt

  .looked:
         mov rbx, [rsi]                           ;ACPI申领的起始物理地址
         mov rcx, [rsi + 8]                       ;ACPI申领的内存数量，以字节计
         add rcx, rbx                             ;ACPI申领的内存上边界
         mov rdx, 0xffff_ffff_ffff_f000           ;用于生成页地址的掩码
  .maping:
         mov r13, rbx                             ;R13:本次映射的线性地址
         mov rax, rbx
         and rax, rdx
         or rax, 0x07                             ;RAX:本次映射的物理地址及属性
         call mapping_laddr_to_page
         add rbx, 0x1000
         cmp rbx, rcx
         jle .maping

         ;从物理地址0x60000开始，搜索根系统描述指针结构（RSDP）
         mov rbx, 0x60000
         mov rcx, 'RSD PTR '                      ;结构的起始标记（注意尾部的空格）
  .searc:
         cmp qword [rbx], rcx
         je .finda
         add rbx, 16                              ;结构的标记总是位于16字节边界处
         cmp rbx, 0xffff0                         ;低端1MB物理内存的上边界
         jl .searc
         jmp .acpi_err                            ;未找到RSDP，报错停机处理。

  .finda:
         ;RSDT和XSDT都指向MADT，但RSDT给出的是32位物理地址，而XDST给出64位物理地址。
         ;只有VCPI 2.0及更高版本才有XSDT。典型地，VBox支持ACPI 2.0而Bochs仅支持1.0
         cmp byte [rbx + 15], 2                   ;检测ACPI的版本是否为2
         jne .acpi_1
         mov rbx, [rbx + 24]                      ;得到扩展的系统描述表（XSDT）的物理地址

         ;以下，开始在XSDT中遍历搜索多APIC描述表（MADT）
         xor rdi, rdi
         mov edi, [rbx + 4]                       ;获得XSDT的长度（以字节计）
         add rdi, rbx                             ;计算XSDT上边界的物理位置
         add rbx, 36                              ;XSDT尾部数组的物理位置
  .madt0:
         mov r11, [rbx]
         cmp dword [r11], 'APIC'                  ;MADT表的标记
         je .findm
         add rbx, 8                               ;下一个元素
         cmp rbx, rdi
         jl .madt0
         jmp .acpi_err                            ;未找到MADT，报错停机处理。

         ;以下按VCPI 1.0处理，开始在RSDT中遍历搜索多APIC描述表（MADT）
  .acpi_1:
         mov ebx, [rbx + 16]                      ;得到根系统描述表（RSDT）的物理地址
         ;以下，开始在RSDT中遍历搜索多APIC描述表（MADT）
         mov edi, [ebx + 4]                       ;获得RSDT的长度（以字节计）
         add edi, ebx                             ;计算RSDT末端的物理位置
         add ebx, 36                              ;RSDT尾部数组的物理位置
         xor r11, r11
  .madt1:
         mov r11d, [ebx]
         cmp dword [r11], 'APIC'                  ;MADT表的标记
         je .findm
         add ebx, 4                               ;下一个元素
         cmp ebx, edi
         jl .madt1
         jmp .acpi_err                            ;未找到MADT，报错停机处理。

  .findm:
         ;此时，R11是MADT的物理地址
         mov edx, [r11 + 36]                      ;预置的LAPIC物理地址
         mov [rel lapic_addr], edx

         ;以下开始遍历系统中的逻辑处理器（其LAPID ID）和I/O APIC。
         mov r15, [rel position]                  ;为访问cpu_list准备线性地址
         lea r15, [r15 + cpu_list]

         xor rdi, rdi
         mov edi, [r11 + 4]                       ;EDI:MADT的长度，以字节计
         add rdi, r11                             ;RDI:MADT尾部边界的物理地址
         add r11, 44                              ;R11:指向MADT尾部的中断控制器结构列表
  .enumd:
         cmp byte [r11], 0                        ;列表项类型：Processor Local APIC
         je .l_apic
         cmp byte [r11], 1                        ;列表项类型：I/O APIC
         je .ioapic
         jmp .m_end
  .l_apic:
         cmp dword [r11 + 4], 0                   ;Local APIC Flags
         jz .m_end
         mov al, [r11 + 3]                        ;local APIC ID
         mov [r15], al                            ;保存local APIC ID到cpu_list
         inc r15
         inc byte [rel num_cpus]                  ;可用的CPU数量递增
         jmp .m_end
  .ioapic:
         mov al, [r11 + 2]                        ;取出I/O APIC ID
         mov [rel ioapic_id], al                  ;保存I/O APIC ID
         mov eax, [r11 + 4]                       ;取出I/O APIC物理地址
         mov [rel ioapic_addr], eax               ;保存I/O APIC物理地址
   .m_end:
         xor rax, rax
         mov al, [r11 + 1]
         add r11, rax                             ;计算下一个中断控制器结构列表项的地址
         cmp r11, rdi
         jl .enumd

         ;将Local APIC的物理地址映射到预定义的线性地址LAPIC_START_ADDR
         mov r13, LAPIC_START_ADDR                ;在global_defs.wid中定义
         xor rax, rax
         mov eax, [rel lapic_addr]                ;取出LAPIC的物理地址
         or eax, 0x1f                             ;PCD=PWT=U/S=R/W=P=1，强不可缓存
         call mapping_laddr_to_page

         ;将I/O APIC的物理地址映射到预定义的线性地址IOAPIC_START_ADDR
         mov r13, IOAPIC_START_ADDR               ;在global_defs.wid中定义
         xor rax, rax
         mov eax, [rel ioapic_addr]               ;取出I/O APIC的物理地址
         or eax, 0x1f                             ;PCD=PWT=U/S=R/W=P=1，强不可缓存
         call mapping_laddr_to_page

         ;以下测量当前处理器在1毫秒的时间里经历多少时钟周期，作为后续的定时基准。
         mov rsi, LAPIC_START_ADDR                ;Local APIC的线性地址

         mov dword [rsi + 0x320], 0x10000         ;定时器的本地向量表入口寄存器。单次击发模式
         mov dword [rsi + 0x3e0], 0x0b            ;定时器的分频配置寄存器：1分频（不分频）

         mov al, 0x0b                             ;RTC寄存器B
         or al, 0x80                              ;阻断NMI
         out 0x70, al
         mov al, 0x52                             ;设置寄存器B，开放周期性中断，开放更
         out 0x71, al                             ;新结束后中断，BCD码，24小时制

         mov al, 0x8a                             ;CMOS寄存器A
         out 0x70, al
         ;in al, 0x71
         mov al, 0x2d                             ;32kHz，125ms的周期性中断
         out 0x71, al                             ;写回CMOS寄存器A

         mov al, 0x8c
         out 0x70, al
         in al, 0x71                              ;读寄存器C
  .w0:
         in al, 0x71                              ;读寄存器C
         bt rax, 6                                ;更新周期结束中断已发生？
         jnc .w0
         mov dword [rsi + 0x380], 0xffff_ffff     ;定时器初始计数寄存器：置初值并开始计数
  .w1:
         in al, 0x71                              ;读寄存器C
         bt rax, 6                                ;更新周期结束中断已发生？
         jnc .w1
         mov edx, [rsi + 0x390]                   ;定时器当前计数寄存器：读当前计数值

         mov eax, 0xffff_ffff
         sub eax, edx
         xor edx, edx
         mov ebx, 125                             ;125毫秒
         div ebx                                  ;EAX=当前处理器在1ms内的时钟数

         mov [rel clocks_1ms], eax                ;登记起来用于其它定时的场合

         mov al, 0x0b                             ;RTC寄存器B
         or al, 0x80                              ;阻断NMI
         out 0x70, al
         mov al, 0x12                             ;设置寄存器B，只允许更新周期结束中断
         out 0x71, al

         ;以下安装用于任务切换的中断处理过程
         mov r9, [rel position]
         lea rax, [r9 + rtm_interrupt_handle]     ;得到中断处理过程的线性地址
         call make_interrupt_gate                 ;位于core_utils64.wid

         cli

         mov r8, 0x28                             ;任务切换使用的中断向量
         call mount_idt_entry                     ;位于core_utils64.wid

         ;设置和时钟中断相关的硬件
         mov al, 0x0b                             ;RTC寄存器B
         or al, 0x80                              ;阻断NMI
         out 0x70, al
         mov al, 0x12                             ;设置寄存器B，禁止周期性中断，开放更
         out 0x71, al                             ;新结束后中断，BCD码，24小时制

         in al, 0xa1                              ;读8259从片的IMR寄存器
         and al, 0xfe                             ;清除bit 0(此位连接RTC)
         out 0xa1, al                             ;写回此寄存器

         sti

         mov al, 0x0c
         out 0x70, al
         in al, 0x71                              ;读RTC寄存器C，复位未决的中断状态

         ;计算机启动后，默认使用经由LINT0的虚拟线模式。
         ;LVT LINT0寄存器的默认值：0x700，不屏蔽LINT0，ExtINT投递模式
         ;LVT LINT1寄存器的默认值：0x400，不屏蔽LINT1，NMI投递模式


         ;如果不使用8259A PIC，直接使用I/O APIC，则应当屏蔽LVT LINT0或者8259A PIC的输入。
         ;以下两种方式可以选择一种即可。建议选择第二种，即，屏蔽8259A的全部中断输入。
         ;mov rsi, LAPIC_START_ADDR
         ;mov dword [rsi + 0x350], 0x10000         ;屏蔽LINT0的中断信号

         mov al, 0xff                             ;屏蔽所有发往8259A主芯片的中断信号
         out 0x21, al                             ;多处理器环境下不再使用8259芯片


         mov rdi, IOAPIC_START_ADDR               ;I/O APIC的线性地址

         ;根据图纸可知，若选择RTC定时器，需要设置I/O APIC的I/O重定向表寄存器8（IOREDTBL8）
         ;mov dword [rdi], 0x20                    ;对应RTC。
         ;mov dword [rdi + 0x10], 0x00000028       ;不屏蔽；物理模式；固定模式；向量0x28
         ;mov dword [rdi], 0x21
         ;mov dword [rdi + 0x10], 0x00000000       ;Local APIC ID：0

         ;如果想加快任务切换速度，可选择8254定时器。对应I/O APIC的IOREDTBL2
         ;mov dword [rdi], 0x14                    ;对应8254定时器。
         ;mov dword [rdi + 0x10], 0x00000028       ;不屏蔽；物理模式；固定模式；向量0x28
         ;mov dword [rdi], 0x15
         ;mov dword [rdi + 0x10], 0x00000000       ;Local APIC ID：0


         ;也可以使用Local APIC内部的定时器，更加灵活。
         mov eax, [rel clocks_1ms]
         mov ebx, 55
         mul ebx
         mov rsi, LAPIC_START_ADDR                ;Local APIC的线性地址
         mov dword [rsi + 0x3e0], 0x0b            ;1分频（不分频）
         mov dword [rsi + 0x320], 0x20028         ;周期性模式；固定模式；中断向量：0x28
         mov dword [rsi + 0x380], eax             ;初始计数值

         ;以下开始创建系统外壳任务（进程）
         mov r8, 50
         call create_process

         mov rbx, [rel pcb_ptr]                   ;得到外壳任务PCB的线性地址
         mov rax, [rbx + 56]                      ;从PCB中取出CR3
         mov cr3, rax                             ;切换到新进程的地址空间

         mov [rel cur_pcb], rbx                   ;设置当前任务的PCB。
         mov qword [rbx + 16], 1                  ;设置任务状态为“忙”。

         mov rax, [rbx + 32]                      ;从PCB中取出RSP0
         mov rdx, [rel tss_ptr]                   ;得到TSS的线性地址
         mov [rdx + 4], rax                       ;在TSS中填写RSP0

         push qword [rbx + 208]                   ;用户程序的SS
         push qword [rbx + 120]                   ;用户程序的RSP
         pushfq
         push qword [rbx + 200]                   ;用户程序的CS
         push qword [rbx + 192]                   ;用户程序的RIP

         iretq                                    ;返回当前任务的私有空间执行

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
core_end:
