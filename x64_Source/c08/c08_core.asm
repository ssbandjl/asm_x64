;c08_core.asm：多处理器多线程内核，李忠，2022-11-27

%define __MP__

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

  ack_cpus     db 0                               ;处理器初始化应答计数

  clocks_1ms   dd 0                               ;处理器在1ms内经历的时钟数

  welcome      db "Executing in 64-bit mode.Init MP", 249, 0
  cpu_init_ok  db " CPU(s) ready.", 0x0d, 0x0a, 0

  buffer       times 256 db 0

  sys_entry    dq get_screen_row                  ;#0  获取一个可用的屏幕行坐标
               dq get_cmos_time                   ;#1  获取CMOS时间
               dq put_cstringxy64                 ;#2  在指定坐标打印字符串
               dq create_process                  ;#3  创建任务
               dq get_current_pid                 ;#4  获取当前任务的标识
               dq terminate_process               ;#5  终止当前任务
               dq get_cpu_number                  ;#6  获取当前CPU的标识
               dq create_thread                   ;#7  创建线程
               dq get_current_tid                 ;#8  获取当前线程的标识
               dq thread_exit                     ;#9  退出当前线程
               dq memory_allocate                 ;#10 用户空间内存分配
               dq waiting_for_a_thread            ;#11 等待指定的线程
               dq init_mutex                      ;#12 初始化互斥锁
               dq acquire_mutex                   ;#13 获取互斥锁
               dq release_mutex                   ;#14 释放互斥锁
               dq thread_sleep                    ;#15 线程休眠

  pcb_ptr      dq 0                               ;进程控制块PCB首节点的线性地址

;===============================================================================
section core_code                                 ;内核代码段

%include "..\common\core_utils64.wid"             ;引入内核用到的例程
%include "..\common\user_static64.lib"

         bits 64

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  _ap_string      db 249, 0

ap_to_core_entry:                                 ;应用处理器（AP）进入内核的入口点
         ;启用GDT的高端线性地址并加载IDTR
         mov rax, UPPER_SDA_LINEAR
         lgdt [rax + 2]                           ;只有在64位模式下才能加载64位线性地址部分
         lidt [rax + 0x0c]                        ;只有在64位模式下才能加载64位线性地址部分

         ;为当前处理器创建64位模式下的专属栈
         mov rcx, 4096
         call core_memory_allocate
         mov rsp, r14

         ;创建当前处理器的专属存储区（含TSS），并安装TSS描述符到GDT
         mov rcx, 256                             ;专属数据区的长度，含TSS。
         call core_memory_allocate
         lea rax, [r13 + 128]                     ;TSS开始于专属数据区内偏移为128的地方
         call make_tss_descriptor

         mov r15, UPPER_SDA_LINEAR                ;系统数据区的高端线性地址（低端亦可）

         mov r8, [r15 + 4]                        ;R8=GDT的线性地址
         movzx rcx, word [r15 + 2]                ;RCX=GDT的界限值
         mov [r8 + rcx + 1], rsi                  ;TSS描述符的低64位
         mov [r8 + rcx + 9], rdi                  ;TSS描述符的高64位

         add word [r15 + 2], 16
         lgdt [r15 + 2]                           ;重新加载GDTR

         shr cx, 3                                ;除以8（消除余数），得到索引号
         inc cx                                   ;索引号递增
         shl cx, 3                                ;将索引号移到正确位置

         ltr cx                                   ;为当前处理器加载任务寄存器TR

         ;将处理器专属数据区首地址保存到当前处理器的型号专属寄存器IA32_KERNEL_GS_BASE
         mov ecx, 0xc000_0102                     ;IA32_KERNEL_GS_BASE
         mov rax, r13                             ;只用EAX
         mov rdx, r13
         shr rdx, 32                              ;只用EDX
         wrmsr

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

         mov r15, [rel position]
         lea rbx, [r15 + _ap_string]
         call put_string64                        ;位于core_utils64_mp.wid

         swapgs                                   ;准备用GS操作当前处理器的专属数据
         mov qword [gs:8], 0                      ;没有正在执行的任务
         xor rax, rax
         mov al, byte [rel ack_cpus]
         mov [gs:16], rax                         ;设置当前处理器的编号
         mov [gs:24], rsp                         ;保存当前处理器的固有栈指针
         swapgs

         inc byte [rel ack_cpus]                  ;递增应答计数值

         mov byte [AP_START_UP_ADDR + lock_var], 0;释放自旋锁

         mov rsi, LAPIC_START_ADDR                ;Local APIC的线性地址
         bts dword [rsi + 0xf0], 8                ;设置SVR寄存器，允许LAPIC

         sti                                      ;开放中断

  .do_idle:
         hlt
         jmp .do_idle

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
         call put_cstringxy64                     ;位于core_utils64_mp.wid

         cli
         hlt                                      ;停机且不接受外部硬件中断

  exceptm      db "A exception raised,halt.", 0   ;发生异常时的错误信息

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
handle_waiting_thread:                            ;处理等待其它线程的线程
                                                  ;输入：R11=线程控制块TCB的线性地址
         push rbx
         push rdx
         push r11

         mov rbx, r11

         mov rdx, [r11 + 56]                      ;被等待的线程的标识
         call search_for_thread_id
         or r11, r11                              ;线程已经被清理了吗？
         jz .set_th
         cmp qword [r11 + 16], 2                  ;线程是终止状态吗？
         jne .return                              ;不是。返回（继续等待）
  .set_th:
         mov qword [rbx + 16], 0                  ;将线程设置为就绪状态

         mov r11, LAPIC_START_ADDR                ;Local APIC的线性地址
         mov dword [r11 + 0x310], 0
         mov dword [r11 + 0x300], 0x000840fe      ;向所有处理器发送线程认领中断
  .return:
         pop r11
         pop rdx
         pop rbx

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
handle_waiting_flag:                              ;处理等待标志的线程
                                                  ;输入：R11=线程控制块TCB的线性地址
         push rax
         push rbx
         push rcx

         mov rax, 0
         mov rbx, [r11 + 56]                      ;被等待的标志的线性地址
         mov rcx, 1
         lock cmpxchg [rbx], rcx
         jnz .return

         mov qword [r11 + 16], 0                  ;将线程设置为就绪状态

         mov rbx, LAPIC_START_ADDR                ;Local APIC的线性地址
         mov dword [rbx + 0x310], 0
         mov dword [rbx + 0x300], 0x000840fe      ;向所有处理器发送线程认领中断

  .return:
         pop rcx
         pop rbx
         pop rax

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
handle_waiting_sleep:                             ;处理睡眠中的线程
                                                  ;输入：R11=线程控制块TCB的线性地址
         push rax

         dec qword [r11 + 56]
         cmp qword [r11 + 56], 0
         jnz .return

         mov qword [r11 + 16], 0                  ;将线程设置为就绪状态

         mov rax, LAPIC_START_ADDR                ;Local APIC的线性地址
         mov dword [rax + 0x310], 0
         mov dword [rax + 0x300], 0x000840fe      ;向所有处理器发送线程认领中断

  .return:
         pop rax

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
system_management_handler:                        ;系统管理中断的处理过程

         push rbx
         push r11

         mov rbx, [rel pcb_ptr]                   ;取得链表首节点的线性地址
         or rbx, rbx
         jz .return                               ;系统中尚不存在任务
  .nextp:
         mov r11, [rbx + 272]
         or r11, r11
         jz .return                               ;任务尚未创建线程
  .nextt:
         cmp qword [r11 + 16], 3                  ;正在休眠并等待其它线程？
         jne .next0                               ;不是，转去.b0继续处理此TCB
         ;处理等待其它线程终止的线程并决定其是否唤醒
         call handle_waiting_thread
         jmp .gnext
  .next0:
         ;处理等待某个信号的线程并决定其是否唤醒
         cmp qword [r11 + 16], 5
         jne .next1
         call handle_waiting_flag
         jmp .gnext
  .next1:
         ;处理休眠的线程并决定其是否唤醒
         cmp qword [r11 + 16], 4
         jne .next2
         call handle_waiting_sleep
         jmp .gnext
  .next2:
  .gnext:
         mov r11, [r11 + 280]                     ;否。处理下一个TCB节点
         cmp r11, 0                               ;到达TCB链表尾部？
         jne .nextt                               ;否。

         mov rbx, [rbx + 280]                     ;下一个PCB节点
         cmp rbx, [rel pcb_ptr]                   ;转一圈又回到PCB首节点？
         jne .nextp                               ;否。转.nextp处理下一个PCB

  .return:
         mov r11, LAPIC_START_ADDR                ;给Local APIC发送中断结束命令EOI
         mov dword [r11 + 0xb0], 0

mov rbx, UPPER_TEXT_VIDEO
not byte [rbx]

         pop r11
         pop rbx

         iretq

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
search_for_a_ready_thread:                        ;查找一个就绪的线程并将其置为忙
                                                  ;返回：R11=就绪线程所属任务的PCB线性地址
                                                  ;      R12=就绪线程的TCB线性地址
         ;此例程通常是在中断处理过程内调用，默认中断是关闭状态。
         push rax
         push rbx
         push rcx

         mov rcx, 1                               ;RCX=线程的“忙”状态

         swapgs
         mov rbx, [gs:8]                          ;取得当前任务的PCB线性地址
         mov r12, [gs:32]                         ;取得当前线程的TCB线性地址
         swapgs
         mov r11, rbx
         cmp r11, 0                               ;处理器当前未在执行任务？
         jne .nextt
         mov rbx, [rel pcb_ptr]                   ;是的。从PCB链表首节点及其第一个TCB开始搜索。
         mov r11, rbx
         mov r12, [r11 + 272]                     ;PCB链表首节点的第一个TCB节点
  .nextt:                                         ;这一部分遍历指定任务的TCB链表
         cmp r12, 0                               ;正位于当前PCB的TCB链表末尾?
         je .nextp                                ;转去切换到PCB链表的下一个节点。
         xor rax, rax
         lock cmpxchg [r12 + 16], rcx
         jz .retrn
         mov r12, [r12 + 280]                     ;取得下一个TCB节点
         jmp .nextt
  .nextp:                                         ;这一部分控制任务链表的遍历
         mov r11, [r11 + 280]                     ;取得下一个PCB节点
         cmp r11, rbx                             ;是否转一圈回到初始PCB节点？
         je .fmiss                                ;是。即，未找到就绪线程（节点）
         mov r12, [r11 + 272]                     ;不是。从新的PCB中提取TCB链表首节点
         jmp .nextt
  .fmiss:                                         ;看来系统中不存在就绪线程
         xor r11, r11
         xor r12, r12
  .retrn:
         pop rcx
         pop rbx
         pop rax

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
resume_execute_a_thread:                          ;恢复执行一个线程
                                                  ;传入：R11=线程所属的任务的PCB线性地址
                                                  ;      R12=线程的TCB线性地址
         ;此例程在中断处理过程内调用，默认中断是关闭状态。
         mov eax, [rel clocks_1ms]                ;以下计算新线程运行时间
         mov ebx, [r12 + 240]                     ;为线程指定的时间片
         mul ebx

         mov rsi, LAPIC_START_ADDR                ;Local APIC的线性地址
         mov dword [rsi + 0x3e0], 0x0b            ;1分频
         mov dword [rsi + 0x320], 0xfd            ;单次击发模式，Fixed，中断号0xfd

         mov rbx, [r11 + 56]
         mov cr3, rbx                             ;切换地址空间

         swapgs
         mov [gs:8], r11                          ;将新线程所属的任务设置为当前任务
         mov [gs:32], r12                         ;将新线程设置为当前线程
         mov rbx, [r12 + 32]                      ;取TCB中的RSP0
         mov [gs:128 + 4], rbx                    ;置TSS的RSP0
         swapgs

         mov rcx, [r12 + 80]
         mov rdx, [r12 + 88]
         mov rdi, [r12 + 104]
         mov rbp, [r12 + 112]
         mov rsp, [r12 + 120]
         mov r8, [r12 + 128]
         mov r9, [r12 + 136]
         mov r10, [r12 + 144]

         mov r13, [r12 + 168]
         mov r14, [r12 + 176]
         mov r15, [r12 + 184]
         push qword [r12 + 208]                   ;SS
         push qword [r12 + 120]                   ;RSP
         push qword [r12 + 232]                   ;RFLAGS
         push qword [r12 + 200]                   ;CS
         push qword [r12 + 192]                   ;RIP

         mov dword [rsi + 0x380], eax             ;开始计时

         mov rax, [r12 + 64]
         mov rbx, [r12 + 72]
         mov rsi, [r12 + 96]
         mov r11, [r12 + 152]
         mov r12, [r12 + 160]

         iretq                                    ;转入新线程执行

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
time_slice_out_handler:                           ;时间片到期中断的处理过程
         push rax
         push rbx
         push r11
         push r12
         push r13

         mov r11, LAPIC_START_ADDR                ;给Local APIC发送中断结束命令EOI
         mov dword [r11 + 0xb0], 0

         call search_for_a_ready_thread
         or r11, r11
         jz .return                               ;未找到就绪的线程

         swapgs
         mov rax, qword [gs:8]                    ;当前任务的PCB线性地址
         mov rbx, qword [gs:32]                   ;当前线程的TCB线性地址
         swapgs

         ;保存当前任务和线程的状态以便将来恢复执行。
         mov r13, cr3                             ;保存原任务的分页系统
         mov qword [rax + 56], r13
         ;RAX和RBX不需要保存，将来恢复执行时从栈中弹出
         mov [rbx + 80], rcx
         mov [rbx + 88], rdx
         mov [rbx + 96], rsi
         mov [rbx + 104], rdi
         mov [rbx + 112], rbp
         mov [rbx + 120], rsp
         mov [rbx + 128], r8
         mov [rbx + 136], r9
         mov [rbx + 144], r10
         ;r11、R12和R13不需要设置，将来恢复执行时从栈中弹出
         mov [rbx + 176], r14
         mov [rbx + 184], r15
         mov r13, [rel position]
         lea r13, [r13 + .return]                 ;将来恢复执行时，是从中断返回也～
         mov [rbx + 192], r13                     ;RIP域为中断返回点
         mov [rbx + 200], cs
         mov [rbx + 208], ss
         pushfq
         pop qword [rbx + 232]

         mov qword [rbx + 16], 0                  ;置线程状态为就绪

         jmp resume_execute_a_thread              ;恢复并执行新线程

  .return:
         pop r13
         pop r12
         pop r11
         pop rbx
         pop rax

         iretq

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;新任务/线程创建后，将广播新任务/线程创建消息给所有处理器，所有处理器执行此中断服务例程。
new_task_notify_handler:                          ;任务/线程认领中断的处理过程
         push rsi
         push r11
         push r12

         mov rsi, LAPIC_START_ADDR                ;Local APIC的线性地址
         mov dword [rsi + 0xb0], 0                ;发送EOI

         swapgs
         cmp qword [gs:8], 0                      ;当前处理器没有任务执行吗？
         swapgs
         jne .return                              ;是的（忙）。不打扰了 :)

         call search_for_a_ready_thread
         or r11, r11
         jz .return                               ;未找到就绪的任务

         swapgs
         add rsp, 24                              ;去掉进入例程时压入的三个参数
         mov qword [gs:24], rsp                   ;保存固有栈当前指针以便将来返回
         swapgs

         jmp resume_execute_a_thread              ;恢复并执行新线程

  .return:
         pop r12
         pop r11
         pop rsi

         iretq

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  _append_lock  dq 0

append_to_pcb_link:                               ;在PCB链上追加任务控制块
                                                  ;输入：R11=PCB线性基地址
         push rax
         push rbx

         pushfq                                   ;-->A
         cli
         SET_SPIN_LOCK rax, qword [rel _append_lock]

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
         mov qword [rel _append_lock], 0          ;释放锁
         popfq                                    ;A

         pop rbx
         pop rax

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
get_current_tid:                                  ;返回当前线程的标识
         pushfq
         cli
         swapgs
         mov rax, [gs:32]
         mov rax, [rax + 8]
         swapgs
         popfq

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
get_current_pid:                                  ;返回当前任务（进程）的标识
         pushfq
         cli
         swapgs
         mov rax, [gs:8]
         mov rax, [rax + 8]
         swapgs
         popfq

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
search_for_thread_id:                             ;查找指定标识的线程
                                                  ;输入：RDX=线程标识
                                                  ;输出：R11=线程的TCB线性地址
         push rbx

         mov rbx, [rel pcb_ptr]                   ;取得链表首节点的线性地址
  .nextp:
         mov r11, [rbx + 272]

  .nextt:
         cmp [r11 + 8], rdx                       ;找到指定的线程了吗？
         je .found                                ;是的。转.found
         mov r11, [r11 + 280]                     ;否。处理下一个TCB节点
         cmp r11, 0                               ;到达TCB链表尾部？
         jne .nextt                               ;否。

         mov rbx, [rbx + 280]                     ;下一个PCB节点
         cmp rbx, [rel pcb_ptr]                   ;转一圈又回到PCB首节点？
         jne .nextp                               ;否。转.nextp处理下一个PCB

         xor r11, r11                             ;R11=0表明不存在指定的线程
  .found:
         pop rbx

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
waiting_for_a_thread:                             ;等待指定的线程结束
                                                  ;输入：RDX=线程标识
         push rax
         push rbx
         push r11
         push r12
         push r13

         call search_for_thread_id
         or r11, r11                              ;线程已经被清理了吗？
         jz .return
         cmp qword [r11 + 16], 2                  ;线程是终止状态吗？
         je .return

         ;被等待的线程还在运行，只能休眠并等待通知
         cli

         mov rax, LAPIC_START_ADDR                ;Local APIC的线性地址
         mov dword [rax + 0x320], 0x00010000      ;屏蔽定时器中断

         swapgs
         mov rax, qword [gs:8]                    ;当前任务的PCB线性地址
         mov rbx, qword [gs:32]                   ;当前线程的TCB线性地址
         swapgs

         ;保存当前任务和线程的状态以便将来恢复执行。
         mov r13, cr3                             ;保存原任务的分页系统
         mov qword [rax + 56], r13
         ;RAX和RBX不需要保存，将来恢复执行时从栈中弹出
         mov [rbx + 80], rcx
         mov [rbx + 88], rdx
         mov [rbx + 96], rsi
         mov [rbx + 104], rdi
         mov [rbx + 112], rbp
         mov [rbx + 120], rsp
         mov [rbx + 128], r8
         mov [rbx + 136], r9
         mov [rbx + 144], r10
         ;r11、R12和R13不需要设置，将来恢复执行时从栈中弹出
         mov [rbx + 176], r14
         mov [rbx + 184], r15
         mov r13, [rel position]
         lea r13, [r13 + .return]                 ;将来恢复执行时，是从例程调用返回
         mov [rbx + 192], r13                     ;RIP域为中断返回点
         mov [rbx + 200], cs
         mov [rbx + 208], ss
         pushfq
         pop qword [rbx + 232]

         mov qword [rbx + 16], 3                  ;置线程状态为“休眠并等待指定线程结束”
         mov qword [rbx + 56], rdx                ;设置被等待的线程标识

         call search_for_a_ready_thread
         or r11, r11
         jz .sleep                                ;未找到就绪的任务

         jmp resume_execute_a_thread              ;恢复并执行新线程

  .sleep:
         swapgs
         mov qword [gs:0], 0                      ;当前处理器无有效3特权级栈指针
         mov qword [gs:8], 0                      ;当前处理器未在执行任务
         mov qword [gs:32], 0                     ;当前处理器未在执行线程
         mov rsp, [gs:24]                         ;切换到处理器的固有栈
         swapgs

         iretq
  .return:
         pop r13
         pop r12
         pop r11
         pop rbx
         pop rax

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
init_mutex:                                       ;初始化互斥锁
                                                  ;输入：无
                                                  ;输出：RDX=互斥锁变量线性地址
         push rcx
         push r13
         push r14
         mov rcx, 8
         call core_memory_allocate                ;必须是在内核的空间中开辟
         mov qword [r13], 0                       ;初始化互斥锁的状态（未加锁）
         mov rdx, r13
         pop r14
         pop r13
         pop rcx

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
acquire_mutex:                                    ;获取互斥锁
                                                  ;输入：RDX=互斥锁变量线性地址
         push rax
         push rbx
         push r11
         push r12
         push r13

         mov r11, 1
         mov rax, 0
         lock cmpxchg [rdx], r11
         jz .return

         ;未获得互斥锁，只能阻塞当前线程。
         cli

         mov rax, LAPIC_START_ADDR                ;Local APIC的线性地址
         mov dword [rax + 0x320], 0x00010000      ;屏蔽定时器中断

         swapgs
         mov rax, qword [gs:8]                    ;当前任务的PCB线性地址
         mov rbx, qword [gs:32]                   ;当前线程的TCB线性地址
         swapgs

         ;保存当前任务和线程的状态以便将来恢复执行。恢复时已获得互斥锁
         mov r13, cr3                             ;保存原任务的分页系统
         mov qword [rax + 56], r13
         ;RAX和RBX不需要保存，将来恢复执行时从栈中弹出
         mov [rbx + 80], rcx
         mov [rbx + 88], rdx
         mov [rbx + 96], rsi
         mov [rbx + 104], rdi
         mov [rbx + 112], rbp
         mov [rbx + 120], rsp
         mov [rbx + 128], r8
         mov [rbx + 136], r9
         mov [rbx + 144], r10
         ;r11、R12和R13不需要设置，将来恢复执行时从栈中弹出
         mov [rbx + 176], r14
         mov [rbx + 184], r15
         mov r13, [rel position]
         lea r13, [r13 + .return]                 ;将来恢复执行时已获得互斥锁
         mov [rbx + 192], r13                     ;RIP域为中断返回点
         mov [rbx + 200], cs
         mov [rbx + 208], ss
         pushfq
         pop qword [rbx + 232]

         mov qword [rbx + 56], rdx                ;设置被等待的数据的线性地址
         mov qword [rbx + 16], 5                  ;置线程状态为“休眠并等待某个信号清零”

         call search_for_a_ready_thread
         or r11, r11
         jz .sleep                                ;未找到就绪的任务

         jmp resume_execute_a_thread              ;恢复并执行新线程

  .sleep:
         swapgs
         mov qword [gs:0], 0                      ;当前处理器无有效3特权级栈指针
         mov qword [gs:8], 0                      ;当前处理器未在执行任务
         mov qword [gs:32], 0                     ;当前处理器未在执行线程
         mov rsp, [gs:24]                         ;切换到处理器的固有栈
         swapgs

         iretq

  .return:
         pop r13
         pop r12
         pop r11
         pop rbx
         pop rax

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
release_mutex:                                    ;释放互斥锁
                                                  ;输入：RDX=互斥锁变量线性地址
         push rax
         xor rax, rax
         xchg [rdx], rax
         pop rax

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
thread_sleep:                                     ;线程休眠
                                                  ;输入：RDX=以55ms为单位的时间长度
         push rax
         push rbx
         push r11
         push r12
         push r13

         cmp rdx, 0
         je .return

         ;休眠就意味着阻塞当前线程。
         cli

         mov rax, LAPIC_START_ADDR                ;Local APIC的线性地址
         mov dword [rax + 0x320], 0x00010000      ;屏蔽定时器中断

         swapgs
         mov rax, qword [gs:8]                    ;当前任务的PCB线性地址
         mov rbx, qword [gs:32]                   ;当前线程的TCB线性地址
         swapgs

         ;保存当前任务和线程的状态以便将来恢复执行。
         mov r13, cr3                             ;保存原任务的分页系统
         mov qword [rax + 56], r13
         ;RAX和RBX不需要保存，将来恢复执行时从栈中弹出
         mov [rbx + 80], rcx
         mov [rbx + 88], rdx
         mov [rbx + 96], rsi
         mov [rbx + 104], rdi
         mov [rbx + 112], rbp
         mov [rbx + 120], rsp
         mov [rbx + 128], r8
         mov [rbx + 136], r9
         mov [rbx + 144], r10
         ;r11、R12和R13不需要设置，将来恢复执行时从栈中弹出
         mov [rbx + 176], r14
         mov [rbx + 184], r15
         mov r13, [rel position]
         lea r13, [r13 + .return]                 ;将来恢复执行时，重新尝试加锁
         mov [rbx + 192], r13                     ;RIP域为中断返回点
         mov [rbx + 200], cs
         mov [rbx + 208], ss
         pushfq
         pop qword [rbx + 232]

         mov qword [rbx + 56], rdx                ;设置以55ms为单位的时间长度
         mov qword [rbx + 16], 4                  ;置线程状态为“休眠指定时间长度”

         call search_for_a_ready_thread
         or r11, r11
         jz .sleep                                ;未找到就绪的任务

         jmp resume_execute_a_thread              ;恢复并执行新线程

  .sleep:
         swapgs
         mov qword [gs:0], 0                      ;当前处理器无有效3特权级栈指针
         mov qword [gs:8], 0                      ;当前处理器未在执行任务
         mov qword [gs:32], 0                     ;当前处理器未在执行线程
         mov rsp, [gs:24]                         ;切换到处理器的固有栈
         swapgs

         iretq

  .return:
mov rbx, UPPER_TEXT_VIDEO
not byte [rbx + 2]
         pop r13
         pop r12
         pop r11
         pop rbx
         pop rax

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
thread_exit:                                      ;线程终止退出
                                                  ;输入：RDX=返回码
         mov rsi, LAPIC_START_ADDR                ;Local APIC的线性地址
         mov dword [rsi + 0x320], 0x00010000      ;屏蔽定时器中断

         cli

         swapgs
         mov rbx, [gs:32]                         ;取出当前线程的TCB线性地址
         mov rsp, [gs:24]                         ;切换到处理器的固有栈

         mov qword [gs:0], 0                      ;当前处理器无有效3特权级栈指针
         mov qword [gs:8], 0                      ;当前处理器未在执行任务
         mov qword [gs:32], 0                     ;当前处理器未在执行线程
         swapgs

         mov qword [rbx + 16], 2                  ;线程状态：终止
         mov [rbx + 24], rdx                      ;返回代码

         call search_for_a_ready_thread
         or r11, r11
         jz .sleep                                ;未找到就绪的线程

         jmp resume_execute_a_thread              ;恢复并执行新线程

  .sleep:
         iretq                                    ;回到不执行线程的日子:)

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
terminate_process:                                ;终止当前任务
         mov rsi, LAPIC_START_ADDR                ;Local APIC的线性地址
         mov dword [rsi + 0x320], 0x00010000      ;屏蔽定时器中断

         cli

         swapgs
         mov rax, [gs:8]                          ;定位到当前任务的PCB节点
         mov qword [rax + 16], 2                  ;任务状态=终止
         mov rax, [gs:32]                         ;定位到当前线程的TCB节点
         mov qword [rax + 16], 2                  ;线程状态=终止
         mov qword [gs:0], 0
         mov rsp, [gs:24]                         ;切换到处理器的固有栈

         mov qword [gs:0], 0                      ;当前处理器无有效3特权级栈指针
         mov qword [gs:8], 0                      ;当前处理器未在执行任务
         mov qword [gs:32], 0                     ;当前处理器未在执行线程
         swapgs

         call search_for_a_ready_thread
         or r11, r11
         jz .sleep                                ;未找到就绪的任务

         jmp resume_execute_a_thread              ;恢复并执行新任务

  .sleep:
         iretq                                    ;回到不执行任务的日子:)

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
create_thread:                                    ;创建一个线程
                                                  ;输入：RSI=线程入口的线性地址
                                                  ;      RDI=传递给线程的参数
                                                  ;输出：RDX=线程标识
         push rax
         push rbx
         push rcx
         push r11
         push r12
         push r13
         push r14

         ;先创建线程控制块TCB
         mov rcx, 512                             ;线程控制块TCB的尺寸
         call core_memory_allocate                ;必须是在内核的空间中开辟

         mov rbx, r13                             ;以下，RBX专用于保存TCB线性地址

         call generate_thread_id
         mov [rbx + 8], rax                       ;记录当前线程的标识
         mov rdx, rax                             ;用于返回线程标识

         mov qword [rbx + 16], 0                  ;线程状态=就绪

         mov rcx, 4096 * 16                       ;为TSS的RSP0开辟栈空间
         call core_memory_allocate                ;必须是在内核的空间中开辟
         mov [rbx + 32], r14                      ;填写TCB中的RSP0域的值

         pushfq
         cli
         swapgs
         mov r11, [gs:8]                          ;获取当前任务的PCB线性地址
         mov r12, [gs:32]                         ;获取当前线程的TCB线性地址
         swapgs
         popfq

         mov rcx, 4096 * 16                       ;为线程开辟栈空间
         call user_memory_allocate
         sub r14, 32                              ;在栈中开辟32字节的空间
         mov [rbx + 120], r14                     ;线程执行时的RSP。

         lea rcx, [r14 + 8]                       ;得到线程返回地址
         mov [r14], rcx
         ;以下填写指令MOV RAX, 9的机器代码
         mov byte [rcx], 0xb8
         mov byte [rcx + 1], 0x09
         mov byte [rcx + 2], 0x00
         mov byte [rcx + 3], 0x00
         mov byte [rcx + 4], 0x00
         ;以下填写指令XOR RDX, RDX的机器代码
         mov byte [rcx + 5], 0x48
         mov byte [rcx + 6], 0x31
         mov byte [rcx + 7], 0xd2
         ;以下填写指令SYSCALL的机器代码
         mov byte [rcx + 8], 0x0f
         mov byte [rcx + 9], 0x05

         mov qword [rbx + 192], rsi               ;线程入口点（RIP）

         mov qword [rbx + 200], USER_CODE64_SEL   ;线程的代码段选择子
         mov qword [rbx + 208], USER_STACK64_SEL  ;线程的栈段选择子

         pushfq
         pop qword [rbx + 232]                    ;线程执行时的标志寄存器

         mov qword [rbx + 240], SUGG_PREEM_SLICE  ;推荐的线程执行时间片

         mov qword [rbx + 280], 0                 ;下一个TCB的线性地址，0=无

  .again:
         xor rax, rax
         lock cmpxchg [r12 + 280], rbx            ;如果节点的后继为0，则新节点为其后继
         jz .linkd
         mov r12, [r12 + 280]
         jmp .again
  .linkd:
         mov rcx, LAPIC_START_ADDR                ;Local APIC的线性地址
         mov dword [rcx + 0x310], 0
         mov dword [rcx + 0x300], 0x000840fe      ;向所有处理器发送线程认领中断

         pop r14
         pop r13
         pop r12
         pop r11
         pop rcx
         pop rbx
         pop rax

         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
create_process:                                   ;创建新的任务及其主线程
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

         call core_memory_allocate                ;为线程控制块TCB分配内存
         mov r12, r13                             ;以下，R12专用于保存TCB线性地址

         mov qword [r11 + 272], r12               ;在PCB中登记第一个TCB

         mov qword [r11 + 24], USER_ALLOC_START   ;填写PCB的下一次可分配线性地址域

         ;从当前活动的4级头表复制并创建新任务的4级头表。
         call copy_current_pml4
         mov [r11 + 56], rax                      ;填写PCB的CR3域，默认PCD=PWT=0

         ;以下，切换到新任务的地址空间，并清空其4级头表的前半部分。不过没有关系，
         ;我们正在地址空间的高端执行，可正常执行内核代码并访问内核数据，毕竟所有
         ;任务的高端（全局）部分都相同。同时，当前使用的栈是位于地址空间高端的栈。

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
         mov [r12 + 32], r14                      ;填写TCB中的RSP0域的值

         mov rcx, 4096 * 16                       ;为主线程开辟栈空间
         call user_memory_allocate
         mov [r12 + 120], r14                     ;主线程执行时的RSP。

         mov qword [r11 + 16], 0                  ;任务状态=运行
         mov qword [r12 + 16], 0                  ;线程状态=就绪

         ;以下开始加载用户程序
         mov rcx, 512                             ;在私有空间开辟一个缓冲区
         call user_memory_allocate
         mov rbx, r13
         mov rax, r8                              ;用户程序起始扇区号
         call read_hard_disk_0

         mov [r13 + 16], r13                      ;在程序中填写它自己的起始线性地址
         mov r14, r13
         add r14, [r13 + 8]
         mov [r12 + 192], r14                     ;在TCB中登记程序的入口点线性地址

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
         mov qword [r12 + 200], USER_CODE64_SEL   ;主线程的代码段选择子
         mov qword [r12 + 208], USER_STACK64_SEL  ;主线程的栈段选择子

         pushfq
         pop qword [r12 + 232]

         mov qword [r12 + 240], SUGG_PREEM_SLICE  ;推荐的线程执行时间片

         call generate_process_id
         mov [r11 + 8], rax                       ;记录新任务的标识

         call generate_thread_id
         mov [r12 + 8], rax                       ;记录主线程的标识

         mov qword [r12 + 280], 0                 ;下一个TCB的线性地址（0=无）

         call append_to_pcb_link                  ;将PCB添加到进程控制块链表尾部

         mov cr3, r15                             ;切换到原任务的地址空间

         mov rsi, LAPIC_START_ADDR                ;Local APIC的线性地址
         mov dword [rsi + 0x310], 0
         mov dword [rsi + 0x300], 0x000840fe      ;向所有处理器发送任务/线程认领中断

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
         ;RCX和R11由处理器使用，保存RIP和RFLAGS的内容；进入时中断是禁止状态
         swapgs                                   ;切换GS到当前处理器的数据区
         mov [gs:0], rsp                          ;临时保存当前的3特权级栈指针
         mov rsp, [gs:128+4]                      ;使用TSS的RSP0作为安全栈指针
         push qword [gs:0]
         swapgs
         sti                                      ;准备工作全部完成，中断和任务切换无虞

         push rcx
         mov rcx, [rel position]
         add rcx, [rcx + rax * 8 + sys_entry]     ;得到指定的那个系统调用功能的线性地址
         call rcx
         pop rcx

         cli
         pop rsp                                  ;恢复原先的3特权级栈指针

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
         add rsp, rax                             ;栈指针必须转换为高端地址且必须是扩高地址

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
         call make_interrupt_gate                 ;位于core_utils64_mp.wid

         xor r8, r8
  .idt0:
         call mount_idt_entry                     ;位于core_utils64_mp.wid
         inc r8
         cmp r8, 31
         jle .idt0

         ;创建并安装对应于其它中断的通用处理过程的中断门
         lea rax, [r9 + general_interrupt_handler];得到通用中断处理过程的线性地址
         call make_interrupt_gate                 ;位于core_utils64_mp.wid

         mov r8, 32
  .idt1:
         call mount_idt_entry                     ;位于core_utils64_mp.wid
         inc r8
         cmp r8, 255
         jle .idt1

         mov rax, UPPER_IDT_LINEAR                ;中断描述符表IDT的高端线性地址
         mov rbx, UPPER_SDA_LINEAR                ;系统数据区SDA的高端线性地址
         mov qword [rbx + 0x0e], rax
         mov word [rbx + 0x0c], 256 * 16 - 1

         lidt [rbx + 0x0c]                        ;只有在64位模式下才能加载64位线性地址部分

         mov al, 0xff                             ;屏蔽所有发往8259A主芯片的中断信号
         out 0x21, al                             ;多处理器环境下不再使用8259芯片

         ;在64位模式下显示的第一条信息!
         mov r15, [rel position]
         lea rbx, [r15 + welcome]
         call put_string64                        ;位于core_utils64_mp.wid

         ;安装系统服务（SYSCALL/SYSRET）所需要的代码段和栈段描述符
         mov r15, UPPER_SDA_LINEAR                ;系统数据区SDA的线性地址
         xor rbx, rbx
         mov bx, [r15 + 2]                        ;BX=GDT的界限值
         inc bx                                   ;BX=GDT的长度
         add rbx, [r15 + 4]                       ;RBX=新描述符的追加位置

         mov dword [rbx], 0x0000ffff              ;64位模式下不支持64位立即数传送
         mov dword [rbx + 4], 0x00cf9200          ;数据段描述符，DPL=00
         mov dword [rbx + 8], 0                   ;保留的描述符槽位
         mov dword [rbx + 12], 0
         mov dword [rbx + 16], 0x0000ffff         ;数据段描述符，DPL=11
         mov dword [rbx + 20], 0x00cff200
         mov dword [rbx + 24], 0x0000ffff         ;代码段描述符，DPL=11
         mov dword [rbx + 28], 0x00aff800

         ;我们为每个逻辑处理器都准备一个专属数据区，它是由每个处理器的GS所指向的。
         ;为当前处理器（BSP）准备专属数据区，设置GS并安装任务状态段TSS的描述符
         mov rcx, 256                             ;专属数据区的长度，含TSS。
         call core_memory_allocate
         mov qword [r13 + 8], 0                   ;提前将“当前任务的PCB指针域”清零
         mov qword [r13 + 16], 0                  ;将当前处理器的编号设置为#0
         mov [r13 + 24], rsp                      ;设置当前处理器的专属栈
         lea rax, [r13 + 128]                     ;TSS开始于专属数据区内偏移为128的地方
         call make_tss_descriptor
         mov qword [rbx + 32], rsi                ;TSS描述符的低64位
         mov qword [rbx + 40], rdi                ;TSS描述符的高64位

         add word [r15 + 2], 48                   ;4个段描述符和1个TSS描述符的总字节数
         lgdt [r15 + 2]

         mov cx, 0x0040                           ;TSS描述符的选择子
         ltr cx

         ;将处理器专属数据区首地址保存到当前处理器的型号专属寄存器IA32_KERNEL_GS_BASE
         mov ecx, 0xc000_0102                     ;IA32_KERNEL_GS_BASE
         mov rax, r13                             ;只用EAX
         mov rdx, r13
         shr rdx, 32                              ;只用EDX
         wrmsr

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

         ;以下初始化高级可编程中断控制器APIC。在计算机启动后，BIOS已经对LAPIC和IOAPIC
         ;做了初始化并创建了相关的高级配置和电源管理接口（ACPI）表项。可以从中获取多处理
         ;器和APIC信息。英特尔架构的个人计算机（IA-PC）从1MB物理内存中搜索获取；启用可
         ;扩展固件接口（EFI或者叫UEFI）的计算机需使用EFI传递的EFI系统表指针定位相关表
         ;格并从中获取多处理器和APIC信息。为简单起见，我们采用前一种传统的方式。请注意虚
         ;拟机的配置！

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
         jne .vcpi_1
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
  .vcpi_1:
         mov ebx, [rbx + 16]                      ;得到根系统描述表（RSDT）的物理地址
         ;以下，开始在RSDT中遍历搜索多APIC描述表（MADT）
         mov edi, [ebx + 4]                       ;获得RSDT的长度（以字节计）
         add edi, ebx                             ;计算RSDT上边界的物理位置
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
         add rdi, r11                             ;RDI:MADT上部边界的物理地址
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

         ;以下安装新任务认领中断的处理过程
         mov r9, [rel position]
         lea rax, [r9 + new_task_notify_handler]  ;得到中断处理过程的线性地址
         call make_interrupt_gate                 ;位于core_utils64_mp.wid

         cli
         mov r8, 0xfe
         call mount_idt_entry                     ;位于core_utils64_mp.wid
         sti

         ;以下安装时间片到期中断的处理过程
         mov r9, [rel position]
         lea rax, [r9 + time_slice_out_handler]   ;得到中断处理过程的线性地址
         call make_interrupt_gate                 ;位于core_utils64_mp.wid

         cli
         mov r8, 0xfd
         call mount_idt_entry                     ;位于core_utils64_mp.wid
         sti

         ;以下安装系统管理中断的处理过程
         mov r9, [rel position]
         lea rax, [r9 + system_management_handler]
         call make_interrupt_gate                 ;位于core_utils64_mp.wid

         cli
         mov r8, 0xfc
         call mount_idt_entry                     ;位于core_utils64_mp.wid
         sti

         ;以下开始初始化应用处理器AP。先将初始化代码复制到物理内存最低端的选定位置
         mov rsi, [rel position]
         lea rsi, [rsi + section.ap_init_block.start]
         mov rdi, AP_START_UP_ADDR
         mov rcx, ap_init_tail - ap_init
         cld
         repe movsb

         ;所有处理器都应当在初始化期间递增应答计数值
         inc byte [rel ack_cpus]                  ;BSP自己的应答计数值

         ;给其它处理器发送INIT IPI和SIPI，命令它们初始化自己
         mov rsi, LAPIC_START_ADDR                ;Local APIC的线性地址
         mov dword [rsi + 0x310], 0
         mov dword [rsi + 0x300], 0x000c4500      ;先发送INIT IPI

         ;以下发送两次Start up IPI
         mov dword [rsi + 0x300], (AP_START_UP_ADDR >> 12) | 0x000c4600
         mov dword [rsi + 0x300], (AP_START_UP_ADDR >> 12) | 0x000c4600

         mov al, [rel num_cpus]
  .wcpus:
         cmp al, [rel ack_cpus]
         jne .wcpus                               ;等待所有应用处理器的应答

         ;显示已应答的处理器的数量信息
         mov r15, [rel position]

         xor r8, r8
         mov r8b, [rel ack_cpus]
         lea rbx, [r15 + buffer]
         call bin64_to_dec
         call put_string64

         lea rbx, [r15 + cpu_init_ok]
         call put_string64                        ;位于core_utils64_mp.wid

         mov rdi, IOAPIC_START_ADDR               ;I/O APIC的线性地址

         ;8254定时器。对应I/O APIC的IOREDTBL2
         mov dword [rdi], 0x14                    ;对应8254定时器。
         mov dword [rdi + 0x10], 0x000000fc       ;不屏蔽；物理模式；固定模式；向量0xfc
         mov dword [rdi], 0x15
         mov dword [rdi + 0x10], 0x00000000       ;Local APIC ID：0

         ;以下开始创建系统外壳任务（进程）
         mov r8, 50
         call create_process

         jmp ap_to_core_entry.do_idle             ;去处理器集结休息区 :)

;===============================================================================
section ap_init_block vstart=0

         bits 16                                  ;应用处理器AP从实模式开始执行

ap_init:                                          ;应用处理器AP的初始化代码
         mov ax, AP_START_UP_ADDR >> 4
         mov ds, ax

         SET_SPIN_LOCK al, byte [lock_var]        ;自旋直至获得锁

         mov ax, SDA_PHY_ADDR >> 4                ;切换到系统数据区
         mov ds, ax

         ;加载描述符表寄存器GDTR
         lgdt [2]                                 ;实模式下只加载6个字节的内容

         in al, 0x92                              ;南桥芯片内的端口
         or al, 0000_0010B
         out 0x92, al                             ;打开A20

         cli                                      ;中断机制尚未工作

         mov eax, cr0
         or eax, 1
         mov cr0, eax                             ;设置PE位

         ;以下进入保护模式... ...
         jmp 0x0008: AP_START_UP_ADDR + .flush    ;清流水线并串行化处理器

         [bits 32]
  .flush:
         mov eax, 0x0010                          ;加载数据段(4GB)选择子
         mov ss, eax                              ;加载堆栈段(4GB)选择子
         mov esp, 0x7e00                          ;堆栈指针

         ;令CR3寄存器指向4级头表（保护模式下的32位CR3）
         mov eax, PML4_PHY_ADDR                   ;PCD=PWT=0
         mov cr3, eax

         ;开启物理地址扩展PAE
         mov eax, cr4
         bts eax, 5
         mov cr4, eax

         ;设置型号专属寄存器IA32_EFER.LME，允许IA_32e模式
         mov ecx, 0x0c0000080                     ;指定型号专属寄存器IA32_EFER
         rdmsr
         bts eax, 8                               ;设置LME位
         wrmsr

         ;开启分页功能
         mov eax, cr0
         bts eax, 31                              ;置位CR0.PG
         mov cr0, eax

         ;进入64位模式
         jmp CORE_CODE64_SEL:AP_START_UP_ADDR + .to64
  .to64:

         bits 64

         ;转入内核中继续初始化（使用高端线性地址）
         mov rbx, UPPER_CORE_LINEAR + ap_to_core_entry
         jmp rbx

  lock_var  db 0

ap_init_tail:

;===============================================================================
section core_tail
core_end:
