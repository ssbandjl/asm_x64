;c07_userapp.asm:多线程应用程序，李忠，2022-10-29

;===============================================================================
section app_header                                ;应用程序头部
  length       dq app_end                         ;#0：用户程序的总长度（字节数）
  entry        dq start                           ;#8：用户程序入口点
  linear       dq 0                               ;#16：用户程序加载的虚拟（线性）地址

;===============================================================================
section app_data                                  ;应用程序数据段

  tid_prex     db "Thread ", 0                    ;线程标识前缀文本
  pid_prex     db " <Task ", 0                    ;进程标识前缀文本
  cpu_prex     db "> on CPU ", 0                  ;处理器标识的前缀文本
  delim        db " do 1+2+3+...+", 0             ;分隔文本
  equal        db "=", 0                          ;等于号

;===============================================================================
section app_code                                  ;应用程序代码段

%include "..\common\user_static64.lib"

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
         bits 64

thread_procedure:
         mov rbp, rsp                             ;RBP访问栈中数据，高级语言中的局部变量。
         sub rsp, 56

         mov rax, 10                              ;分配内存
         mov rdx, 288                             ;288个字节
         syscall
         mov [rbp-8], r13                         ;RBP-8->总字符串缓冲区的线性地址

         add r13, 128
         mov [rbp-16], r13                        ;RBP-16->用来保存线程标识的文本

         add r13, 32
         mov [rbp-24], r13                        ;RBP-24->用来保存任务标识的文本

         add r13, 32
         mov [rbp-32], r13                        ;RBP-32->用来保存处理器编号的文本

         add r13, 32
         mov [rbp-40], r13                        ;RBP-40->用来保存加数的文本

         add r13, 32
         mov [rbp-48], r13                        ;RBP-48->用来保存累加和的文本

         mov rax, 8                               ;获得当前线程的标识
         syscall
         mov r8, rax
         mov rbx, [rbp-16]
         call bin64_to_dec                        ;将线程标识转换为字符串

         mov rax, 4                               ;获得当前任务（进程）的标识
         syscall
         mov r8, rax
         mov rbx, [rbp-24]
         call bin64_to_dec                        ;将进程标识转换为字符串

         mov r12, [rel linear]                    ;当前程序加载的起始线性地址

         mov rax, 0                               ;确定当前程序可以使用的显示行
         syscall                                  ;可用显示行，DH=行号

         mov dl, 0
         mov r9b, 0x0f

         mov r8, 0                                ;R8用于存放累加和
         mov r10, 1                               ;R10用于提供加数
  .cusum:
         add r8, r10
         mov rbx, [rbp-48]
         call bin64_to_dec                        ;本次相加的结果转换为字符串

         xchg r8, r10
         mov rbx, [rbp-40]
         call bin64_to_dec                        ;本次的加数转换为字符串

         xchg r8, r10

         mov rax, 6                               ;获得当前处理器的编号
         syscall

         push r8
         mov r8, rax
         mov rbx, [rbp-32]
         call bin64_to_dec                        ;将处理器的编号转换为字符串
         pop r8

         mov rdi, [rbp-8]
         mov byte [rdi], 0

         lea rsi, [r12 + tid_prex]
         call string_concatenates                 ;字符串连接，和strcat相同

         mov rsi, [rbp-16]
         call string_concatenates

         lea rsi, [r12 + pid_prex]
         call string_concatenates                 ;字符串连接，和strcat相同

         mov rsi, [rbp-24]
         call string_concatenates

         lea rsi, [r12 + cpu_prex]
         call string_concatenates

         mov rsi, [rbp-32]
         call string_concatenates

         lea rsi, [r12 + delim]
         call string_concatenates

         mov rsi, [rbp-40]
         call string_concatenates

         lea rsi, [r12 + equal]
         call string_concatenates

         mov rsi, [rbp-48]
         call string_concatenates

         mov rax, 2                               ;在指定坐标显示字符串
         mov rbx, rdi
         syscall

         inc r10
         cmp r10, 10000;000
         jle .cusum

         mov rsp, rbp                             ;栈平衡到返回位置
         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
main:
         mov rsi, [rel linear]                    ;当前程序加载的起始线性地址

         lea rsi, [rsi + thread_procedure]        ;线程例程的线性地址
         mov rax, 7                               ;创建线程
         syscall                                  ;创建第一个线程
         syscall                                  ;创建第二个线程

         call thread_procedure                    ;普通的例程调用（可返回）

         ret
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
start:   ;程序的入口点

         ;这里放置初始化代码，比如初始化全局数据（变量）

         call main

         ;这里放置清理代码

         mov rax, 5                               ;终止任务
         syscall

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
app_end:
