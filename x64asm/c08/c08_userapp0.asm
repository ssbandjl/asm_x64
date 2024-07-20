;应用程序，李忠，2022-11-27
;文件：c08_userapp0.asm
;演示数据竞争所引发的数据一致性问题

;===============================================================================
section app_header                                ;应用程序头部
  length       dq app_end                         ;#0：用户程序的总长度（字节数）
  entry        dq start                           ;#8：用户程序入口点
  linear       dq 0                               ;#16：用户程序加载的虚拟（线性）地址

;===============================================================================
section app_data                                  ;应用程序数据段

  tid_prex     db "Thread ", 0
  thrd_msg     db " has completed the calculation.", 0
  share_d      dq 0

;===============================================================================
section app_code                                  ;应用程序代码段

%include "..\common\user_static64.lib"

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
         bits 64

thread_procedure1:
         mov rbp, rsp                             ;RBP访问栈中数据，高级语言中的局部变量。
         sub rsp, 32

         mov rax, 10                              ;分配内存
         mov rdx, 160                             ;160个字节
         syscall
         mov [rbp-8], r13                         ;RBP-8->总字符串缓冲区的线性地址

         add r13, 128
         mov [rbp-16], r13                        ;RBP-16->用来保存线程标识的文本

         mov rax, 8                               ;获得当前线程的标识
         syscall
         mov r8, rax
         mov rbx, [rbp-16]
         call bin64_to_dec                        ;将线程标识转换为字符串

         mov rcx, 500000000
  .plus_one:
         inc qword [rel share_d]
         loop .plus_one

         mov r12, [rel linear]                    ;当前程序加载的起始线性地址

         mov rdi, [rbp-8]                         ;总字符串缓冲区的线性地址
         mov byte [rdi], 0

         lea rsi, [r12 + tid_prex]
         call string_concatenates                 ;字符串连接，和strcat相同

         mov rsi, [rbp-16]
         call string_concatenates

         lea rsi, [r12 + thrd_msg]
         call string_concatenates                 ;字符串连接，和strcat相同

         mov rax, 0                               ;确定当前线程可以使用的显示行
         syscall                                  ;可用显示行，DH=行号

         mov dl, 0
         mov r9b, 0x0f

         mov rax, 2                               ;在指定坐标显示字符串
         mov rbx, rdi
         syscall

         mov rsp, rbp                             ;栈平衡到返回位置
         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
thread_procedure2:
         mov rbp, rsp                             ;RBP访问栈中数据，高级语言中的局部变量。
         sub rsp, 32

         mov rax, 10                              ;分配内存
         mov rdx, 160                             ;160个字节
         syscall
         mov [rbp-8], r13                         ;RBP-8->总字符串缓冲区的线性地址

         add r13, 128
         mov [rbp-16], r13                        ;RBP-16->用来保存线程标识的文本

         mov rax, 8                               ;获得当前线程的标识
         syscall
         mov r8, rax
         mov rbx, [rbp-16]
         call bin64_to_dec                        ;将线程标识转换为字符串

         mov rcx, 500000000
  .minus_one:
         dec qword [rel share_d]
         loop .minus_one

         mov r12, [rel linear]                    ;当前程序加载的起始线性地址

         mov rdi, [rbp-8]                         ;总字符串缓冲区的线性地址
         mov byte [rdi], 0

         lea rsi, [r12 + tid_prex]
         call string_concatenates                 ;字符串连接，和strcat相同

         mov rsi, [rbp-16]
         call string_concatenates

         lea rsi, [r12 + thrd_msg]
         call string_concatenates                 ;字符串连接，和strcat相同

         mov rax, 0                               ;确定当前线程可以使用的显示行
         syscall                                  ;可用显示行，DH=行号

         mov dl, 0
         mov r9b, 0x0f

         mov rax, 2                               ;在指定坐标显示字符串
         mov rbx, rdi
         syscall

         mov rsp, rbp                             ;栈平衡到返回位置
         ret

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
main:
         mov rdi, [rel linear]                    ;当前程序加载的起始线性地址

         mov rax, 7                               ;创建线程

         lea rsi, [rdi + thread_procedure1]       ;线程例程的线性地址
         syscall                                  ;创建第一个线程
         mov [rel .thrd_1], rdx                   ;保存线程1的标识

         lea rsi, [rdi + thread_procedure2]       ;线程例程的线性地址
         syscall                                  ;创建第二个线程
         mov [rel .thrd_2], rdx                   ;保存线程2的标识

         mov rax, 11
         mov rdx, [rel .thrd_1]
         syscall                                  ;等待线程1结束

         mov rdx, [rel .thrd_2]
         syscall                                  ;等待线程2结束

         mov r12, [rel linear]                    ;当前程序加载的起始线性地址

         lea rdi, [r12 + .main_buf]               ;总字符串缓冲区的线性地址
         mov byte [rdi], 0

         lea rsi, [r12 + .main_msg]
         call string_concatenates                 ;字符串连接，和strcat相同

         mov r8, [rel share_d]
         lea rbx, [r12 + .main_dat]
         call bin64_to_dec                        ;将共享变量的值转换为字符串

         mov rsi, rbx
         call string_concatenates                 ;字符串连接，和strcat相同

         mov rax, 0                               ;确定当前线程可以使用的显示行
         syscall                                  ;可用显示行，DH=行号

         mov dl, 0                                ;列坐标
         mov r9b, 0x0f                            ;文本颜色

         mov rax, 2                               ;在指定坐标显示字符串
         mov rbx, rdi
         syscall

         ret

  .thrd_1       dq 0                              ;线程1的标识
  .thrd_2       dq 0                              ;线程2的标识

  .main_msg db "The result after calculation by two threads is:", 0
  .main_dat times 32 db 0
  .main_buf times 128 db 0

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
start:   ;程序的入口点

         ;这里放置初始化代码，比如初始化全局数据（变量）

         call main

         ;这里放置清理代码

         mov rax, 5                               ;终止任务
         syscall

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
app_end:
