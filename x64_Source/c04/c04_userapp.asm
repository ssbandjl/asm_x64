;c04_userapp.asm:应用程序，李忠，2022-2-2

;===============================================================================
section app_header                                ;应用程序头部
  length       dq app_end                         ;#0：用户程序的总长度（字节数）
  entry        dq start                           ;#8：用户程序入口点
  linear       dq 0                               ;#16：用户程序加载的虚拟（线性）地址

;===============================================================================
section app_data                                  ;应用程序数据段
  app_msg      times 128 db 0                     ;应用程序消息缓冲区
  pid_prex     db "Process ID:", 0                ;进程标识符前缀文本
  pid          times 32 db 0                      ;进程标识符的文本
  delim        db " doing 1+2+3+...+", 0          ;分隔文本
  addend       times 32 db 0                      ;加数的文本
  equal        db "=", 0                          ;等于号
  cusum        times 32 db 0                      ;相加结果的文本

;===============================================================================
section app_code                                  ;应用程序代码段

%include "..\common\user_static64.lib"

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
         bits 64

main:
         mov rax, 0                               ;确定当前程序可以使用的显示行
         syscall                                  ;可用显示行，DH=行号

         mov dl, 0
         mov r9b, 0x0f

         mov r12, [rel linear]                    ;当前程序加载的起始线性地址

         mov rax, 4                               ;获得当前程序（进程）的标识
         syscall
         mov r8, rax
         lea rbx, [r12 + pid]
         call bin64_to_dec                        ;将进程标识转换为字符串

         mov r8, 0                                ;R8用于存放累加和
         mov r10, 1                               ;R10用于提供加数
  .cusum:
         add r8, r10
         lea rbx, [r12 + cusum]
         call bin64_to_dec                        ;本次相加的结果转换为字符串
         xchg r8, r10
         lea rbx, [r12 + addend]
         call bin64_to_dec                        ;本次的加数转换为字符串
         xchg r8, r10

         lea rdi, [r12 + app_msg]
         mov byte [rdi], 0

         lea rsi, [r12 + pid_prex]
         call string_concatenates                 ;字符串连接，和strcat相同
         lea rsi, [r12 + pid]
         call string_concatenates
         lea rsi, [r12 + delim]
         call string_concatenates
         lea rsi, [r12 + addend]
         call string_concatenates
         lea rsi, [r12 + equal]
         call string_concatenates
         lea rsi, [r12 + cusum]
         call string_concatenates

         mov rax, 2                               ;在指定坐标显示字符串
         mov rbx, rdi
         syscall

         inc r10
         cmp r10, 100000
         jle .cusum

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
