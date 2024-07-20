;c06_shell.asm:系统外壳程序，2022-1-19。用于模拟一个操作系统用户接口，比如Linux控制台

;===============================================================================
section shell_header                              ;外壳程序头部
  length       dq shell_end                       ;#0：外壳程序的总长度（字节数）
  entry        dq start                           ;#8：外壳入口点
  linear       dq 0                               ;#16：外壳加载的虚拟（线性）地址

;===============================================================================
section shell_data                                ;外壳程序数据段
  shell_msg    times 128 db 0

  msg0         db "OS SHELL on CPU ", 0
  pcpu         times 32 db 0                      ;处理器编号的文本
  msg1         db " -", 0

  time_buff    times 32 db 0                      ;当前时间的文本


;===============================================================================
section shell_code                                ;外壳程序代码段

%include "..\common\user_static64.lib"

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
         bits 64

main:
         ;这里可显示一个界面，比如Windows桌面或者Linux控制台窗口，用于接收用户
         ;输入的命令，包括显示磁盘文件、设置系统参数或者运行一个程序。我们的系
         ;统很简单，所以不提供这些功能。

         ;以下， 模拟按用户的要求运行8个程序......
         mov r8, 100
         mov rax, 3
         syscall
         syscall
         syscall
         syscall
         syscall
         syscall
         syscall
         syscall                                  ;用同一个副本创建8个任务

         mov rax, 0
         syscall                                  ;可用显示行，DH=行号
         mov dl, 0
         mov r9b, 0x5f

         mov r12, [rel linear]
  _time:
         lea rbx, [r12 + time_buff]
         mov rax, 1
         syscall

         mov rax, 6                               ;获得当前处理器的编号
         syscall
         mov r8, rax
         lea rbx, [r12 + pcpu]
         call bin64_to_dec                        ;将处理器的编号转换为字符串

         lea rdi, [r12 + shell_msg]
         mov byte [rdi], 0

         lea rsi, [r12 + msg0]
         call string_concatenates                 ;字符串连接，和strcat相同

         lea rsi, [r12 + pcpu]
         call string_concatenates                 ;字符串连接，和strcat相同

         lea rsi, [r12 + msg1]
         call string_concatenates                 ;字符串连接，和strcat相同

         lea rsi, [r12 + time_buff]
         call string_concatenates                 ;字符串连接，和strcat相同

         mov rbx, rdi
         mov rax, 2
         syscall

         jmp _time

;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
start:    ;程序的入口点
         call main
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
shell_end:
