;global_defs.wid:系统全局使用的常量定义。李忠，2021-09-05

;定义地址的，至少按16字节对齐！！！与分页有关的地址必须按4KB对齐！！！

%ifndef _GLOBAL_DEFS_
   %define _GLOBAL_DEFS_

   SDA_PHY_ADDR        equ     0x00007e00	;系统数据区的起始物理地址
   PML5_PHY_ADDR       equ     0x00009000	;内核5级头表物理地址
   PML4_PHY_ADDR       equ     0x0000a000	;内核4级头表物理地址
   PDPT_PHY_ADDR       equ     0x0000b000	;对应于低端2MB的内核页目录指针表物理地址
   PDT_PHY_ADDR        equ     0x0000c000	;对应于低端2MB的页目录表物理地址
   PT_PHY_ADDR         equ     0x0000d000	;对应于低端2MB的内核页表的物理地址
   IDT_PHY_ADDR        equ     0x0000e000	;中断描述符表的物理地址
   LDR_PHY_ADDR        equ     0x0000f000	;用于安装内核加载器的起始物理地址
   GDT_PHY_ADDR        equ     0x00010000	;全局描述符表GDT的物理地址
   CORE_PHY_ADDR       equ     0x00020000	;内核的起始物理地址
   COR_PDPT_ADDR       equ     0x00100000	;从这个物理地址开始的1MB是内核的254个
	                                        ;页目录指针表
   LDR_START_SECTOR    equ     1      	        ;内核加载器在硬盘上的起始逻辑扇区号
   COR_START_SECTOR    equ     9      	        ;内核程序在硬盘上的起始逻辑扇区号

   ;虚拟内存空间的高端起始于线性地址0xffff800000000000
   UPPER_LINEAR_START  equ     0xffff800000000000

   UPPER_CORE_LINEAR   equ     UPPER_LINEAR_START + CORE_PHY_ADDR	;内核的高端线性地址
   UPPER_TEXT_VIDEO    equ     UPPER_LINEAR_START + 0x000b8000	        ;文本显示缓冲区的高
	                                                                ;端起始线性地址
   UPPER_SDA_LINEAR    equ     UPPER_LINEAR_START + SDA_PHY_ADDR	;系统数据区的高端线
	                                                                ;性地址
   UPPER_GDT_LINEAR    equ     UPPER_LINEAR_START + GDT_PHY_ADDR	;GDT的高端线性地址
   UPPER_IDT_LINEAR    equ     UPPER_LINEAR_START + IDT_PHY_ADDR	;IDT的高端线性地址

   ;与全局描述符表有关的选择子定义，及内存管理有关的常量定义
   CORE_CODE64_SEL     equ     0x0018	;内核代码段的描述符选择子（RPL=00）
   CORE_STACK64_SEL    equ     0x0020	;内核栈段的描述符选择子（RPL=00）
   RESVD_DESC_SEL      equ     0x002b	;保留的描述符选择子
   USER_CODE64_SEL     equ     0x003b	;3特权级代码段的描述符选择子（RPL=11）
   USER_STACK64_SEL    equ     0x0033	;3特权级栈段的描述符选择子（RPL=11）

   PHY_MEMORY_SIZE     equ     32    	;物理内存大小（MB），要求至少3MB
   CORE_ALLOC_START    equ     0xffff800000200000	;在虚拟地址空间高端（内核）分配内存
			;时的起始地址
   USER_ALLOC_START    equ     0x0000000000000000	;在每个任务虚拟地址空间低端分配内存
			;时的起始地址

   ;创建任务时，需要分配一个物理页作为新任务的4级头表，并分配一个临时的线性地址来初始化这个页
   NEW_PML4_LINEAR     equ     0xffffff7ffffff000	;用来映射新任务4级头表的线性地址

   LAPIC_START_ADDR    equ     0xffffff7fffffe000	;LOCAL APIC寄存器的起始线性地址
   IOAPIC_START_ADDR   equ     0xffffff7fffffd000	;I/O APIC寄存器的起始线性地址

   AP_START_UP_ADDR    equ     0x0000f000 	;应用处理器（AP）启动代码的物理地址

   SUGG_PREEM_SLICE    equ     55          	;推荐的任务/线程抢占时间片长度（毫秒）

   ;多处理器环境下的自旋锁加锁宏。需要两个参数：寄存器，以及一个对应宽度的锁变量
   %macro   SET_SPIN_LOCK 2               	;两个参数，分别是寄存器%1和锁变量%2
            %%spin_lock:
                       cmp %2, 0           	;锁是释放状态吗？
                       je %%get_lock      	;获取锁
                       pause
                       jmp %%spin_lock    	;继续尝试获取锁
            %%get_lock:
                       mov %1, 1
                       xchg %1, %2
                       cmp %1, 0          	;交换前为零？
                       jne %%spin_lock   	;已有程序抢先加锁，失败重来
   %endmacro

%endif

