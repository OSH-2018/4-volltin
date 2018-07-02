# Meltdown 攻击实验

- [Meltdown 攻击实验](#meltdown-%E6%94%BB%E5%87%BB%E5%AE%9E%E9%AA%8C)
  - [实验原理](#%E5%AE%9E%E9%AA%8C%E5%8E%9F%E7%90%86)
    - [Meltdown 简介](#meltdown-%E7%AE%80%E4%BB%8B)
    - [原论文简介](#%E5%8E%9F%E8%AE%BA%E6%96%87%E7%AE%80%E4%BB%8B)
    - [攻击原理之乱序执行](#%E6%94%BB%E5%87%BB%E5%8E%9F%E7%90%86%E4%B9%8B%E4%B9%B1%E5%BA%8F%E6%89%A7%E8%A1%8C)
    - [攻击原理之异常处理](#%E6%94%BB%E5%87%BB%E5%8E%9F%E7%90%86%E4%B9%8B%E5%BC%82%E5%B8%B8%E5%A4%84%E7%90%86)
    - [攻击原理之地址空间](#%E6%94%BB%E5%87%BB%E5%8E%9F%E7%90%86%E4%B9%8B%E5%9C%B0%E5%9D%80%E7%A9%BA%E9%97%B4)
    - [攻击方案](#%E6%94%BB%E5%87%BB%E6%96%B9%E6%A1%88)
  - [实验环境](#%E5%AE%9E%E9%AA%8C%E7%8E%AF%E5%A2%83)
    - [机器环境](#%E6%9C%BA%E5%99%A8%E7%8E%AF%E5%A2%83)
    - [操作系统环境](#%E6%93%8D%E4%BD%9C%E7%B3%BB%E7%BB%9F%E7%8E%AF%E5%A2%83)
  - [实验准备](#%E5%AE%9E%E9%AA%8C%E5%87%86%E5%A4%87)
    - [关闭系统中的保护](#%E5%85%B3%E9%97%AD%E7%B3%BB%E7%BB%9F%E4%B8%AD%E7%9A%84%E4%BF%9D%E6%8A%A4)
      - [KASLR](#kaslr)
        - [KASLR 原理](#kaslr-%E5%8E%9F%E7%90%86)
        - [绕过 KASLR](#%E7%BB%95%E8%BF%87-kaslr)
          - [Intel TSX](#intel-tsx)
          - [Meltdown](#meltdown)
        - [关闭 KASLR](#%E5%85%B3%E9%97%AD-kaslr)
      - [KPTI (KAISER)](#kpti-kaiser)
        - [KPTI 原理](#kpti-%E5%8E%9F%E7%90%86)
        - [关闭 KPTI](#%E5%85%B3%E9%97%AD-kpti)
    - [检测漏洞](#%E6%A3%80%E6%B5%8B%E6%BC%8F%E6%B4%9E)
  - [攻击模型](#%E6%94%BB%E5%87%BB%E6%A8%A1%E5%9E%8B)
  - [攻击过程](#%E6%94%BB%E5%87%BB%E8%BF%87%E7%A8%8B)
  - [结果分析](#%E7%BB%93%E6%9E%9C%E5%88%86%E6%9E%90)
  - [局限性](#%E5%B1%80%E9%99%90%E6%80%A7)
  - [参考资料](#%E5%8F%82%E8%80%83%E8%B5%84%E6%96%99)

## 实验原理

### Meltdown 简介

Meltdown 是一个影响 Intel CPU 和 ARM Cortex A75 等现代处理器的严重漏洞，影响范围十分广泛，且攻击易于实施，无法在操作系统内进行防御。使用 Meltdown 不需要软件的特定缺陷，只要求攻击发起者和攻击对象使用同一个的地址空间，该漏洞暴露了目前体系结构中一个本质的问题，如何真正做到隔离，如何在处理器使用各种复杂的机制的条件下（如：分支预测，乱序执行等）下做好隔离。

### 原论文简介

计算机系统安全的一个很大原因是隔离性，而内存隔离性在隔离性中体现得最为重要，如果内存隔离性被破坏那么系统上的任何一个软件都不再拥有自己的私有内存空间来存放敏感信息，甚至连操作系统本身的敏感信息也会被读取到，那么整个操作系统上的任何一个软件都可以得到敏感数据，如：键入的密码，保存的凭证等等。

为了解决这个隔离问题，计算机组成中的硬件和操作系统协同工作，用一个关键的 bit 来实现两种不同的权限登记，这个 bit 叫做 supervisor bit，他标记的两种权限等分别是用户模式和内核模式，对应的权限是只能访问用户空间和可以访问内核空间，内核空间包含了整个系统很多的敏感信息，其中也包含了某些映射过来的用户数据，如果能被轻松读到那个整个计算机系统的安全性就无从谈起。

正常情况下我们用系统调用或中断的方法来陷入内核模式，如果我们不经过这一步直接访问，理想情况下，则会产生一个异常访问，结果不会被读取。进一步，如果采用乱序执行的方法来优化这一过程，那么只要处理得当，再乱序发射之后能检测到这一异常行为并且丢弃掉得到的结果，整个过程仍然能避免内存被异常读取，从处理器体系结构角度来看这也是没有问题的。

然而 Meltdown 正是给出了一个回答，指令的执行并不是理想情况下发生的，因此产生异常访问后，结果虽然无法通过传统的途径被程序所获得，但是如果利用乱序执行的特性使得读取到的数据在该用户空间留下可以观测到的痕迹，而这种可以观测到的痕迹则是由 cache 带来的。利用 cache 留下的这些细微的可观测的差异，足以将没有权限读取到的内存通过统计时间给观测出来。

不同的机器上可能有不同的速度，不过 Meltdown 在某些情况下可以以 502 KB/s 的速度将内核空间的内存读取出来。

论文摘要中还提到对 Meltdown 的防御措施，一个最简单的方法就是部署 KAISER 技术。KAISER 技术本来是用于解决针对 KASLR 的边信道攻击的，但是意外之中也解决了 Meltdown 的问题，现在主流的操作系统（Windows macOS Linux）都已经向用户发布了新版本来解决这个问题，使用新版本之后这个漏洞将不会明显的危害。

### 攻击原理之乱序执行

正如我们在学习组成原理时讨论过的问题，处理器流水线的 Stall 是一个非常影响整体性能的一个因素，为了提高整体性能，我们就需要找到一种方法来避免 Stall，换言之，将处理器的每个时间都充分利用。这样的一个优化技术叫做乱序执行，乱序执行是指不按照编程的顺序来执行指令的一种方法，如果当前指令需要的资源是可以满足的，那么就执行当前指令，如果不是，则尝试延后执行该指令，取而代之的是取出后面的资源可以满足的指令来提前运行，只要恰当地处理了前后的顺序问题，不即时提交对状态的更改，那么最后的结果就是符合体系结构定义的期望结果。

具体来说，CPU 执行单元中设置一个保留站，用于读取和保存操作数，操作结果。为了解决 Harzard 问题，我们需要有一个寄存器重命名机制，可以在操作数一旦产生的时候就进行计算，而不用等待上一条指令提交结果。这两个机制结合起来，实现了乱序执行，顺序依赖的结果。

可以看出，乱序执行中一个很大的特点就是，一条指令可能在之前的指令提交结果前就已经执行完毕，这也是之后 Meltdown 能够攻击的重要基础。

### 攻击原理之异常处理

如果指令乱序执行中遇到了异常，那么其后的指令都应该被撤销掉，具体实现机制是，产生异常的指令打上特殊的标记，在顺序提交的时候打断后续的提交，实现的效果则是清空了后面的指令的一切影响——理论上。

然而事实上真是这样吗，其实并不是，因为后面的指令可能使用了访存指令，而对内存的读取会在 cache 上造成副作用，这正是 Meltdown 能够攻击的直接原因。

### 攻击原理之地址空间

操作系统和处理器在软硬件两方面配合实现了分页机制，简单来说就是实现了一个用户程序的内存隔离，并且提供虚地址到实地址的转换，这通过页表完成，页表除了这些信息，还包含了访问权限的标记，简单来说这个标记区分了用户模式和内核模式能访问到的页。

### 攻击方案

综合以上的攻击原理，我们可以理解 Meltdown 攻击的方案，用汇编给出一个最小的示范，即：

```assembly
# 非法访问，会产生异常
mov rax byte[x]
# 偏移量，之所以乘以 4096 是为了克服缓存时相邻内存会被缓存的设定
shl rax 0xC
# 访问一个可以访问的空间，然而偏移量中的信息原本是不能被读取的
mov rbx qword [rbx + rax]  // [rbx] 为用户空间的一个array，合法操作
```

我们期望的情况是： rax 不应该被第三条指令获取到，因为早就因为异常而清零了，然而由于乱序执行的副作用，rbx + rax 这个地址如果不在 cache 中就会被缓存，而之后根据缓存的情况，我们就能推测出这个被缓存的地址的值（rbx + rax）进而得到 x 地址处的值，其中 x 地址原本是不能被访问的。

## 实验环境

### 机器环境

使用一个 Linux 虚拟机完成本次试验：

```
model name       : Intel(R) Core(TM) i7-6700HQ CPU @ 2.60GHz
bugs             : cpu_meltdown spectre_v1 spectre_v2
address sizes    : 42 bits physical, 48 bits virtual
```

### 操作系统环境

使用的发行版为 Debian：

```shell
# uanme -a
Linux victim 4.9.0-6-amd64 #1 SMP Debian 4.9.88-1+deb9u1 (2018-05-07) x86_64 GNU/Linux
```

使用到的软件均为常见软件，如 make 等。

## 实验准备

### 关闭系统中的保护

由于我使用了新版本的操作系统，为了本次试验能顺利进行，进行以下操作，并附有理由。

- 关闭 KASLR
- 关闭 KPTI (KAISER)

#### KASLR

##### KASLR 原理

KASLR 是 Kernel Address Space Layout Randomization 的缩写，即内核地址空间布局随机化，这一机制在系统启动时生效，将系统内核的代码随机加载到内存的一个地址，这使得攻击者更难展开攻击，因为难以得到内核代码确切的地址。

不过这个机制只提供了一个很有限的保护作用，并且由于这个随机化仅仅发生在启动阶段，整个系统运行阶段不会再次变化。

##### 绕过 KASLR

有多种方案可以绕过 KASLR，这里列举 Meltdown 原论文中应用的几个例子：

[9] GRUSS, D., MAURICE, C., FOGH, A., LIPP, M., AND MANGARD, S. Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR. In CCS (2016).

[13] HUND, R., WILLEMS, C., AND HOLZ, T. Practical Timing Side Channel Attacks against Kernel Space ASLR. In S&P (2013).

[17] JANG, Y., LEE, S., AND KIM, T. Breaking Kernel Address Space Layout Randomization with Intel TSX. In CCS (2016).

下面举例说明：

###### Intel TSX

即原论文引用 [17] 提出的一种侧信道攻击方案，可以以小于一秒的时间，准确率 99%-100%，在主流操作系统上实现去掉 KASLR 的随机化保护。

###### Meltdown

Meltdown 本身也可以泄漏 KASLR 的随机偏移量。这里先假设我们有了一个 Meltdown 的利用模型（实际上还没有），提供以下接口：

- `int mread(size_t addr)` ，其作用是读取 `addr` 这个地址的内容（即使是无权读取的）；

- `size_t v2p(sizr_t vaddr)`，通过 `/proc` 下的信息，返回 `vaddr` 这个虚拟地址对应的物理地址。由于需要读取 `/proc` 下的信息，所以需要给 root 权限。 

那么以下伪代码表示的流程便可以“试”出这个随机偏移量（记为 `k_offset` )。

```c
for k_offset in (k_offset_min ... k_offset_max)
{
    char* var = get_a_var();
    *var = 'a';
    char* addr_before_kaslr = v2p(var);
    char* guess_addr_after_kaslr = addr_before_kaslr + k_offset;
    char result = mread(guess_addr_after_kaslr);
    if (result == 'a')
    {
        // k_offset is correct!
    } else {
        // k_offset is incorrect.
    }
}
```

我们在一台没有开启 KASLR 的机器上尝试一下上面的代码，取 `k_offset_min` 为默认值（`0xffff880000000000`）：

在我的机器上，其第一次尝试的结果类似于：

```
var = 0x7ffe13855ad0
addr_before_kaslr = 0x6eff0ad0
guess_addr_after_kaslr = 0xffff880000000000 + 0x6eff0ad0 = 0xffff88006eff0ad0
```

也就是说，我们向虚拟地址 `0x7ffe13855ad0` 写入 `a`，经过查询发现其对应的物理地址是 `0x6eff0ad0`，而经过映射，加上我们猜测的物理地址偏移量，地址为 `0xffff88006eff0ad0`，我们在这里读取到了 `a`。这说明我们猜测的偏移量是正确的，这个偏移量在重启之前不会改变。

注意：

- 这里通过虚拟地址查询物理地址是通过读取 `/proc/self/pagemap` 实现的，因此需要 root 权限；
- 为了避免程序执行混乱，这里的 `*var = 'a'` 需要使用一定的技巧，即不被编译器优化的多次写入，来防止因为优化带来的执行顺序不一致的问题；
- 为了正确得到结果，需要设置使用单核，采用 `taskset 0x1` 来运行； 

这段代码的一个实现参考：https://github.com/IAIK/meltdown/blob/master/kaslr.c

关键部分是：

```c
size_t scratch[4096];
size_t var = (size_t)(scratch + 2048);
*(char *)var = 'X';
size_t start = libkdump_virt_to_phys(var);

while (1) {
    /*
    为了解决执行顺序带来的还没有被写入内存的问题，这里写入了多次，并且声明禁止编译器优化。
    反汇编可以看到指令是：
      40068d:       c6 84 24 30 40 00 00    movb   $0x58,0x4030(%rsp)
      400694:       58
      400695:       c6 84 24 30 40 00 00    movb   $0x58,0x4030(%rsp)
      40069c:       58
      40069d:       c6 84 24 30 40 00 00    movb   $0x58,0x4030(%rsp)
      4006a4:       58
      4006a5:       c6 84 24 30 40 00 00    movb   $0x58,0x4030(%rsp)
      4006ac:       58
      4006ad:       c6 84 24 30 40 00 00    movb   $0x58,0x4030(%rsp)
      4006b4:       58
    */
    *(volatile char *)var = 'X';
    *(volatile char *)var = 'X';
    *(volatile char *)var = 'X';
    *(volatile char *)var = 'X';
    *(volatile char *)var = 'X';

    int res = libkdump_read(start + offset + delta);
    
    if (res == 'X') {
      // correct!
      print_offset();
      break;
    } else {
      // incorrect.
      change_delta();
    }
  }
```

##### 关闭 KASLR

经过以上的验证不难得出一个结论：**利用 Meltdown 可以有效的得到 KASLR 的随机偏移。**

所以之后的实验为了方便观察结果，将精力集中在关键步骤上，我们关闭 KASLR，即，使得这个偏移地址是默认的 `0xffff880000000000`，之后不再重复提及。

Linux 内核 4.12 以后 KASLR 是默认开启的，我们在启动参数中加入参数，关闭该机制。

关闭方法：

```shell
# 修改 /etc/default/grub
sudo vim /etc/default/grub
# 在 GRUB_CMDLINE_LINUX_DEFAULT 选项中加入 nokaslr

# 更新 grub
sudo update-grub

# 重启系统
sudo reboot
```

#### KPTI (KAISER)

这里说的 **KPTI**，也称为 **PTI**， **KAISER**，是 **Kernel page-table isolation** 的缩写，是一个增强用户空间和内核空间隔离性的机制。它可以修复（或一定程度上减缓，下面不再重复）Meltdown 带来的问题（需要注意的是，它并不能完全解决这类问题，见后文的“局限性”一节）。

##### KPTI 原理

原论文（Meltdown）中也多次提到 KAISER 这个增强机制一开始并不是为了解决 Meltdown 问题（那个时候 Meltdown 还没有被公布或没有被发现），而是为了解决其他的侧信道攻击的问题，然而 Meltdown 被披露以后大家发现 KAISER 将用户空间与内核空间的页表完全分离是可以修复 Meltdown 的。

程序执行性能上，根据主流的测试结果显示，会带来 5%-30% 的性能损失。

##### 关闭 KPTI

和关闭 KASLR 类似，增加启动参数：

```shell
# 修改 /etc/default/grub
sudo vim /etc/default/grub
# 在 GRUB_CMDLINE_LINUX_DEFAULT 选项中加入 nokaslr

# 更新 grub
sudo update-grub

# 重启系统
sudo reboot
```

### 检测漏洞

使用脚本 https://github.com/speed47/spectre-meltdown-checker 来初步检测漏洞是否可利用

结果为：

```
CVE-2017-5754 [rogue data cache load] aka 'Meltdown' aka 'Variant 3'
* Mitigated according to the /sys interface:  NO  (Vulnerable)
* Kernel supports Page Table Isolation (PTI):  YES
  * PTI enabled and active:  NO
  * Reduced performance impact of PTI:  YES  (CPU supports INVPCID, performance impact of PTI will be greatly reduced)
* Running as a Xen PV DomU:  NO
> STATUS:  VULNERABLE  (PTI is needed to mitigate the vulnerability)
```

初步的检测说明，该机器是容易受到 Meltdown 攻击的，我们可以开展攻击。

## 攻击模型

在实验准备的“绕过 KASLR”中提到 Meltdown 的攻击模型会提供以下接口：

- `int mread(size_t addr) ` ，其作用是读取 `addr` 这个地址的内容（即使是无权读取的）；
- `size_t v2p(sizr_t vaddr)`，通过 `/proc` 下的信息，返回 `vaddr` 这个虚拟地址对应的物理地址。由于需要读取 ``/proc` 下的信息，所以需要给 root 权限。 

实际上我们还需要一个和 `v2p` 相反功能的接口：

- `size_t p2v(sizr_t paddr)`， 通过物理地址得到虚拟地址——仅仅是运算而已。

（坑）

## 攻击过程

（坑）

## 结果分析

（坑）

## 局限性

本实验讨论的攻击方案和防御方案均针对 Meltdown 攻击，对于原理类似的 Spectre 攻击，情况会有不同，如：

- Meltdown 有非常容易实现的软件修复（或降低攻击成功率）的方案，而 Spectre 很难仅仅通过软件方案修复。
- KPTI/KAISER 修复方案仅仅保证针对 Meltdown 攻击的防御效果。

## 参考资料

- 原论文 https://meltdownattack.com/meltdown.pdf
- Wikipedia: ASLR https://en.wikipedia.org/wiki/Address_space_layout_randomization
- Wikipedia: KPTI https://en.wikipedia.org/wiki/Kernel_page-table_isolation
- Differences between ASLR, KASLR and KARL http://www.daniloaz.com/en/differences-between-aslr-kaslr-and-karl/
- https://security.stackexchange.com/questions/176803/meltdown-and-spectre-attacks
- https://meltdownattack.com/
-  https://github.com/speed47/spectre-meltdown-checker
- https://github.com/IAIK/meltdown/