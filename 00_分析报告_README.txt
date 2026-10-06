================================================================================
  iOS 第三方 dylib 全面逆向分析报告
  目标文件：ace-第四课-授权靶场.dylib.dylib
================================================================================

【一、前提确认】

1. 文件接收：成功。
   上传文件已收到并完整读取，字节数与 MD5 校验一致：
     文件名   : ace-第四课-授权靶场.dylib.dylib
     大小     : 4,206,864 字节 (4.01 MiB)
     MD5      : 9c5a6c8a6d784ecf4d80253d13ab087b
     文件类型 : Mach-O 64-bit arm64 dynamically linked shared library
                flags: NOUNDEFS | DYLDLINK | TWOLEVEL | WEAK_DEFINES |
                       BINDS_TO_WEAK | NO_REEXPORTED_DYLIBS | HAS_TLV_DESCRIPTORS

2. Ghidra 安装与运行：成功。
     版本     : Ghidra 12.1.4 PUBLIC (2026-09-21 构建)，当前最新正式版
     运行环境 : JDK 21 (Temurin 21.0.12.1) + Python 3.12
     加载器   : Mac OS X Mach-O
     语言/编译器: AARCH64:LE:64:AppleSilicon:default
     分析状态 : 全量自动分析 + 全函数反编译，2753/2753 成功，0 失败
     注：Ghidra 拒绝含中文字符的文件名，故分析时复制为 ASCII 名 target_ace.dylib，
         二进制内容未做任何修改（MD5 与原件一致）。


【二、目标文件总体画像】

  Mach-O 头
    magic        : 0xfeedfacf (MH_MAGIC_64)
    cputype      : 16777228 (arm64)
    filetype     : 6 (MH_DYLIB)
    ncmds        : 29 个加载命令
    flags        : 0x0918085
    安装名       : /Library/1.dylib    (LC_ID_DYLIB)
    平台         : iOS，最低系统 12.0，SDK 26.2，工具链 1230.1.0
    UUID         : f15f00d5-7d43-38aa-88cc-90ed438057a9
    加密         : cryptid = 0 —— 未加密（未套用 App Store 加密壳）

  段与节
    __TEXT   vmaddr 0x0000000  vmsize 0x3e8000  12 个节
    __DATA   vmaddr 0x03e8000  vmsize 0x018000  21 个节
    __LINKEDIT vmaddr 0x0400000 vmsize 0x014000   0 个节
    合计 33 个节

  依赖动态库（16 个）
    CoreFoundation / CoreGraphics / SystemConfiguration / Security /
    Accelerate / QuartzCore / CFNetwork / libz.1 / Foundation / IOKit /
    UIKit / Metal / libSystem.B / libc++.1 / MetalKit / libobjc.A

  关键规模统计（Ghidra 分析结果）
    函数         : 2,753
    类           : 76      命名空间 : 152
    符号总数     : 34,648（Ghidra 符号表；其中 Function 3,200 / Label 31,448 / 外部引用 1,310）
    Mach-O 符号表: 375 条 nlist_64（local 1 / extdef 16 / undef 358）
    导出         : 16
    导入/绑定修复 : 556 条 dyld bind
    代码交叉引用 : 46,328
    数据交叉引用 : 52,194
    已定义字符串 : 2,090；原始扫描字符串 62,161（Ghidra 口径）
    全文件 ASCII 字符串 27,681 / UTF-16LE 字符串 4,909（独立扫描口径）
    数据类型     : 395
    重定位/修复  : 556
    Objective-C  : 643 个选择器、30 个类名、17 个自定义类、6 个协议、444 个选择器引用
    Swift        : 无（不存在 __swift5_* 段，无 $s / _$s 符号，Ghidra 明确判定 "Not a Swift program"）


【三、关键发现】

1. 该 dylib 内含 Dobby 内联 Hook（inline hook）框架
   导出符号直接暴露 Dobby 的公开 API：
     _DobbyCodePatch            —— 代码补丁
     _DobbyInstrument           —— 函数插桩
     _DobbyDestroy              —— 卸载 hook
     _DobbySymbolResolver       —— 符号解析
     _dobby_set_options / _dobby_set_near_trampoline /
     _dobby_register_alloc_near_code_callback
     closure_bridge / closure_trampoline 汇编桩及其边界符号
     _common_closure_bridge_handler
   说明该模块具备在运行时改写任意函数、劫持方法调用的能力。

2. ObjC 类名被系统性混淆
   17 个自定义类的名字全部形如 _0x6D1C8F45、_0xB1D7F3A9、_0xE4A91C73 …，
   属性 / ivar 名同样被混淆（_0xE4C8719B、q0/q1/_q0/_q1 等），
   方法选择器则保留了语义（如 URLSession:dataTask:didReceiveResponse:completionHandler:、
   initWithBuffer:、renderPipelineState 相关），呈现"类名混淆 + 选择器保留"的加固风格。
   唯一未混淆的自定义类是 YYSYNTH_DUMMY_CLASS_UIView_YYAdd，
   指向 YYAdd / YYKit 风格的 UIView 分类实现。

3. 中文游戏 MOD/辅助界面文本（直接可读）
   __cstring 段中保留了明文界面字符串，可直接对应功能：
     基地址: 0x%llX
     自己ID: %llu
     队友ID: %llu
     状态:已锁定 (目标 %d/%d，倒计时 %ds)
     ▲ 追%s ON | 队友ID=%llu | %s
   结合 Dobby hook 框架与 JZSkyEye_UpdateViewReplacement /
   JZSkyEye_UpdateViewTrampoline 两个导出符号，该模块面向"游戏视野/透视类"功能。

4. __TEXT.__const 存在高熵加密/压缩载荷
   __const 节大小 2,654,305 字节（约占整个文件 63%），信息熵 7.571 bit/byte，
   显著高于正常代码与常量数据（正常字符串节约 4～6）。文件头 16 字节后即为
   连续高熵数据，判断为加密或压缩后的载荷/资源，静态不可直接读取。
   同段内还散落着经异或类变换的字符串残片，与"字符串运行时解密"的常见加固一致。

5. 内嵌 Metal 着色器源码（明文）
   数据段中存在完整的 Metal shader 源码字符串：
     #include <metal_stdlib> using namespace metal;
     struct Uniforms { float4x4 projectionMatrix; };
     struct VertexIn { float2 position[[attribute(0)]];
                       float2 texCoords[[attribute(1)]];
                       uchar4 color[[attribute(2)]]; };
     ...
     vertex VertexOut vertex_main(...) / fragment half4 fragment_main(...)
   说明该 dylib 自带基于 Metal 的绘制管线（绘制覆盖层/ESP 方框、文字纹理等）。

6. 使用 SAMKeychain 处理钥匙串
   字符串 com.samsoffes.samkeychain、SAMKeychain、
   SAMKeychainErrorBadArguments、encrypted_key，
   以及 errSecItemNotFound / errSecAuthFailed 等 SecItem 错误码，
   表明其通过 Keychain 保存/读取"加密密钥"类数据。

7. 网络能力
   链接 CFNetwork / SystemConfiguration，并实现 NSURLSession 全流程回调
   （URLSession:dataTask:didReceiveResponse:completionHandler:、
   URLSession:task:didCompleteWithError: 等），具备 HTTP 通信能力。
   另有 socket / inet_pton / setsockopt / send / recv 调用，具备原始套接字能力。


【四、交付文件索引】

本压缩包内每一类信息各占一个 txt 文件：

符号与命名空间 (Symbol Tree)
  01_导入_Imports.txt                    导入符号 + dyld bind 明细（含所属库与修复地址）
  02_导出_Exports.txt                    导出符号（导出 trie / 符号表 EXTDEF / Ghidra 三口径）
  03_函数_Functions.txt                  全部函数：入口地址、名称、命名空间、大小、参数、返回类型、调用约定
  04_类与命名空间_Classes_Namespaces.txt  类列表、命名空间清单、按命名空间分组的符号
  05_符号总表_All_Symbols.txt             符号总表（名称/地址/类型/来源/命名空间/是否外部/是否主符号）

Mach-O 元数据与内存布局
  06_段与节_Segments_Sections.txt         段与节（Ghidra 内存块 + 原始 Mach-O 节表含文件偏移/标志）
  07_加载命令_Load_Commands.txt           Mach-O 头 + 全部 29 条加载命令逐条解析
  08_链接与修复_Linking_Fixups.txt        重定位表 + dyld bind 修复 + nlist 符号表 + DYSYMTAB 分组
  22_MachO符号表_Symtab.txt               符号表原始视图（nlist_64）

代码与数据引用 (XREF)
  09_代码引用_XREF_Code.txt               代码引用：from / to / 引用类型 / 操作数序号 / 所属函数 / 指令
  10_数据引用_XREF_Data.txt               数据引用：from / to / 引用类型 / 目标数据值

字符串与常量 (Strings)
  11_字符串_Strings.txt                   已定义字符串 + 原始字符串扫描 + 全文件 ASCII/UTF-16 扫描 + __cstring/__ustring 段
  12_ObjectiveC_方法名与方法类型.txt        ObjC 选择器（方法名）、类名、方法类型编码
  13_UI文本与错误信息.txt                  UI 文本与错误信息（启发式分类）
  14_硬编码密钥与路径.txt                  硬编码密钥/令牌/口令线索 + 路径/URL（启发式分类）

控制流图与函数细节
  15_函数图_Call_Graph.txt                每个函数的被调用者（callees）与调用者（callers）
  16_控制流图_CFG_BasicBlocks.txt          每个函数的基本块划分与块间跳转边
  17_反汇编列表_Listing.txt               全量反汇编（地址 | 助记符 | 操作数 | 所属函数）+ 已定义数据
  18_变量与数据类型_Variables_DataTypes.txt 函数参数与局部变量（含存储位置）+ 程序内数据类型

语言特定元数据
  19_ObjectiveC元数据_ObjC_Metadata.txt    ObjC 运行时元数据原始解析：class_t / class_ro_t / method_list /
                                          property_list / protocol_list / ivar_list / 选择器引用 /
                                          类引用 / 父类引用（含属性与方法 IMP 地址）
  20_Swift元数据_Swift_Metadata.txt        Swift 元数据分析结果（结论：无 Swift 内容）

反编译伪代码
  21_反编译伪代码_Decompiled_Pseudocode.txt  全部 2,753 个函数的反编译 C 伪代码（附带函数名/地址/大小/命名空间）

程序信息
  23_Ghidra程序信息_Program_Info.txt       Ghidra 程序信息、地址空间、程序元数据选项


【五、分析方法与工具链】

  · 加载器     : Ghidra 12.1.4 Mach-O 加载器（AARCH64 AppleSilicon）
  · 静态分析   : 自动分析（函数识别、交叉引用、数据类型传播）+ 全函数反编译
  · 原始结构解析: 独立 Python Mach-O 解析器，直接解析头部 / 加载命令 / 段节表 /
                nlist 符号表 / 导出 trie / dyld bind 操作码流 / ObjC 运行时结构 /
                Swift 段扫描，用于与 Ghidra 结果交叉验证
  · 字符串分析 : 已定义字符串提取 + 全文件 ASCII / UTF-16LE 扫描 +
                按节熵值（>7.0 bit/byte 判定为加密/压缩）过滤噪声
  · 交叉验证   : 导出数量经两条独立路径确认（16 = 导出 trie 条目 = 符号表 EXTDEF 组）
  · 反编译覆盖 : 2,753 个函数全部成功，失败 0 个

  已知限制（如实说明）：
  1. __TEXT.__const（2.65 MB）为高熵加密/压缩数据，静态分析无法还原其明文；
     其内部字符串需运行时解密后才能获取，本报告未包含该部分内容。
  2. 由于类名/属性名被混淆，函数名在 Ghidra 中多为 FUN_xxxxxxxx 形式，
     但 ObjC 方法级信息（选择器、类型编码、IMP 地址、所属类）已完整还原于第 19 号文件。
  3. UI 文本 / 密钥 / 路径分类基于启发式规则，可能包含少量误报或漏报，
     原始完整字符串见第 11 号文件，可自行复核。
  4. 分析为纯静态分析，未执行该 dylib，未进行动态调试。

================================================================================
  报告生成时间基准：2026-10-06
  工具：Ghidra 12.1.4 PUBLIC + OpenJDK 21
================================================================================
