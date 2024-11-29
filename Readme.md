##### 为什么你正常的的C++，go，pyinstaller项目被杀软报病毒文件？？
---
### 写在前面
![alt text](image.png)
### 1.静态扫描原理
静态扫描，顾名思义，就是不对程序进行运行，而是通过分析程序代码，发现程序中可能存在恶意代码。在多年前，杀毒软件厂商为了对抗恶意软件，开始使用静态扫描技术。但随着代码混淆技术和加密壳的发展，静态扫描技术已经无法应对现代恶意软件。因此，杀毒软件厂商开始使用动态扫描技术，通过运行程序来检测恶意代码，但静态扫描仍然是重要的一种手段，可以提前避免未知的风险，由此发展而来的是静态上的机器学习对编译后的二进制文件进行检测。

### 2.静态扫描方式
- yara：基于规则匹配的静态扫描工具，可以检测已知恶意软件的特征码。
- 机器学习：通过训练数据集，对二进制文件进行分类，判断是否为恶意软件。

本次主要探讨的是机器学习的方式，通过训练数据集，对二进制文件进行分类，判断是否为恶意软件。

---
### 3.机器学习原理
机器学习是一种通过训练数据集，让计算机自动学习规律，从而对未知数据进行预测的方法。在静态扫描中，机器学习通过训练数据集，让计算机自动学习恶意软件的特征，从而对未知二进制文件进行分类，判断是否为恶意软件；同样的会自动学习非恶意软件的特征，避免误报的情况。
### 4.思考绕过方式
根据原理，我们可简单将其训练数据集分类为三种
- 非恶意软件
- 恶意软件
- 未知软件

由此可知，我们想要杀软将我们分类为“非恶意软件”，就需要考虑如何将我们的二进制文件在“外观上”更像机器学习数据集中的“非恶意软件”，“未知文件”分类，从而降低被杀软报毒的风险。
#### 4.1 非恶意软件
我们可以简单猜测，非恶意软件的学习来源，就是微软本身的一些文件，各大厂的发布文件，几乎我们平时正规下载来源的文件，都有可能被用于训练机器模型，尤其是包含数字签名的。
这里我们便有了第一种思路，我们能否直接将我们的代码，直接放进这些“非恶意软件”中。
具体思路如下：
在编译后的二进制PE文件中，包含很多空字节的区域，如下图所示：
![](/wechat.png)
我们可以将自己的代码，直接写入这些00区域，再到程序入口点对代码进行修改，直接在入口点跳转到我们的代码地址进行执行，这样就可以将我们的代码，直接放进这些“非恶意软件”中，从而导致杀软的机器学习直接将我们判定为“非恶意软件”。
具体自动化实现该思路的的项目可以参考我之前的一个小项目：
> https://github.com/Laster-dev/Patch_All-in-one

#### 4.2 未知软件
这个思路便更是简单，只需要把自己编译后的二进制文件，做的亲妈来了都不认识即可。
个人观点如下：
C++，Golang，pyinstaller，易语言（这个是真有特殊照顾）...
以上这些在都是历史悠久的，而相较于rust，ruby，nim这些新兴的，冷门的，杀软的机器学习模型中，肯定是没有这些语言的训练数据集的，因此我们可以直接使用这些语言，进行编译，从而绕过杀软的静态扫描。
但是我们写这个分析就是为了解决C++为代表的语言的痛点，这里以hellowrd为例，通过对C++MSVC编译后的PE结构进行剖析可以看到
``` C++
#include <iostream>

int main()
{
    std::cout << "Hello World!" << std::endl;
    return 0;
}
```
编译后，查看导入表，可以看到
![](/import.png)
可以看到，在我们默认编译下，我们明明是没有调用这些函数的，但是导入表有大量导入
这便是相同点，以此为例，我们直接手动去配置链接器，除所有依赖项，如下图：
![](/link.png)
在链接器 -> 输入 -> 忽略所有默认库选择 “是”
这种情况下，会出现大量“无法解析的外部符号”的报错，这里直接给出解决方式，不懂得可以自行搜索查阅
将所有优化项关闭，定义自己的入口点，手动实现控制台输出函数，如下：
``` C++
#include <windows.h>
#pragma comment(linker, "/entry:run")//修改入口点为run方法

void print(const char* message) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD written;
    WriteConsole(hConsole, message, (DWORD)strlen(message), &written, NULL);
}

int run() {
    print("Hello, World!\n");
    return 0;
}
```
到现在，我们几乎已经完全主管了我们的PE文件，当然还有一些别的细节，如调试文件，清单文件，可以手动配置链接器进行去除。做到这里，我们还能做什么，我们的目的就是把代码改的谁都不认识，主打一个非主流，个人提出以下几条：
- 修改段名
    这里有个小tips，如果我们将段名修改为.UPX*之类的，杀软会认为我们程序有加壳，首先会对我们程序进行脱壳处理，但是我们并没有真的加壳，导致部分杀软引擎分析失败
- 再次对代码进行非主流的修改
- 添加导出表（一般EXE文件是不会有的，但也不是不能有）
- 自定义入口
- ~~手动修改最终的PE文件(这里不做讨论，单独从代码角度解决)~~
最终结果如下：
``` C++
#include <windows.h>
#pragma comment(linker, "/entry:run")//修改入口点为run方法

#pragma code_seg(".UPX1")
void print(const wchar_t* message) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD written;
    WriteConsoleW(hConsole, message, (DWORD)wcslen(message), &written, NULL);
}
class PreMainWizard {
public:
    PreMainWizard() {
        print(L"Hello, World!\n");
    }
};


#pragma code_seg(".UPX0")
void run() {
    PreMainWizard preMainWizardObj;//创建对象，构造函数触发代码执行
}

//胡乱写一些导出
/////////////////////////////////////////
__declspec(dllexport) wchar_t* dJgUmhKoJu(int a,bool c, wchar_t* d) {
    return NULL;
}
__declspec(dllexport) void KNQRBHsNhB(int a, bool c, wchar_t* d) {
    return;
}
__declspec(dllexport) int OREaWXlWzr(int a, bool c, wchar_t* d) {
    return NULL;
}
__declspec(dllexport) bool jZixJKbgMq(int a, bool c, wchar_t* d) {
    return NULL;
}
```
做完这些，编译，得到一个大小为3.5kb的exe，拖到VT，不出所料，正常0/72全绿
> https://www.virustotal.com/gui/file/dc9bafc91c6befa0806de79dcd99c10880fc4fa3e0a188a12d592eb034d2d014?nocache=1

![](/vt.png)
这里再次比较原始helloword的查杀率：
> https://www.virustotal.com/gui/file/1a069b407676673183b6f4fea3c5345bcaff78a59f471246206c4f7ca6e57497?nocache=1
![](/vt1.png)
### 5.结论
所以说到这里，真的是C++，go，pyinstaller，易语言这些静态过不去这些机器学习吗，当然如果不想深究，只想要结果，什么语言都无所谓，但是如果你想要真的知道为什么被杀，还是建议从杀软开发者的角度去思考问题。