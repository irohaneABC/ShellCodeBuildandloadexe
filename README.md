![image](https://github.com/irohaneABC/ShellCodeBuildandloadexe/assets/40713706/56f77455-6e67-48a1-a1e9-ce753c888d54)# ShellCodeBuildandloadexe
这是一个shellcode简单的示例demo，使目标exe程序转换为shellcode可执行程序的一个demo【并不打算后期维护】，两年前写的，我发现被工作磨平了对技术的探索，今天翻到发现的。

# 编译
1. 打开Shellcode中的.sln文件
2. 对shellcode进行生成。
3. 打开x96Dbg 找到Messagebox中EntryPoint(); 进入其中。
4. 使用鼠标将从进入EntryPoint()函数后所有的shellcode直到Mian中看到Messagebox前全部选中，右键导出shellcode形式
5. 恭喜你提取到了shellcode
6. 该项目配备了一个shellcodeBuild 是使用shellcode 做创建的。
7. ShellcodeBuild主要是使用Shellcode 作为引导加载exe【比如DHL】。
8. 注意该shellcode只做了简单重定位区段修复，不能加载较为复杂的程序，仅供学习使用

