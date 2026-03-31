# C++ Coding Style

这份文档只定义当前项目使用的命名风格，不再比较其他风格。

项目统一采用风格 A，也就是偏现代 C++ / 系统工程的命名方式。

## 1. 总原则

命名的目标只有三点：

- 一致
- 可预测
- 适合底层工具和解析器代码阅读

当前项目是 Windows / PE 解析方向代码，因此命名要兼顾：

- 现代 C++ 的可读性
- 与 C / Win32 / PE 资料的语感一致
- 面对缩写术语时仍然清晰，例如 `rva`、`foa`、`iat`、`tls`

## 2. 命名规则

### 2.1 类型名

- 类
- 结构体
- 枚举类型

统一使用 `PascalCase`。

示例：

```cpp
class PeParser;
struct SectionInfo;
enum class Format;
```

### 2.2 函数名

- 普通函数
- 成员函数
- 工具函数

统一使用 `snake_case`。

示例：

```cpp
bool load_from_file(const std::filesystem::path& target_path);
std::optional<std::uint32_t> rva_to_foa(std::uint32_t rva) const;
void print_sections(const ParsedPe& parsed_pe);
```

### 2.3 变量名

- 局部变量
- 参数
- 普通成员变量

统一使用 `snake_case`。

示例：

```cpp
std::filesystem::path target_path;
std::string error_message;
std::uint32_t entry_point_rva{};
```

### 2.4 私有成员

私有成员使用 `snake_case_` 后缀。

示例：

```cpp
std::filesystem::path path_;
std::vector<std::byte> file_data_;
ParsedPe info_{};
```

### 2.5 结构体字段

结构体字段统一使用 `snake_case`。

示例：

```cpp
struct SectionInfo {
    std::string name;
    std::uint32_t virtual_address{};
    std::uint32_t raw_offset{};
};
```

### 2.6 常量

项目内常量统一使用 `k_snake_case`。

示例：

```cpp
constexpr auto k_directory_names = ...;
```

### 2.7 宏

宏保持全大写。

示例：

```cpp
#define NOMINMAX
```

### 2.8 文件名

项目内源码文件名统一使用 `snake_case`。

适用范围：

- `.h`
- `.hpp`
- `.c`
- `.cpp`

示例：

```text
pe_parser.h
pe_parser.cpp
import_parser.h
import_parser.cpp
```

不建议这样写：

```text
PeParser.h
PEParser.cpp
ImportParser.cpp
```

原因很简单：

- 文件名和函数 / 变量命名风格一致
- 大小写更稳定，跨工具链和跨平台时更少歧义
- 对应到底层工具型项目时更自然

### 2.9 目录名

项目目录名统一使用小写，多个单词之间使用下划线分隔，也就是 `snake_case`。

示例：

```text
src
include
tests
pe_tools
manual_map
```

不建议这样写：

```text
PETools
ManualMap
PeTools
```

目录命名规则保持简单：

- 全小写
- 需要分词时用下划线
- 不使用空格
- 不使用混合大小写

## 3. 缩写规则

PE 解析代码会大量使用缩写，统一规则如下：

- 缩写按普通单词处理
- 在 `snake_case` 里直接小写
- 不要混用不同写法

正确示例：

```cpp
rva_to_foa
find_section_by_rva
read_ascii_string_at_rva
number_of_rva_and_sizes
```

不要这样写：

```cpp
RvaToFOA
rvaToFoa
RVA_to_FOA
```

## 4. 当前项目推荐写法

当前项目统一按下面这套写：

- 类型使用 `PascalCase`
- 其余标识符使用 `snake_case`
- 私有成员使用 `snake_case_`

示例：

```cpp
class PeParser {
public:
    bool load_from_file(const std::filesystem::path& target_path, std::string& error_message);
    std::optional<std::uint32_t> rva_to_foa(std::uint32_t rva) const noexcept;
    const ParsedPe& get_info() const noexcept;

private:
    bool parse(std::string& error_message);

    std::filesystem::path path_;
    std::vector<std::byte> file_data_;
    ParsedPe info_{};
};

struct DirectoryInfo {
    std::string name;
    std::uint32_t rva{};
    std::optional<std::size_t> section_index;
    bool in_headers{};
};
```

## 5. 不建议的写法

项目中不再混用以下风格：

- 成员函数 `PascalCase`
- 局部变量 `camelCase`
- 私有成员 `_camelCase`
- 匈牙利命名，例如 `dw_size`、`lp_buffer`

## 6. 一句话版本

当前项目统一使用：

- 类型 `PascalCase`
- 函数 / 变量 / 字段 `snake_case`
- 私有成员 `snake_case_`