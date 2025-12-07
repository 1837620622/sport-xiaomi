# 🏃 小米运动刷步数工具（Zepp API 版本）

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/PHP-7.0+-green.svg" alt="PHP">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Author-传康KK-purple.svg" alt="Author">
</p>

<p align="center">
  <strong>一款基于 Zepp API 的小米运动步数修改工具</strong><br>
  支持网页界面操作和 API 接口调用，可同步微信、支付宝、QQ等第三方平台运动数据
</p>

---

## 📖 项目简介

本工具是一个 PHP 单文件应用，通过调用小米 Zepp 官方 API 接口实现运动步数的修改功能。修改后的步数可自动同步到已绑定的第三方平台（微信运动、支付宝运动、QQ运动等）。

### ⚠️ 免责声明

**本工具仅供个人学习、研究使用，禁止用于商业用途！使用本工具产生的任何后果由使用者自行承担。建议使用小号进行测试。**

---

## ✨ 功能特性

| 特性 | 描述 |
|------|------|
| 🔐 **安全设计** | 不存储用户密码，仅缓存登录 Token |
| ⚡ **智能缓存** | 登录信息缓存 7 天，大幅提升访问速度 |
| 🌐 **双模式** | 支持网页界面操作和 API 接口调用 |
| 📱 **多账号类型** | 支持手机号和邮箱两种账号登录方式 |
| 🔄 **自动同步** | 修改后自动同步到微信、支付宝、QQ 等平台 |
| 🛡️ **并发安全** | 采用文件锁机制防止并发写入冲突 |
| 🎨 **美观界面** | 现代化渐变 UI 设计，响应式布局适配移动端 |

---

## 🔧 技术架构

```
┌─────────────────────────────────────────────────────────┐
│                    小米运动刷步数工具                      │
├─────────────────────────────────────────────────────────┤
│  前端界面层                                               │
│  ├── LayUI 框架 (v2.6.8)                                 │
│  ├── 响应式 CSS 设计                                      │
│  └── AJAX 异步提交                                        │
├─────────────────────────────────────────────────────────┤
│  后端逻辑层                                               │
│  ├── MiMotionRunner 核心类                               │
│  ├── AES-128-CBC 加密模块                                │
│  ├── Token 缓存管理                                       │
│  └── cURL HTTP 客户端                                    │
├─────────────────────────────────────────────────────────┤
│  外部 API                                                │
│  ├── api-user.zepp.com (登录认证)                        │
│  ├── account.zepp.com (账号验证)                         │
│  └── api-mifit-cn.zepp.com (步数同步)                    │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 环境要求

- **PHP 版本**: >= 7.0
- **PHP 扩展**: 
  - `curl` - 用于 HTTP 请求
  - `openssl` - 用于 AES 加密
  - `json` - 用于数据处理
- **Web 服务器**: Apache / Nginx / 其他支持 PHP 的服务器

---

## 🚀 部署指南

### Mac 系统部署

#### 方式一：使用内置 PHP 服务器（推荐测试使用）

```bash
# 1. 进入项目目录
cd /path/to/sport-xiaomi

# 2. 启动 PHP 内置服务器
php -S localhost:8080

# 3. 打开浏览器访问
open http://localhost:8080
```

#### 方式二：使用 MAMP 环境

```bash
# 1. 下载并安装 MAMP
# 官网: https://www.mamp.info/

# 2. 将项目文件复制到 MAMP 网站目录
cp -r sport-xiaomi /Applications/MAMP/htdocs/

# 3. 启动 MAMP 并访问
open http://localhost:8888/sport-xiaomi/
```

#### 方式三：使用 Homebrew + PHP

```bash
# 1. 安装 PHP（如未安装）
brew install php

# 2. 进入项目目录并启动服务
cd /path/to/sport-xiaomi
php -S 0.0.0.0:666

# 3. 访问（局域网内其他设备也可访问）
# http://你的IP:666
```

---

### Windows 系统部署

#### 方式一：使用 PHPStudy（推荐）

```bash
# 1. 下载并安装 PHPStudy
# 官网: https://www.xp.cn/

# 2. 将项目文件复制到网站目录
# 默认路径: C:\phpstudy_pro\WWW\sport-xiaomi

# 3. 启动 PHPStudy，开启 Apache 和 MySQL

# 4. 浏览器访问
# http://localhost/sport-xiaomi/
```

#### 方式二：使用 XAMPP

```bash
# 1. 下载并安装 XAMPP
# 官网: https://www.apachefriends.org/

# 2. 将项目文件复制到网站目录
# 路径: C:\xampp\htdocs\sport-xiaomi

# 3. 启动 XAMPP 控制面板，开启 Apache

# 4. 浏览器访问
# http://localhost/sport-xiaomi/
```

#### 方式三：使用 PHP 内置服务器

```bash
# 1. 确保已安装 PHP 并配置环境变量

# 2. 命令行进入项目目录
cd C:\path\to\sport-xiaomi

# 3. 启动服务器
php -S localhost:8080

# 4. 浏览器访问
# http://localhost:8080
```

---

### 服务器部署（Linux）

```bash
# 1. 安装 LNMP 或 LAMP 环境

# 2. 配置 Nginx（示例）
server {
    listen 666;
    server_name your_domain.com;
    root /var/www/sport-xiaomi;
    index index.php;
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
}

# 3. 设置目录权限
chmod 755 /var/www/sport-xiaomi
chmod 777 /var/www/sport-xiaomi/cache  # 缓存目录需要写权限

# 4. 重启 Nginx
sudo systemctl restart nginx
```

---

## 📱 使用说明

### 网页界面使用

1. 访问工具主页（如 `http://localhost:8080`）
2. 输入 Zepp 账号（手机号或邮箱）
3. 输入账号密码
4. 输入需要修改的步数
5. 点击「立即提交」按钮
6. 等待返回结果

### 第三方平台绑定

在使用本工具之前，需要完成以下步骤：

1. **下载小米运动 APP**（或 Zepp Life）
2. **注册并登录**账号
3. **绑定第三方平台**：
   - 微信运动
   - 支付宝运动
   - QQ 运动
   - 新浪微博
   - 阿里体育
4. 绑定成功后可卸载 APP，使用本工具修改步数会自动同步

---

## 🔌 API 接口文档

### 接口基本信息

| 项目 | 内容 |
|------|------|
| **接口地址** | `http://你的域名/index.php` |
| **请求方式** | GET / POST |
| **返回格式** | JSON |

### 请求参数

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| `user` | string | ✅ | 账号（手机号或邮箱） |
| `pwd` | string | ✅ | 登录密码 |
| `step` | int | ✅ | 需要修改的步数 |
| `token` | string | ✅(API) | API 密钥，固定值：`666` |

> **注意**：网页提交时无需 `token` 参数，仅 API 调用时需要

### GET 请求示例

```bash
curl "http://localhost:666/index.php?user=13888888888&pwd=yourpassword&step=20000&token=666"
```

### POST 请求示例

```bash
curl -X POST "http://localhost:666/index.php" \
  -d "user=13888888888" \
  -d "pwd=yourpassword" \
  -d "step=20000"
```

### 返回结果示例

**成功响应：**
```json
{
    "time": "2025-01-01 12:00:00",
    "user": "138****8888",
    "step": 20000,
    "status": "success",
    "message": "修改步数（20000）"
}
```

**失败响应：**
```json
{
    "time": "2025-01-01 12:00:00",
    "user": "138****8888",
    "step": 20000,
    "status": "failed",
    "message": "账号或密码错误！"
}
```

---

## 📁 项目结构

```
sport-xiaomi/
├── index.php          # 主程序文件（包含前端界面和后端逻辑）
├── cache/             # Token 缓存目录（运行时自动创建）
│   └── *.txt          # 用户登录 Token 缓存文件
└── README.md          # 项目说明文档
```

---

## 🔒 安全说明

1. **密码安全**：本工具不存储用户密码，仅在请求时临时使用
2. **Token 缓存**：登录成功后仅缓存 Token，有效期 7 天
3. **账号脱敏**：日志和返回结果中的账号均做脱敏处理
4. **路径安全**：采用安全文件名过滤，防止目录遍历攻击
5. **并发安全**：使用文件锁机制，防止并发写入导致数据损坏

---

## ❓ 常见问题

### Q: 提交成功但第三方平台未同步？

A: 请尝试以下操作：
1. 在小米运动 APP 中解绑第三方平台
2. 重新绑定第三方平台
3. 等待几分钟后查看

### Q: 提示「账号或密码错误」？

A: 请确认：
1. 使用的是小米运动（Zepp Life）账号
2. 账号和密码正确无误
3. 账号未被封禁

### Q: 为什么不建议使用特殊步数？

A: 如 66666、88888 等整数步数可能因过于规律被系统检测或被他人举报，导致数据无法同步。建议使用随机步数。

### Q: 缓存文件在哪里？

A: 缓存文件存储在 `cache/` 目录下，以用户名命名，格式为 JSON。如需清除缓存，可直接删除对应文件。

---

## 📝 更新日志

### V2.0 (2025-01)
- 🆕 升级至最新 Zepp API 接口
- 🆕 新增 7 天登录缓存机制
- 🆕 全新响应式 UI 设计
- 🆕 新增 API 文档页面
- 🔧 优化并发安全处理
- 🔧 增强错误提示信息

### V1.0 (2024)
- 🎉 初始版本发布
- ✅ 支持手机号/邮箱登录
- ✅ 支持步数修改
- ✅ 支持第三方平台同步

---

## 👨‍💻 作者信息

<p align="center">
  <img src="https://img.shields.io/badge/Author-传康KK-blueviolet?style=for-the-badge" alt="Author">
</p>

| 联系方式 | 信息 |
|----------|------|
| **微信** | 1837620622（传康kk） |
| **邮箱** | 2040168455@qq.com |
| **咸鱼** | 万能程序员 |
| **B站** | 万能程序员 |

---

## ⭐ Star History

如果这个项目对你有帮助，请给一个 Star ⭐ 支持一下！

---

## 📄 开源协议

本项目采用 [MIT License](https://opensource.org/licenses/MIT) 开源协议。

```
MIT License

Copyright (c) 2025 传康KK

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

<p align="center">
  <strong>💡 生命在于运动，可别忘了出门锻炼哦！</strong>
</p>

<p align="center">
  Made with ❤️ by 传康优创互联网科技
</p>
