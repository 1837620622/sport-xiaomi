# STEP.ENGINE · 小米运动(Zepp Life)刷步数工具

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.1-orange.svg" alt="Version">
  <img src="https://img.shields.io/badge/PHP-7.0+-green.svg" alt="PHP">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Author-传康KK-red.svg" alt="Author">
</p>

<p align="center">
  <strong>基于 Zepp 官方 API 的步数同步引擎</strong><br>
  云端直连小米运动 / Zepp Life 服务, 一键同步微信运动、支付宝运动、QQ 运动等已绑定平台
</p>

<p align="center">
  <a href="https://sport-xiaomi.vercel.app">在线演示 (Vercel)</a> ·
  <a href="http://101.43.83.185:666">在线演示 (独立服务器)</a> ·
  <a href="http://101.43.83.185:666/?m=appinfo">API 文档</a>
</p>

---

## 项目简介

STEP.ENGINE 是一个 PHP 单文件应用, 通过调用 Zepp 官方 API 实现运动步数同步。支持**网页界面操作**与**HTTP API 调用**两种方式, 修改后的步数自动同步至已绑定的第三方平台。

**免责声明**: 本工具仅供个人学习、研究使用, 禁止用于商业用途! 使用本工具产生的任何后果由使用者自行承担, 建议使用小号测试。

---

## 功能特性

| 特性 | 描述 |
|------|------|
| 单文件部署 | 整个应用只有 `index.php`, 前端界面 + API 后端 + 文档页一体 |
| 双模式 | 网页表单提交 + HTTP API 调用 (GET / POST) |
| 随机步数 | `step=随机数` 自动生成 18000~30000, 降低异常判定风险 |
| 安全设计 | 不存储密码(仅存密码哈希), 仅缓存登录 Token (7 天) |
| Token 鉴权 | API 调用必须携带 token (默认 `666`, 可用 `STEP_TOKEN` 覆盖) |
| 频率限制 | 同一 IP 每分钟最多 10 次 (并发安全, flock 互斥) |
| 并发防护 | 账号级锁防止缓存击穿, 原子写防止缓存损坏 |
| SSL 校验 | 上游请求强制证书校验, 失败自动重试一次 |
| 双主题 | 深色 / 浅色主题, 响应式适配移动端 |
| 内置文档 | `?m=appinfo` 访问详细 API 文档页 |

---

## 快速开始

### 环境要求

- PHP >= 7.0 (推荐 8.x)
- PHP 扩展: `curl`、`openssl`、`json`
- Web 服务器: 任意支持 PHP 的服务器 / `php -S` 内置服务器

### 本地启动 (Mac / Linux)

```bash
cd sport-xiaomi
mkdir -p cache
php -S 0.0.0.0:666
# 浏览器访问 http://localhost:666
# API 文档 http://localhost:666/?m=appinfo
```

### Windows 启动

```powershell
cd sport-xiaomi
php -S localhost:8080
# 浏览器访问 http://localhost:8080
```

### 服务器部署 (Linux)

```bash
# 上传 index.php 到服务器后:
mkdir -p cache
nohup php -S 0.0.0.0:666 > php666.log 2>&1 &
# 或使用 Nginx/Apache 指向项目目录, 入口为 index.php
```

> 建议: 生产部署时将缓存目录放到 Web 根目录之外, 例如
> `STEP_CACHE_DIR=/var/lib/step-engine-cache nohup php -S 0.0.0.0:666 > php666.log 2>&1 &`

### Vercel 部署

1. 在 [Vercel](https://vercel.com) 导入仓库 `1837620622/sport-xiaomi`
2. 直接 Deploy, 运行时已由 `vercel.json` 配置 (vercel-php@0.7.1)
3. 部署完成后访问: https://sport-xiaomi.vercel.app

> 注意: Vercel 无服务器环境下文件系统只读, 缓存与限频会自动降级放行, 每次请求可能重新登录。完整功能建议使用独立服务器部署。

---

## 使用说明

### 网页界面

1. 打开首页, 输入 Zepp 账号(手机号或邮箱)与密码
2. 输入目标步数, 或点击"随机" / 快捷按钮 (10K~88K)
3. 点击"提交同步", 在右侧终端查看实时执行日志

### 第三方平台绑定 (重要)

1. 下载 **Zepp Life**(原小米运动)APP
2. 注册并登录账号
3. 在"我的 > 第三方接入"中绑定: 微信运动、支付宝运动、QQ 运动等
4. 绑定完成后即可通过本工具同步步数

---

## HTTP API 文档

**在线完整文档**: 部署后访问 `/?m=appinfo`(内置文档页, 含参数表、curl/Python 示例、错误码表)。

### 基本信息

| 项目 | 内容 |
|------|------|
| 接口地址 | `http://你的域名/index.php` |
| 请求方式 | GET / POST (推荐 POST, 密码不进 URL) |
| 内容类型 | `application/x-www-form-urlencoded` |
| 返回格式 | JSON (`application/json; charset=utf-8`) |
| 频率限制 | 同一 IP 每分钟 10 次, 超出返回 429 |

### 请求参数

| 参数 | 必填 | 说明 |
|------|------|------|
| `user` | 是 | Zepp Life 账号 (手机号或邮箱) |
| `pwd` | 是 | 登录密码 |
| `step` | 是 | 目标步数 (1~98800) 或 `随机数` (自动生成 18000~30000) |
| `token` | 条件 | API 密钥 (默认 `666`): GET 必填; POST 填了则跳过同源检查; 网页表单同源 POST 可省略 |

### 错误码

| 状态码 | 说明 |
|--------|------|
| 200 | 请求处理完成 (看 `status` 字段判断业务成败) |
| 400 | 参数错误 (缺参数 / 步数超范围) |
| 401 | Token 验证失败 |
| 404 | 接口不存在 (未知 `m` 参数) |
| 429 | 请求过于频繁 |
| 500 | 服务器内部错误 |

### GET 请求示例

> ⚠️ 警告: GET 方式会把账号密码明文写入服务器访问日志(如 systemd journal), 公网部署请一律使用 POST 方式, GET 仅限本地测试。

```bash
# 固定步数
curl "http://your.domain/index.php?user=13888888888&pwd=yourpassword&step=28000&token=666"

# 随机步数 (18000~30000)
curl "http://your.domain/index.php?user=you@example.com&pwd=yourpassword&step=随机数&token=666"
```

### POST 请求示例 (推荐)

```bash
curl -X POST "http://your.domain/index.php" \
  -d "user=you@example.com" \
  -d "pwd=yourpassword" \
  -d "step=28000" \
  -d "token=666"
```

### Python 调用示例

```python
import requests

r = requests.post("http://your.domain/index.php", data={
    "user": "you@example.com",
    "pwd": "yourpassword",
    "step": "随机数",
    "token": "666",
})
print(r.json())
```

### 返回结果

```json
{
    "time": "2026-08-02 21:00:00",
    "user": "138****8888",
    "step": 28000,
    "status": "success",
    "message": "修改步数(28000)"
}
```

| 字段 | 说明 |
|------|------|
| `time` | 提交时间 (北京时间) |
| `user` | 脱敏后的账号 |
| `step` | 实际提交的步数 (随机模式返回生成值) |
| `status` | `success` 或 `failed` |
| `message` | 详细提示信息 |

---

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `STEP_TOKEN` | `666` | 覆盖 API 密钥 |
| `STEP_CACHE_DIR` | `./cache` | 自定义缓存目录, 建议放 Web 根目录之外 |
| `STEP_TRUST_PROXY` | 关闭 | 设为 `1` 时限频读取 `X-Forwarded-For` 首个 IP (仅限可信反代环境) |

---

## 项目结构

```
sport-xiaomi/
├── index.php          # 主程序 (网页界面 + API 后端 + 文档页, 独立服务器部署用)
├── api/
│   └── index.php      # Vercel 部署入口 (与根 index.php 内容同步, 由 vercel.json 指定)
├── cache/             # Token 缓存 / 频率限制 (运行时自动创建, 含 .htaccess 保护)
├── vercel.json        # Vercel 部署配置
├── .gitignore
└── README.md
```

> 维护提示: Vercel 的 Serverless 函数必须在 `api/` 目录下, 因此 `api/index.php` 是根 `index.php` 的部署副本, 修改主程序后请同步复制 (`cp index.php api/index.php`)。

---

## 技术原理

```
浏览器/API 请求
      │
      ▼
index.php ──► token 鉴权 + 参数校验 + 频率限制
      │
      ▼
MiMotionRunner ──► 读取 7 天 Token 缓存 ──(未命中)──► Zepp 登录
      │                                                    │
      │                                              api-user.zepp.com (加密令牌)
      │                                              account.zepp.com (登录)
      │                                                    │
      └────────► api-mifit-cn.zepp.com (提交步数数据) ◄──────┘
```

- 登录凭据使用 AES-128-CBC 加密传输, 上游请求强制 SSL 证书校验
- 缓存只存密码哈希 + Token, 不存明文密码; 缓存文件 chmod 0600
- 账号级锁 + 双检缓存防止并发冷启动重复登录
- 请求头模拟 MiFit 6.14.0 Android 客户端

---

## 常见问题

**Q: 提交成功但第三方平台未同步?**
A: 在 Zepp Life APP 中解绑后重新绑定第三方平台, 等待几分钟查看。

**Q: 提示"账号或密码错误"?**
A: 确认使用的是 Zepp Life / 小米运动账号 (非小米账号), 且密码正确。缓存清除后需重新登录。

**Q: 为什么不建议使用 66666 / 88888 等特殊步数?**
A: 过于规律的整数步数可能被系统判定异常。建议使用"随机数"模式。

**Q: 缓存文件在哪里?**
A: `cache/` 目录下以用户名命名的 JSON 文件 (Apache 环境已被 `.htaccess` 禁止下载)。删除即可强制重新登录。

---

## 更新日志

### V3.1
- 完整 API 文档页内置 (`?m=appinfo`): 参数表、curl/Python 示例、错误码表
- 修复: 复制按钮图标 TypeError、主题切换图标不更新、密码可见按钮兼容
- 修复: 非中国大陆手机号被错误补 +86 前缀
- 修复: 锁文件不可用时登录永久"繁忙"(降级无锁直连)
- token 支持环境变量 `STEP_TOKEN` 覆盖, 文档示例自动跟随
- 缓存目录增加 `.htaccess` 访问保护

### V3.0
- 全新运动竞速风格界面 (深/浅双主题)
- API 文档独立成页, 自动检测接口地址
- 新增轻量 `?m=ping` 自检接口 (不触发登录、不消耗限频)
- 记分牌数字滚动动画, 终端实时日志优化

### V2.1
- 新增请求频率限制 (每分钟 10 次)
- 新增步数范围验证 (1~98800)
- 修复邮箱账号判断逻辑 bug

### V2.0
- 升级至 Zepp API 接口
- 新增 7 天登录缓存
- 全新 UI 设计

---

## 作者信息

| 联系方式 | 信息 |
|----------|------|
| 微信 | 1837620622 (传康Kk) |
| 邮箱 | 2040168455@qq.com |
| 咸鱼 | 万能程序员 |
| B站 | 万能程序员 |

---

## 开源协议

本项目采用 [MIT License](https://opensource.org/licenses/MIT)。

生命在于运动, 可别忘了出门锻炼哦!
