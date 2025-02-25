## wechat-app-vercel

![GitHub Repo stars](https://img.shields.io/github/stars/alfchao/wechat-app-vercel) ![GitHub Repo stars](https://img.shields.io/github/forks/alfchao/wechat-app-vercel)

[TOC]

### 部署

#### 方式一（推荐）：

1. [fork](https://github.com/alfchao/Vercel-Telegram-Webhook/fork) 此项目。
2. 在 [vercel](https://vercel.com/) 上选择自己克隆的项目，设置环境变量后部署。

#### 方式二：

直接点击下方按钮部署，缺点是更新需要删除后重新部署。

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Falfchao%2Fwechat-app-vercel)

### 环境变量

项目使用了一些环境变量来配置应用的运行环境，这些环境变量可以通过 `.env` 文件或者系统环境变量来设置。以下是各个环境变量的含义：

| 环境变量名       | 含义                                                         | 是否必须 |
| ---------------- | :----------------------------------------------------------- | -------- |
| `REDIS_URL`      | Redis 数据库的连接 URL，用于存储和管理访问令牌。             | 是       |
| `redis_prefix`   | Redis 键的前缀，用于区分不同的应用或者项目。                 | 是       |
| `corp_id`        | 企业微信的企业 ID，用于获取访问令牌。                        | 是       |
| `corp_secret`    | 企业微信的应用密钥，用于获取访问令牌。                       | 是       |
| `agent_id`       | 企业微信的应用 ID，用于发送消息时指定应用。                  | 是       |
| `WECHAT_API_URL` | 企业微信的 API 基础 URL，用于构建 API 请求的 URL。           | 是       |
| `sendKey`        | 用于验证请求的密钥，确保只有授权的请求可以触发消息发送操作。 | 是       |

### 用法

get请求 https://vercel项目的域名?sendKey=<sendKey>&user_ids=<要发送的人>&msg=<要发送的消息>

