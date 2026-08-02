<?php
/**
 * 小米运动(Zepp Life)刷步数引擎 - Zepp API 版
 *
 * 接口用法(GET / POST 均可):
 *   GET  ?user=账号&pwd=密码&step=28000&token=666
 *   POST user=账号&pwd=密码&step=28000&token=666   (推荐, 密码不进 URL)
 *   step 支持数字(1~98800)或"随机数"(自动生成 18000~30000 随机步数)
 *
 * 环境变量(可选):
 *   STEP_TOKEN     覆盖默认 API 密钥(默认 "666")
 *   STEP_CACHE_DIR 自定义缓存目录, 建议放在 Web 根目录之外防止缓存文件被直接下载
 *   STEP_TRUST_PROXY=1  部署在可信反向代理后时, 限频读取 X-Forwarded-For 首个 IP
 *
 * 作者: 传康KK
 * 说明: 仅供个人学习研究, 修改后的步数自动同步微信/支付宝等已绑定平台
 */

// API 密钥: 默认 666, 可通过环境变量 STEP_TOKEN 覆盖
$token = trim(getenv('STEP_TOKEN')) ?: "666";
date_default_timezone_set('Asia/Shanghai');

// 统一 JSON 输出(带正确状态码与禁止缓存头)
function jsonResponse($data, $code = 200) {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    // 输入含非法 UTF-8 时 json_encode 返回 false, 兜底输出避免空响应
    if ($json === false) {
        $json = json_encode(['error' => '响应编码失败'], JSON_UNESCAPED_UNICODE);
    }
    echo $json;
    exit;
}

// 缓存目录: 优先使用环境变量 STEP_CACHE_DIR(建议部署到 Web 根目录之外, 防止缓存文件被直接下载)
function cacheBaseDir() {
    return getenv('STEP_CACHE_DIR') ?: __DIR__ . '/cache';
}

// 同源校验: 判断请求是否来自本站页面(用于放行网页表单 POST, 阻止跨站伪造)
function isSameOrigin() {
    $host = $_SERVER['HTTP_HOST'] ?? '';
    $origin = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_REFERER'] ?? '';
    if ($host === '' || $origin === '') {
        return false;
    }
    $parts = parse_url($origin);
    if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
        return false;
    }
    $scheme = strtolower($parts['scheme']);
    if ($scheme !== 'http' && $scheme !== 'https') {
        return false;
    }
    // 当前请求是否为 HTTPS(兼容反向代理)
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https');
    // Origin 端口: 显式给定则用给定值, 否则按 scheme 默认
    $originPort = isset($parts['port']) ? (int)$parts['port'] : ($scheme === 'https' ? 443 : 80);
    // 请求 Host 拆出主机名与端口(端口缺省按当前 scheme 默认)
    $reqHost = strtolower(preg_replace('/[^a-zA-Z0-9.\-:\[\]]/', '', $host));
    $reqPort = $isHttps ? 443 : 80;
    if (preg_match('#^(.*):(\d+)$#', $reqHost, $m)) {
        $reqHost = $m[1];
        $reqPort = (int)$m[2];
    }
    // 主机名与端口必须完全一致, 拒绝同域异端口(如 http://host:8080)的跨端口伪造
    return $reqHost === strtolower($parts['host']) && $reqPort === $originPort;
}

// 自动识别当前页面基础地址(兼容反向代理下的 HTTPS)
function baseUrl() {
    $host = preg_replace('/[^a-zA-Z0-9.\-:\[\]]/', '', $_SERVER['HTTP_HOST'] ?? 'localhost');
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https')
        || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);
    $scheme = $isHttps ? 'https' : 'http';
    // Vercel 上函数入口为 /api/index.php, 统一归一化为根路径
    $script = preg_replace('#/api/index\.php$#', '/', $_SERVER['SCRIPT_NAME'] ?? '/');
    return $scheme . '://' . $host . $script;
}

// ==================== 路由处理 ====================
// 轻量自检接口(首页状态灯使用, 不消耗限频、不触发登录)
if (isset($_GET['m']) && $_GET['m'] === 'ping') {
    jsonResponse(['status' => 'ok', 'time' => date('Y-m-d H:i:s')]);
}
// 纯 GET 且无 token 参数 -> 显示网页界面 / API 文档页
if ($_SERVER['REQUEST_METHOD'] === 'GET' && !isset($_GET['token']) && empty($_POST)) {
    if (isset($_GET['m'])) {
        if ($_GET['m'] === 'appinfo') {
            showAppInfo();
        } else {
            jsonResponse(['error' => 'not found'], 404);
        }
    } else {
        showWebPage();
    }
}

function param($key, $default = '') {
    // 防御数组参数(如 user[]=a), PHP 8 下 trim(array) 会抛 TypeError
    $v = $_POST[$key] ?? $_GET[$key] ?? $default;
    return is_string($v) ? trim($v) : $default;
}

// 脱敏账号
function desensitizeUserName($user) {
    $len = strlen($user);
    if ($len <= 8) {
        $ln = max(intval(floor($len / 3)), 1);
        return substr($user, 0, $ln) . "***" . substr($user, -$ln);
    }
    return substr($user, 0, 3) . "****" . substr($user, -4);
}

// 安全文件名过滤
function getSafeFilename($username) {
    $safeName = preg_replace('/[^a-zA-Z0-9_\-@.]/', '_', $username);
    if (strlen($safeName) > 100) {
        $safeName = substr($safeName, 0, 100);
    }
    return $safeName;
}

// 步数解析: 支持数字 / 随机数 / random / ? 等
function resolveStep($step) {
    $step = trim($step);
    // 随机数模式
    if ($step === '' || in_array(strtolower($step), ['随机数', '随机', 'random', 'rand', '?'], true)) {
        $min = 18000;
        $max = 30000;
        return [true, mt_rand($min, $max), true];
    }
    // 必须是纯整数(拒绝 1.9、1e3 等会被 intval 截断的写法)
    if (!preg_match('/^\d+$/', $step)) {
        return [false, 'step 参数必须是整数或"随机数"', false];
    }
    $step = intval($step);
    if ($step < 1) {
        return [false, '步数不能小于1', false];
    }
    if ($step > 98800) {
        return [false, '步数不能超过98800(每日最大合理步数)', false];
    }
    return [true, $step, false];
}

// 简单的请求频率限制(基于IP, 每分钟最多10次)
// 读-改-写全程使用 flock 互斥锁, 防止多进程并发下计数丢失或文件损坏
function checkRateLimit() {
    // 默认按 REMOTE_ADDR 计频; 部署在可信反向代理后(如 Nginx), 设置 STEP_TRUST_PROXY=1 后读取 X-Forwarded-For 首个 IP
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (getenv('STEP_TRUST_PROXY') === '1' && isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $xff = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $first = trim($xff[0]);
        if ($first !== '') {
            $ip = $first;
        }
    }
    $rateLimitDir = cacheBaseDir() . '/rate_limit/';
    if (!is_dir($rateLimitDir)) {
        @mkdir($rateLimitDir, 0755, true);
    }
    // 目录不可写(如 Vercel serverless)时降级放行, 不阻塞正常使用
    if (!is_dir($rateLimitDir) || !is_writable($rateLimitDir)) {
        return [true, ''];
    }
    // 随机抽样清理限频文件(含残留的 tmp 文件): 文件数超 200 且抽样命中时清理最旧的一半
    // 不限定 mtime(持续刷新的文件也应回收), 防止公网扫描导致文件数无限增长
    if (mt_rand(1, 20) === 1) {
        $files = glob($rateLimitDir . '*.txt*');
        if (is_array($files) && count($files) > 200) {
            // 按修改时间升序, 删除最旧的一半
            usort($files, function ($a, $b) {
                return @filemtime($a) - @filemtime($b);
            });
            $removeCount = (int)(count($files) / 2);
            for ($i = 0; $i < $removeCount; $i++) {
                @unlink($files[$i]);
            }
        }
    }
    $rateLimitFile = $rateLimitDir . md5($ip) . '.txt';
    $currentTime = time();
    $windowSize = 60;
    $maxRequests = 10;

    $lockFp = @fopen($rateLimitDir . '.lock', 'c');
    if (!$lockFp) {
        return [true, ''];
    }
    $ok = true;
    $msg = '';
    if (flock($lockFp, LOCK_EX)) {
        $requests = [];
        if (file_exists($rateLimitFile)) {
            $data = @file_get_contents($rateLimitFile);
            $requests = json_decode((string)$data, true);
            if (!is_array($requests)) {
                $requests = [];
            }
        }
        $requests = array_values(array_filter($requests, function ($timestamp) use ($currentTime, $windowSize) {
            return is_numeric($timestamp) && ($currentTime - $timestamp) < $windowSize;
        }));
        if (count($requests) >= $maxRequests) {
            $ok = false;
            $msg = '请求过于频繁, 请稍后再试(每分钟最多' . $maxRequests . '次)';
        } else {
            $requests[] = $currentTime;
            // 临时文件 + rename 原子写, 避免并发交错写损坏 JSON
            $tmp = $rateLimitFile . '.tmp.' . uniqid('', true);
            if (@file_put_contents($tmp, json_encode(array_values($requests))) !== false) {
                @rename($tmp, $rateLimitFile);
                @chmod($rateLimitFile, 0600);
            }
        }
        flock($lockFp, LOCK_UN);
    }
    fclose($lockFp);
    return [$ok, $msg];
}

// ==================== 核心: MiMotionRunner ====================
class MiMotionRunner {
    private $user;
    private $password;
    public $logStr = "";
    public $invalid = false;
    private $cacheDir;
    private $cacheFile;

    function __construct($user, $passwd) {
        if (!$user || !$passwd) {
            $this->invalid = true;
            $this->logStr .= "用户名或密码填写有误!\n";
            return;
        }
        $this->user = $user;
        $this->password = $passwd;

        $this->cacheDir = rtrim(cacheBaseDir(), '/') . '/';
        if (!is_dir($this->cacheDir)) {
            @mkdir($this->cacheDir, 0755, true);
        }
        $this->cacheFile = $this->cacheDir . getSafeFilename($user) . '.txt';
    }

    // 读取缓存(返回 null 表示无有效缓存)
    private function readCache() {
        if (!file_exists($this->cacheFile)) {
            return null;
        }
        $fp = @fopen($this->cacheFile, 'r');
        if (!$fp) {
            return null;
        }
        if (flock($fp, LOCK_SH)) {
            $data = stream_get_contents($fp);
            flock($fp, LOCK_UN);
            fclose($fp);
            $cache = json_decode((string)$data, true);
            if (!$cache || !isset($cache['expire_time']) || $cache['expire_time'] < time()) {
                return null;
            }
            return $cache;
        }
        fclose($fp);
        return null;
    }

    // 校验缓存: 有效期内且密码哈希匹配才可复用(防止缓存期内密码被篡改仍可刷步)
    private function getCachedAccess($password) {
        $cache = $this->readCache();
        if ($cache && isset($cache['access']) && isset($cache['third_name'])
            && isset($cache['pwd_hash']) && password_verify($password, $cache['pwd_hash'])) {
            return [$cache['access'], $cache['third_name']];
        }
        return null;
    }

    // 写入缓存(临时文件 + rename 原子写, 权限 0600)
    private function writeCache($access, $third_name, $password) {
        $cacheData = [
            'access' => $access,
            'third_name' => $third_name,
            'user' => $this->user,
            'pwd_hash' => password_hash($password, PASSWORD_DEFAULT),
            'create_time' => time(),
            'expire_time' => time() + 604800 // 7天
        ];
        $jsonData = json_encode($cacheData);
        if ($jsonData === false) {
            return false;
        }
        $tempFile = $this->cacheFile . '.tmp.' . uniqid('', true);
        $fp = @fopen($tempFile, 'w');
        if (!$fp) {
            return false;
        }
        if (fwrite($fp, $jsonData) !== strlen($jsonData)) {
            // 写入长度不完整, 丢弃临时文件, 避免产生损坏缓存
            fclose($fp);
            @unlink($tempFile);
            return false;
        }
        fflush($fp);
        fclose($fp);
        @chmod($tempFile, 0600);
        if (@rename($tempFile, $this->cacheFile)) {
            return true;
        }
        @unlink($tempFile);
        return false;
    }

    // 清除缓存
    private function clearCache() {
        if (file_exists($this->cacheFile)) {
            @unlink($this->cacheFile);
        }
    }

    // AES-128-CBC 加密
    private function encryptData($plain) {
        $key = 'xeNtBVqzDc6tuNTh';
        $iv = 'MAAAYAAAAAAAAABg';
        return openssl_encrypt($plain, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);
    }

    // 统一 HTTP 请求: 开启 SSL 证书校验、失败自动重试一次、带超时保护
    private function curl($url, $data = null, $app_token = null, $ekv = false) {
        $lastError = '';
        for ($i = 0; $i < 2; $i++) {
            $ch = curl_init();
            $httpheader = [];
            $httpheader[] = "Accept: application/json";
            $httpheader[] = "Accept-Language: zh-CN,zh;q=0.8";
            $httpheader[] = "Connection: keep-alive";
            if ($ekv) $httpheader[] = "x-hm-ekv: 1";
            $httpheader[] = "app_name: com.xiaomi.hm.health";
            $httpheader[] = "appname: com.xiaomi.hm.health";
            $httpheader[] = "appplatform: android_phone";
            if ($app_token) {
                $httpheader[] = "apptoken: " . $app_token;
            }
            curl_setopt($ch, CURLOPT_HTTPHEADER, $httpheader);
            curl_setopt($ch, CURLOPT_URL, $url);
            if ($data) {
                if (is_array($data)) $data = http_build_query($data);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
                curl_setopt($ch, CURLOPT_POST, 1);
            }
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
            curl_setopt($ch, CURLOPT_TIMEOUT, 25);
            curl_setopt($ch, CURLOPT_USERAGENT, 'MiFit6.14.0 (OPD2413; Android 15; Density/2.625)');
            curl_setopt($ch, CURLOPT_HEADER, 1);
            $ret = curl_exec($ch);
            $lastError = curl_error($ch);
            $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            curl_close($ch);
            if ($ret !== false && is_int($headerSize) && $headerSize >= 0) {
                $header = substr($ret, 0, $headerSize);
                $body = substr($ret, $headerSize);
                return ['header' => $header, 'body' => $body];
            }
        }
        throw new Exception('网络请求失败: ' . ($lastError ?: '未知错误'));
    }

    private function getAccess($username, $password) {
        // 快路径: 缓存有效且密码匹配则直接复用, 免重复登录
        $cached = $this->getCachedAccess($password);
        if ($cached) {
            return $cached;
        }

        // 账号级互斥锁: 防止同一账号并发冷启动导致重复登录(缓存击穿)
        $lockFile = $this->cacheDir . '.lock.' . md5($this->user);
        $lockFp = @fopen($lockFile, 'c');
        $gotLock = false;
        if ($lockFp) {
            for ($i = 0; $i < 75; $i++) { // 75 × 200ms = 最长等待 15 秒
                if (flock($lockFp, LOCK_EX | LOCK_NB)) {
                    $gotLock = true;
                    break;
                }
                usleep(200000); // 最长等待 15 秒(超过即放弃锁, 走最终缓存检查)
            }
        } else {
            // 锁文件无法创建(如只读文件系统): 降级为无锁直连登录, 仅可能多一次重复登录
            $gotLock = true;
        }
        try {
            if ($gotLock) {
                // 双检: 等待锁期间可能有其他进程已完成登录
                $cached = $this->getCachedAccess($password);
                if ($cached) {
                    return $cached;
                }

                $third_name = strpos($username, '@') === false ? 'huami_phone' : 'email';
                if (strpos($username, '@') === false && preg_match('/^1[3-9]\d{9}$/', $username)) {
                    // 中国大陆 11 位手机号补 +86; 邮箱 / 已带国家码前缀 / 非手机号则原样上传
                    $username = '+86' . $username;
                }
                $url = 'https://api-user.zepp.com/v2/registrations/tokens';
                $data = [
                    'emailOrPhone' => $username,
                    'password' => $password,
                    'state' => 'REDIRECTION',
                    'client_id' => 'HuaMi',
                    'country_code' => 'CN',
                    'token' => 'access',
                    'redirect_uri' => 'https://s3-us-west-2.amazonaws.com/hm-registration/successsignin.html',
                ];
                $body = $this->encryptData(http_build_query($data));
        if ($body === false) {
            throw new Exception('数据加密失败');
        }
                $response = $this->curl($url, $body, null, true);
                if (preg_match("/access=(.*?)&/", $response['header'], $access)) {
                    $this->writeCache($access[1], $third_name, $password);
                    return [$access[1], $third_name];
                } elseif (preg_match("/refresh=(.*?)&/", $response['header'], $refresh)) {
                    $this->writeCache($refresh[1], $third_name, $password);
                    return [$refresh[1], $third_name];
                } elseif (strpos($response['header'], 'error=') !== false) {
                    $this->clearCache();
                    throw new Exception('账号或密码错误!');
                } else {
                    throw new Exception('登录token接口请求失败');
                }
            }
            // 未拿到锁(超时): 最后再尝试一次缓存, 失败则提示稍后重试
            $cached = $this->getCachedAccess($password);
            if ($cached) {
                return $cached;
            }
            throw new Exception('登录繁忙, 请稍后重试');
        } finally {
            if ($lockFp) {
                if ($gotLock) {
                    flock($lockFp, LOCK_UN);
                }
                fclose($lockFp);
            }
        }
    }

    public function login() {
        try {
            list($access, $third_name) = $this->getAccess($this->user, $this->password);
            $this->logStr .= "获取access token成功\n";
            $url = 'https://account.zepp.com/v2/client/login';
            $data = [
                'app_name' => 'com.xiaomi.hm.health',
                'country_code' => 'CN',
                'code' => $access,
                'device_id' => 'efd38eeb-160d-44e4-9317-6df2145bcb0a',
                'device_model' => 'android_phone',
                'app_version' => '6.14.0',
                'grant_type' => 'access_token',
                'allow_registration' => 'false',
                'dn' => 'account.zepp.com,api-user.zepp.com,api-mifit.zepp.com,api-watch.zepp.com,app-analytics.zepp.com,api-analytics.huami.com,auth.zepp.com',
                'third_name' => $third_name,
                'source' => 'com.xiaomi.hm.health:6.14.0:50818',
                'lang' => 'zh',
            ];
            $response = $this->curl($url, $data);
            $arr = json_decode($response['body'], true);
            if (!$arr || !is_array($arr)) {
                throw new Exception('登录接口请求失败');
            } elseif (isset($arr['result']) && $arr['result'] == 'ok') {
                $token = $arr['token_info']['app_token'] ?? 0;
                $userid = $arr['token_info']['user_id'] ?? 0;
                if (!$token || !$userid) {
                    throw new Exception('登录接口返回数据不完整');
                }
                return ['token' => $token, 'userid' => $userid, 'error' => ''];
            } else {
                $this->clearCache();
                // 只回显上游 message 字段, 不回显原始响应体, 避免泄露内部信息
                $msg = is_string($arr['message'] ?? null) ? $arr['message'] : '登录失败';
                throw new Exception('登录失败: ' . $msg);
            }
        } catch (Exception $e) {
            $this->logStr .= "登录异常: " . $e->getMessage() . "\n";
            return ['token' => 0, 'userid' => 0, 'error' => $e->getMessage()];
        }
    }

    public function loginAndPostStep($step) {
        if ($this->invalid) return ["账号或密码配置有误", false];

        $loginResult = $this->login();
        $token = $loginResult['token'] ?? 0;
        $userid = $loginResult['userid'] ?? 0;
        $loginError = $loginResult['error'] ?? '';

        if (!$token) {
            $errorMsg = $loginError ? "登录失败: {$loginError}" : "登录失败!";
            return [$errorMsg, false];
        }

        try {
            $url = "https://api-mifit-cn.zepp.com/v1/data/band_data.json?t=" . time();
$json = '[{"data_hr":"\/\/\/\/\/\/9L\/\/\/\/\/\/\/\/\/\/\/\/Vv\/\/\/\/\/\/\/\/\/\/\/0v\/\/\/\/\/\/\/\/\/\/\/9e\/\/\/\/\/0n\/a\/\/\/S\/\/\/\/\/\/\/\/\/\/\/\/0b\/\/\/\/\/\/\/\/\/\/1FK\/\/\/\/\/\/\/\/\/\/\/\/R\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/9PTFFpaf9L\/\/\/\/\/\/\/\/\/\/\/\/R\/\/\/\/\/\/\/\/\/\/\/\/0j\/\/\/\/\/\/\/\/\/\/\/9K\/\/\/\/\/\/\/\/\/\/\/\/Ov\/\/\/\/\/\/\/\/\/\/\/zf\/\/\/86\/zr\/Ov88\/zf\/Pf\/\/\/0v\/S\/8\/\/\/\/\/\/\/\/\/\/\/\/\/Sf\/\/\/\/\/\/\/\/\/\/\/z3\/\/\/\/\/\/0r\/Ov\/\/\/\/\/\/S\/9L\/zb\/Sf9K\/0v\/Rf9H\/zj\/Sf9K\/0\/\/N\/\/\/\/0D\/Sf83\/zr\/Pf9M\/0v\/Ov9e\/\/\/\/\/\/\/\/\/\/\/\/S\/\/\/\/\/\/\/\/\/\/\/\/zv\/\/z7\/O\/83\/zv\/N\/83\/zr\/N\/86\/z\/\/Nv83\/zn\/Xv84\/zr\/PP84\/zj\/N\/9e\/zr\/N\/89\/03\/P\/89\/z3\/Q\/9N\/0v\/Tv9C\/0H\/Of9D\/zz\/Of88\/z\/\/PP9A\/zr\/N\/86\/zz\/Nv87\/0D\/Ov84\/0v\/O\/84\/zf\/MP83\/zH\/Nv83\/zf\/N\/84\/zf\/Of82\/zf\/OP83\/zb\/Mv81\/zX\/R\/9L\/0v\/O\/9I\/0T\/S\/9A\/zn\/Pf89\/zn\/Nf9K\/07\/N\/83\/zn\/Nv83\/zv\/O\/9A\/0H\/Of8\/\/zj\/PP83\/zj\/S\/87\/zj\/Nv84\/zf\/Of83\/zf\/Of83\/zb\/Nv9L\/zj\/Nv82\/zb\/N\/85\/zf\/N\/9J\/zf\/Nv83\/zj\/Nv84\/0r\/Sv83\/zf\/MP\/\/\/zb\/Mv82\/zb\/Of85\/z7\/Nv8\/\/0r\/S\/85\/0H\/QP9B\/0D\/Nf89\/zj\/Ov83\/zv\/Nv8\/\/0f\/Sv9O\/0ZeXv\/\/\/\/\/\/\/\/\/\/\/1X\/\/\/\/\/\/\/\/\/\/\/9B\/\/\/\/\/\/\/\/\/\/\/\/TP\/\/\/1b\/\/\/\/\/\/0\/\/\/\/\/\/\/\/\/\/\/\/9N\/\/\/\/\/\/\/\/\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+\/v7+","date":"' . date('Y-m-d') . '","data":[{"start":0,"stop":1439,"value":"UA8AUBQAUAwAUBoAUAEAYCcAUBkAUB4AUBgAUCAAUAEAUBkAUAwAYAsAYB8AYB0AYBgAYCoAYBgAYB4AUCcAUBsAUB8AUBwAUBIAYBkAYB8AUBoAUBMAUCEAUCIAYBYAUBwAUCAAUBgAUCAAUBcAYBsAYCUAATIPYD0KECQAYDMAYB0AYAsAYCAAYDwAYCIAYB0AYBcAYCQAYB0AYBAAYCMAYAoAYCIAYCEAYCYAYBsAYBUAYAYAYCIAYCMAUB0AUCAAUBYAUCoAUBEAUC8AUB0AUBYAUDMAUDoAUBkAUC0AUBQAUBwAUA0AUBsAUAoAUCEAUBYAUAwAUB4AUAwAUCcAUCYAUCwKYDUAAUUlEC8IYEMAYEgAYDoAYBAAUAMAUBkAWgAAWgAAWgAAWgAAWgAAUAgAWgAAUBAAUAQAUA4AUA8AUAkAUAIAUAYAUAcAUAIAWgAAUAQAUAkAUAEAUBkAUCUAWgAAUAYAUBEAWgAAUBYAWgAAUAYAWgAAWgAAWgAAWgAAUBcAUAcAWgAAUBUAUAoAUAIAWgAAUAQAUAYAUCgAWgAAUAgAWgAAWgAAUAwAWwAAXCMAUBQAWwAAUAIAWgAAWgAAWgAAWgAAWgAAWgAAWgAAWgAAWREAWQIAUAMAWSEAUDoAUDIAUB8AUCEAUC4AXB4AUA4AWgAAUBIAUA8AUBAAUCUAUCIAUAMAUAEAUAsAUAMAUCwAUBYAWgAAWgAAWgAAWgAAWgAAWgAAUAYAWgAAWgAAWgAAUAYAWwAAWgAAUAYAXAQAUAMAUBsAUBcAUCAAWwAAWgAAWgAAWgAAWgAAUBgAUB4AWgAAUAcAUAwAWQIAWQkAUAEAUAIAWgAAUAoAWgAAUAYAUB0AWgAAWgAAUAkAWgAAWSwAUBIAWgAAUC4AWSYAWgAAUAYAUAoAUAkAUAIAUAcAWgAAUAEAUBEAUBgAUBcAWRYAUA0AWSgAUB4AUDQAUBoAXA4AUA8AUBwAUA8AUA4AUA4AWgAAUAIAUCMAWgAAUCwAUBgAUAYAUAAAUAAAUAAAUAAAUAAAUAAAUAAAUAAAUAAAWwAAUAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAeSEAeQ8AcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBcAcAAAcAAAcCYOcBUAUAAAUAAAUAAAUAAAUAUAUAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcCgAeQAAcAAAcAAAcAAAcAAAcAAAcAYAcAAAcBgAeQAAcAAAcAAAegAAegAAcAAAcAcAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcCkAeQAAcAcAcAAAcAAAcAwAcAAAcAAAcAIAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcCIAeQAAcAAAcAAAcAAAcAAAcAAAeRwAeQAAWgAAUAAAUAAAUAAAUAAAUAAAcAAAcAAAcBoAeScAeQAAegAAcBkAeQAAUAAAUAAAUAAAUAAAUAAAUAAAcAAAcAAAcAAAcAAAcAAAcAAAegAAegAAcAAAcAAAcBgAeQAAcAAAcAAAcAAAcAAAcAAAcAkAegAAegAAcAcAcAAAcAcAcAAAcAAAcAAAcAAAcA8AeQAAcAAAcAAAeRQAcAwAUAAAUAAAUAAAUAAAUAAAUAAAcAAAcBEAcA0AcAAAWQsAUAAAUAAAUAAAUAAAUAAAcAAAcAoAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAYAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBYAegAAcAAAcAAAegAAcAcAcAAAcAAAcAAAcAAAcAAAeRkAegAAegAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAEAcAAAcAAAcAAAcAUAcAQAcAAAcBIAeQAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBsAcAAAcAAAcBcAeQAAUAAAUAAAUAAAUAAAUAAAUBQAcBYAUAAAUAAAUAoAWRYAWTQAWQAAUAAAUAAAUAAAcAAAcAAAcAAAcAAAcAAAcAMAcAAAcAQAcAAAcAAAcAAAcDMAeSIAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBQAeQwAcAAAcAAAcAAAcAMAcAAAeSoAcA8AcDMAcAYAeQoAcAwAcFQAcEMAeVIAaTYAbBcNYAsAYBIAYAIAYAIAYBUAYCwAYBMAYDYAYCkAYDcAUCoAUCcAUAUAUBAAWgAAYBoAYBcAYCgAUAMAUAYAUBYAUA4AUBgAUAgAUAgAUAsAUAsAUA4AUAMAUAYAUAQAUBIAASsSUDAAUDAAUBAAYAYAUBAAUAUAUCAAUBoAUCAAUBAAUAoAYAIAUAQAUAgAUCcAUAsAUCIAUCUAUAoAUA4AUB8AUBkAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAA","tz":32,"did":"DA932FFFFE8816E7","src":24}],"summary":"{\"v\":6,\"slp\":{\"st\":1628296479,\"ed\":1628296479,\"dp\":0,\"lt\":0,\"wk\":0,\"usrSt\":-1440,\"usrEd\":-1440,\"wc\":0,\"is\":0,\"lb\":0,\"to\":0,\"dt\":0,\"rhr\":0,\"ss\":0},\"stp\":{\"ttl\":' . $step . ',\"dis\":10627,\"cal\":510,\"wk\":41,\"rn\":50,\"runDist\":7654,\"runCal\":397,\"stage\":[{\"start\":327,\"stop\":341,\"mode\":1,\"dis\":481,\"cal\":13,\"step\":680},{\"start\":342,\"stop\":367,\"mode\":3,\"dis\":2295,\"cal\":95,\"step\":2874},{\"start\":368,\"stop\":377,\"mode\":4,\"dis\":1592,\"cal\":88,\"step\":1664},{\"start\":378,\"stop\":386,\"mode\":3,\"dis\":1072,\"cal\":51,\"step\":1245},{\"start\":387,\"stop\":393,\"mode\":4,\"dis\":1036,\"cal\":57,\"step\":1124},{\"start\":394,\"stop\":398,\"mode\":3,\"dis\":488,\"cal\":19,\"step\":607},{\"start\":399,\"stop\":414,\"mode\":4,\"dis\":2220,\"cal\":120,\"step\":2371},{\"start\":415,\"stop\":427,\"mode\":3,\"dis\":1268,\"cal\":59,\"step\":1489},{\"start\":428,\"stop\":433,\"mode\":1,\"dis\":152,\"cal\":4,\"step\":238},{\"start\":434,\"stop\":444,\"mode\":3,\"dis\":2295,\"cal\":95,\"step\":2874},{\"start\":445,\"stop\":455,\"mode\":4,\"dis\":1592,\"cal\":88,\"step\":1664},{\"start\":456,\"stop\":466,\"mode\":3,\"dis\":1072,\"cal\":51,\"step\":1245},{\"start\":467,\"stop\":477,\"mode\":4,\"dis\":1036,\"cal\":57,\"step\":1124},{\"start\":478,\"stop\":488,\"mode\":3,\"dis\":488,\"cal\":19,\"step\":607},{\"start\":489,\"stop\":499,\"mode\":4,\"dis\":2220,\"cal\":120,\"step\":2371},{\"start\":500,\"stop\":511,\"mode\":3,\"dis\":1268,\"cal\":59,\"step\":1489},{\"start\":512,\"stop\":522,\"mode\":1,\"dis\":152,\"cal\":4,\"step\":238}]},\"goal\":8000,\"tz\":\"28800\"}","source":24,"type":0}]';
            $data = [
                'data_json' => $json,
                'userid' => $userid,
                'device_type' => '0',
                'last_sync_data_time' => time() . '',
                'last_deviceid' => 'C4D2D4FFFE8C5068',
            ];

            $response = $this->curl($url, $data, $token);
            $arr = json_decode($response['body'], true);
            if (!$arr) {
                throw new Exception('修改步数接口请求失败');
            } elseif (isset($arr['code']) && $arr['code'] == 1) {
                return ["修改步数({$step})", true];
            } else {
                // 不回显上游原始响应体, 避免泄露上游内部错误结构
                $message = isset($arr['message']) && is_string($arr['message']) ? $arr['message'] : '未知错误';
                throw new Exception('修改步数失败: ' . $message);
            }
        } catch (Exception $e) {
            return [$e->getMessage(), false];
        }
    }
}

// ==================== 网页界面(运动竞速仪表风格) ====================
function showWebPage() {
    global $token;
    $base = baseUrl();
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="STEP.ENGINE - 小米运动 Zepp Life 步数同步引擎, 一键同步微信运动 / 支付宝运动">
<title>STEP.ENGINE - 把今天的目标跑出来</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%23ff4d00'/%3E%3Cpath d='M8 21h3l2-8 4 13 3-11 1 6h3' fill='none' stroke='%23fff' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<script src="https://unpkg.com/lucide@0.462.0"></script>
<style>
:root {
    --bg: #f6f5f1;
    --bg-2: #eeede8;
    --fg: #101010;
    --muted: #6f6e67;
    --line: rgba(16,16,16,0.12);
    --card: #fcfbf8;
    --accent: #ff4d00;
    --accent-ink: #ffffff;
    --ok: #1a9c5c;
    --err: #d92d20;
    --grid: rgba(16,16,16,0.05);
    --code-bg: #101010;
    --code-fg: #e8e6df;
    --shadow: 0 1px 2px rgba(0,0,0,0.05), 0 12px 32px -20px rgba(0,0,0,0.16);
}
[data-theme="dark"] {
    --bg: #0b0b0a;
    --bg-2: #121210;
    --fg: #f2f1ec;
    --muted: #8f8e86;
    --line: rgba(242,241,236,0.13);
    --card: #141412;
    --accent: #ff5a1f;
    --accent-ink: #0b0b0a;
    --ok: #34d399;
    --err: #f87171;
    --grid: rgba(242,241,236,0.045);
    --code-bg: #000000;
    --code-fg: #e8e6df;
    --shadow: none;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
    background-color: var(--bg);
    background-image:
        linear-gradient(var(--grid) 1px, transparent 1px),
        linear-gradient(90deg, var(--grid) 1px, transparent 1px);
    background-size: 72px 72px;
    color: var(--fg);
    font-family: 'Space Grotesk', 'PingFang SC', 'Microsoft YaHei', sans-serif;
    min-height: 100vh;
    transition: background .35s ease, color .35s ease;
    overflow-x: hidden;
}
::selection { background: var(--accent); color: var(--accent-ink); }
a { text-decoration: none; color: inherit; }

/* ---------- 顶栏 ---------- */
.topbar {
    position: sticky; top: 0; z-index: 50;
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px clamp(20px, 5vw, 64px);
    background: color-mix(in srgb, var(--bg) 86%, transparent);
    backdrop-filter: blur(14px);
    border-bottom: 1px solid var(--line);
}
.brand { display: flex; align-items: center; gap: 12px; }
.brand-mark {
    width: 36px; height: 36px; border-radius: 8px;
    background: var(--accent); color: var(--accent-ink);
    display: grid; place-items: center;
    font-family: 'JetBrains Mono'; font-weight: 800; font-size: 16px;
}
.brand-name { font-weight: 700; font-size: 16px; letter-spacing: -0.02em; }
.brand-sub { display: block; font-size: 10px; color: var(--muted); letter-spacing: 0.14em; text-transform: uppercase; margin-top: 2px; font-family: 'JetBrains Mono'; }
.top-actions { display: flex; align-items: center; gap: 8px; }
.icon-btn {
    width: 38px; height: 38px; border-radius: 8px;
    border: 1px solid var(--line); background: var(--card);
    color: var(--fg); display: inline-grid; place-items: center;
    cursor: pointer; transition: all .2s ease;
}
.icon-btn:hover { border-color: var(--accent); color: var(--accent); transform: translateY(-1px); }
.top-link {
    display: inline-flex; align-items: center; gap: 7px;
    padding: 9px 14px; border-radius: 8px;
    border: 1px solid var(--line); background: var(--card);
    font-size: 13px; font-weight: 600; cursor: pointer; transition: all .2s ease;
}
.top-link:hover { border-color: var(--accent); color: var(--accent); }

/* ---------- Hero ---------- */
.hero {
    max-width: 1440px; margin: 0 auto;
    padding: clamp(48px, 8vw, 96px) clamp(20px, 5vw, 64px) 32px;
    display: grid; grid-template-columns: 1.05fr 0.95fr;
    gap: clamp(32px, 5vw, 72px); align-items: center;
}
.eyebrow {
    display: inline-flex; align-items: center; gap: 10px;
    font-family: 'JetBrains Mono'; font-size: 12px;
    letter-spacing: 0.22em; text-transform: uppercase; color: var(--muted);
    margin-bottom: 28px;
}
.eyebrow::before { content: ''; width: 34px; height: 2px; background: var(--accent); }
.hero h1 {
    font-size: clamp(46px, 7.5vw, 108px);
    line-height: 0.96; font-weight: 700;
    letter-spacing: -0.045em;
}
.hero h1 em { font-style: normal; color: var(--accent); }
.hero .lead {
    margin-top: 26px; font-size: clamp(15px, 1.5vw, 18px);
    color: var(--muted); max-width: 34em; line-height: 1.75;
}
.status-row { display: flex; gap: 10px; margin-top: 32px; flex-wrap: wrap; }
.tag {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 8px 12px; border: 1px solid var(--line);
    background: var(--card); font-size: 12.5px; color: var(--muted);
    font-family: 'JetBrains Mono';
}
.tag .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); }
.tag.offline .dot { background: var(--err); }
.tag b { color: var(--fg); font-weight: 600; }

/* ---------- 记分牌 ---------- */
.scoreboard {
    position: relative;
    border: 1px solid var(--line);
    background: var(--card);
    box-shadow: var(--shadow);
    padding: clamp(26px, 3.5vw, 44px);
    overflow: hidden;
}
.scoreboard::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px;
    background: linear-gradient(90deg, var(--accent), transparent 70%);
}
.sb-head {
    display: flex; justify-content: space-between; align-items: center;
    font-family: 'JetBrains Mono'; font-size: 11px; letter-spacing: 0.2em;
    text-transform: uppercase; color: var(--muted);
}
.sb-head .sb-live { display: inline-flex; align-items: center; gap: 6px; color: var(--ok); }
.sb-head .sb-live i { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); animation: pulse 1.6s ease infinite; }
@keyframes pulse { 50% { opacity: 0.25; } }
.sb-value {
    font-family: 'JetBrains Mono'; font-weight: 800;
    font-size: clamp(84px, 11vw, 168px);
    letter-spacing: -0.05em; line-height: 1;
    margin: 22px 0 8px;
    font-variant-numeric: tabular-nums;
    transition: color .3s;
    white-space: nowrap;
}
.sb-value.ok { color: var(--ok); }
.sb-value.err { color: var(--err); }
.sb-track { height: 10px; background: var(--bg-2); overflow: hidden; margin-top: 24px; }
.sb-track i { display: block; height: 100%; width: 0%; background: var(--accent); transition: width .8s cubic-bezier(.2,.8,.2,1); }
.sb-scale { display: flex; justify-content: space-between; margin-top: 10px; font-family: 'JetBrains Mono'; font-size: 11px; color: var(--muted); }
.sb-hint { margin-top: 18px; font-size: 12.5px; color: var(--muted); font-family: 'JetBrains Mono'; display: flex; gap: 6px; align-items: center; }
.sb-hint .arrow { color: var(--accent); }

/* ---------- 工作区 ---------- */
.workspace {
    max-width: 1440px; margin: 0 auto;
    padding: 40px clamp(20px, 5vw, 64px) 90px;
    display: grid; grid-template-columns: 1.1fr 0.9fr;
    gap: clamp(24px, 4vw, 48px);
    align-items: start;
}
.panel {
    border: 1px solid var(--line);
    background: var(--card);
    box-shadow: var(--shadow);
}
.panel-head {
    display: flex; align-items: center; gap: 12px;
    padding: 16px 22px; border-bottom: 1px solid var(--line);
    font-size: 13px; font-weight: 600; letter-spacing: 0.03em;
}
.panel-head .pn {
    font-family: 'JetBrains Mono'; font-size: 11px; font-weight: 700;
    color: var(--accent); letter-spacing: 0.14em;
    border: 1px solid var(--line); padding: 3px 8px;
}
.panel-head .ph-sub { margin-left: auto; font-family: 'JetBrains Mono'; font-size: 11px; color: var(--muted); letter-spacing: 0.1em; text-transform: uppercase; }
.panel-body { padding: clamp(22px, 3vw, 34px); }

.field { margin-bottom: 22px; }
.field label {
    display: block; font-size: 11.5px; font-weight: 600;
    color: var(--muted); margin-bottom: 8px; letter-spacing: 0.1em; text-transform: uppercase;
    font-family: 'JetBrains Mono';
}
.input-wrap { position: relative; }
.input-wrap .i-ic {
    position: absolute; left: 14px; top: 50%; transform: translateY(-50%);
    color: var(--muted); pointer-events: none;
}
.input-wrap input {
    width: 100%; padding: 15px 16px 15px 44px;
    border: 1px solid var(--line); border-radius: 8px;
    background: var(--bg); color: var(--fg);
    font-size: 15px; font-family: inherit;
    outline: none; transition: border-color .2s, box-shadow .2s;
}
.input-wrap input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 16%, transparent); }
.input-wrap .eye-btn {
    position: absolute; right: 8px; top: 50%; transform: translateY(-50%);
    width: 34px; height: 34px; border: none; background: transparent;
    color: var(--muted); cursor: pointer; display: grid; place-items: center; border-radius: 6px;
}
.input-wrap .eye-btn:hover { color: var(--fg); }

.step-row { display: flex; gap: 10px; align-items: stretch; }
.step-row .input-wrap { flex: 1; }
.step-row .input-wrap input { padding-left: 44px; font-family: 'JetBrains Mono'; font-weight: 700; font-size: 19px; }
.rand-btn {
    padding: 0 18px; border-radius: 8px;
    border: 1px dashed var(--line); background: var(--bg);
    color: var(--muted); cursor: pointer; font-size: 13px;
    display: inline-flex; align-items: center; gap: 8px;
    transition: all .2s; white-space: nowrap; font-family: 'JetBrains Mono';
}
.rand-btn:hover { color: var(--accent); border-color: var(--accent); }

/* 号码牌快捷步数 */
.bib-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin-top: 12px; }
.bib {
    padding: 11px 4px; border: 1px solid var(--line); border-radius: 8px;
    background: var(--bg); color: var(--fg);
    cursor: pointer; font-family: 'JetBrains Mono'; font-weight: 700; font-size: 14px;
    transition: all .2s; text-align: center;
}
.bib:hover { border-color: var(--accent); color: var(--accent); transform: translateY(-1px); }
.bib.active { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); }

.submit-btn {
    width: 100%; margin-top: 26px;
    padding: 18px; border: none; border-radius: 8px;
    background: var(--fg); color: var(--bg);
    font-size: 16px; font-weight: 700; font-family: inherit;
    cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 10px;
    transition: all .22s cubic-bezier(.2,.8,.2,1);
    position: relative; overflow: hidden;
}
.submit-btn .btn-arr { transition: transform .22s ease; }
.submit-btn:hover .btn-arr { transform: translateX(4px); }
.submit-btn:hover { background: var(--accent); color: var(--accent-ink); transform: translateY(-2px); }
.submit-btn:active { transform: translateY(0); }
.submit-btn[disabled] { opacity: .6; cursor: not-allowed; transform: none; }
.submit-btn.loading .btn-label { visibility: hidden; }
.submit-btn .spinner {
    position: absolute; inset: 0; display: none;
    place-items: center; gap: 10px; font-size: 14px;
}
.submit-btn.loading .spinner { display: flex; }
.spinner i { animation: spin 0.9s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

/* ---------- 终端 ---------- */
.terminal {
    background: var(--code-bg); color: var(--code-fg);
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px; line-height: 1.9;
}
.term-head {
    display: flex; align-items: center; gap: 8px;
    padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.09);
    background: rgba(255,255,255,0.03);
}
.term-head .tt { color: rgba(232,230,223,0.5); font-size: 12px; letter-spacing: 0.08em; }
.term-dots { display: flex; gap: 6px; margin-right: 8px; }
.term-dots i { width: 10px; height: 10px; border-radius: 50%; }
.term-dots i:nth-child(1) { background: #ff5f57; }
.term-dots i:nth-child(2) { background: #febc2e; }
.term-dots i:nth-child(3) { background: #28c840; }
.term-body { padding: 20px 22px; min-height: 300px; max-height: 380px; overflow-y: auto; }
.term-body .line { display: block; white-space: pre-wrap; word-break: break-all; }
.term-body .line .p { color: #8f8e86; }
.term-body .line .c { color: #ff5a1f; }
.term-body .line .s { color: #34d399; }
.term-body .line .e { color: #f87171; }
.term-body .line .d { color: #f2f1ec; }
.term-body .cursor { display: inline-block; width: 8px; height: 15px; background: var(--accent); vertical-align: -2px; animation: blink 1s steps(1) infinite; }
@keyframes blink { 50% { opacity: 0; } }
.term-empty { color: rgba(232,230,223,0.35); }

/* ---------- 使用步骤 ---------- */
.steps {
    max-width: 1440px; margin: 0 auto;
    padding: 0 clamp(20px, 5vw, 64px) 90px;
}
.sec-head { display: flex; align-items: baseline; gap: 20px; flex-wrap: wrap; margin-bottom: 40px; }
.sec-head h2 { font-size: clamp(26px, 3.2vw, 42px); letter-spacing: -0.035em; }
.sec-head .sub { color: var(--muted); font-size: 14px; font-family: 'JetBrains Mono'; }
.step-list { list-style: none; display: grid; grid-template-columns: repeat(3, 1fr); gap: 0; border: 1px solid var(--line); background: var(--card); box-shadow: var(--shadow); }
.step-item {
    padding: clamp(24px, 3vw, 36px);
    position: relative;
    border-right: 1px solid var(--line);
}
.step-item:last-child { border-right: none; }
.step-item .idx {
    font-family: 'JetBrains Mono'; font-size: 12px; font-weight: 700;
    color: var(--accent); letter-spacing: 0.16em;
    display: inline-flex; align-items: center; gap: 10px; margin-bottom: 18px;
}
.step-item .idx::after { content: ''; width: 26px; height: 1px; background: var(--accent); }
.step-item h3 { font-size: 18px; margin-bottom: 10px; letter-spacing: -0.01em; }
.step-item p { font-size: 14px; color: var(--muted); line-height: 1.7; }

/* ---------- 页脚 ---------- */
.footer {
    border-top: 1px solid var(--line);
    padding: 28px clamp(20px, 5vw, 64px);
    display: flex; justify-content: space-between; align-items: center;
    flex-wrap: wrap; gap: 14px;
    color: var(--muted);
    font-family: 'JetBrains Mono'; font-size: 12px;
}
.footer a { color: var(--muted); }
.footer a:hover { color: var(--accent); }
.footer .fl a { margin-left: 18px; }

/* ---------- 响应式 ---------- */
@media (max-width: 980px) {
    .hero, .workspace { grid-template-columns: 1fr; }
    .step-list { grid-template-columns: 1fr; }
    .step-item { border-right: none; border-bottom: 1px solid var(--line); }
    .step-item:last-child { border-bottom: none; }
    .hero h1 { font-size: clamp(40px, 11vw, 64px); }
}
@media (max-width: 560px) {
    .brand-sub { display: none; }
    .step-row { flex-direction: column; }
    .rand-btn { justify-content: center; padding: 14px; }
    .sb-value { font-size: 76px; }
    .bib-row { grid-template-columns: repeat(3, 1fr); }
}
</style>
</head>
<body>
<div class="topbar">
    <a class="brand" href="<?php echo $base; ?>">
        <span class="brand-mark">S</span>
        <span>
            <span class="brand-name">STEP.ENGINE</span>
            <span class="brand-sub">Zepp Life Step Sync</span>
        </span>
    </a>
    <div class="top-actions">
        <a class="top-link" href="?m=appinfo"><i data-lucide="book-open" style="width:15px;height:15px"></i> API 文档</a>
        <a class="top-link" href="https://github.com/1837620622/sport-xiaomi" target="_blank" rel="noopener"><i data-lucide="external-link" style="width:15px;height:15px"></i> GitHub</a>
        <button class="icon-btn" id="themeBtn" title="切换主题" onclick="toggleTheme()"><i data-lucide="moon" style="width:17px;height:17px"></i></button>
    </div>
</div>

<section class="hero">
    <div>
        <span class="eyebrow">Zepp Life · Step Sync Engine</span>
        <h1>把今天的<br>目标<em>跑出来</em></h1>
        <p class="lead">基于 Zepp Life 官方 API 的步数同步引擎。提交后自动同步至微信运动、支付宝运动、QQ 运动等已绑定平台。</p>
        <div class="status-row">
            <span class="tag" id="apiPill"><span class="dot"></span><b id="apiText">API 自检中</b></span>
            <span class="tag"><i data-lucide="zap" style="width:13px;height:13px"></i> 7天登录缓存</span>
            <span class="tag"><i data-lucide="shield-check" style="width:13px;height:13px"></i> 不记录密码</span>
        </div>
    </div>
    <div class="scoreboard">
        <div class="sb-head">
            <span>Target Steps</span>
            <span class="sb-live"><i></i>LIVE</span>
        </div>
        <div class="sb-value" id="gaugeValue">0</div>
        <div class="sb-track"><i id="gaugeBar"></i></div>
        <div class="sb-scale"><span>0</span><span>98800</span></div>
        <div class="sb-hint"><span class="arrow">&#10148;</span> 输入目标步数, 或点击"随机"</div>
    </div>
</section>

<section class="workspace">
    <div class="panel">
        <div class="panel-head">
            <span class="pn">01</span> 步数设置
            <span class="ph-sub">Console Input</span>
        </div>
        <div class="panel-body">
            <div class="field">
                <label for="fUser">Zepp 账号</label>
                <div class="input-wrap">
                    <span class="i-ic"><i data-lucide="user" style="width:16px;height:16px"></i></span>
                    <input id="fUser" type="text" placeholder="手机号或邮箱" autocomplete="username">
                </div>
            </div>
            <div class="field">
                <label for="fPwd">密码</label>
                <div class="input-wrap">
                    <span class="i-ic"><i data-lucide="lock" style="width:16px;height:16px"></i></span>
                    <input id="fPwd" type="password" placeholder="请输入密码" autocomplete="current-password">
                    <button class="eye-btn" onclick="togglePwd()" type="button" aria-label="显示密码"><i data-lucide="eye" id="eyeIc" style="width:16px;height:16px"></i></button>
                </div>
            </div>
            <div class="field">
                <label for="fStep">目标步数</label>
                <div class="step-row">
                    <div class="input-wrap">
                        <span class="i-ic"><i data-lucide="footprints" style="width:16px;height:16px"></i></span>
                        <input id="fStep" type="number" min="1" max="98800" value="28000" placeholder="28000">
                    </div>
                    <button class="rand-btn" type="button" onclick="randomStep()"><i data-lucide="dices" style="width:15px;height:15px"></i> 随机</button>
                </div>
                <div class="bib-row">
                    <button class="bib" data-v="10000">10K</button>
                    <button class="bib" data-v="18000">18K</button>
                    <button class="bib active" data-v="28000">28K</button>
                    <button class="bib" data-v="50000">50K</button>
                    <button class="bib" data-v="88888">88K</button>
                </div>
            </div>
            <button class="submit-btn" id="submitBtn" onclick="doSubmit()">
                <span class="btn-label"><i data-lucide="send" style="width:17px;height:17px"></i> 提交同步 <i class="btn-arr" data-lucide="arrow-right" style="width:16px;height:16px"></i></span>
                <span class="spinner"><i data-lucide="loader-2" style="width:17px;height:17px"></i> 正在同步</span>
            </button>
        </div>
    </div>

    <div class="panel" style="padding:0; overflow:hidden;">
        <div class="panel-head" style="border-bottom:none; background:var(--code-bg);">
            <span class="pn" style="border-color:rgba(255,255,255,0.15); color:#ff5a1f;">02</span>
            <span style="color:rgba(232,230,223,0.85);">执行终端</span>
            <span class="ph-sub" style="color:rgba(232,230,223,0.4);">Live Log</span>
        </div>
        <div class="terminal">
            <div class="term-head">
                <span class="term-dots"><i></i><i></i><i></i></span>
                <span class="tt">step-engine --console</span>
            </div>
            <div class="term-body" id="termBody">
                <span class="line term-empty" id="termEmpty">等待任务... 填写账号并点击提交同步</span>
            </div>
        </div>
    </div>
</section>

<section class="steps">
    <div class="sec-head">
        <h2>三步完成同步</h2>
        <span class="sub">无需手机与电脑, 云端直连 Zepp 服务</span>
    </div>
    <ol class="step-list">
        <li class="step-item">
            <span class="idx">01 / LOGIN</span>
            <h3>注册并登录 Zepp Life</h3>
            <p>下载 Zepp Life(原小米运动), 使用邮箱或手机号注册账号。建议使用小号测试。</p>
        </li>
        <li class="step-item">
            <span class="idx">02 / LINK</span>
            <h3>绑定第三方平台</h3>
            <p>在"我的 &gt; 第三方接入"中绑定微信运动、支付宝运动, 完成授权后即可同步。</p>
        </li>
        <li class="step-item">
            <span class="idx">03 / SYNC</span>
            <h3>提交目标步数</h3>
            <p>在本页或调用 API 提交步数, 服务器直连 Zepp 接口, 秒级同步到微信与支付宝。</p>
        </li>
    </ol>
</section>

<footer class="footer">
    <span>© 传康KK · STEP.ENGINE · 仅供个人学习研究</span>
    <div class="fl">
        <a href="?m=appinfo">API 文档</a>
        <a href="https://github.com/1837620622/sport-xiaomi" target="_blank" rel="noopener">GitHub</a>
    </div>
</footer>

<script>
lucide.createIcons();
document.querySelectorAll('svg.lucide').forEach(function (s) { s.setAttribute('aria-hidden', 'true'); });

/* ---------- 主题切换 ---------- */
(function () {
    const saved = localStorage.getItem('step-theme');
    const prefers = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    document.documentElement.dataset.theme = saved || prefers;
    syncThemeIcon();
})();
function toggleTheme() {
    const cur = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = cur;
    localStorage.setItem('step-theme', cur);
    syncThemeIcon();
}
function syncThemeIcon() {
    const dark = document.documentElement.dataset.theme === 'dark';
    const btn = document.querySelector('#themeBtn');
    if (btn) {
        btn.innerHTML = '<i data-lucide="' + (dark ? 'sun' : 'moon') + '" style="width:17px;height:17px"></i>';
        lucide.createIcons();
    }
}

/* ---------- 密码可见 ---------- */
function togglePwd() {
    const inp = document.getElementById('fPwd');
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    const eye = document.getElementById('eyeIc');
    if (eye) {
        eye.setAttribute('data-lucide', show ? 'eye-off' : 'eye');
        lucide.createIcons();
    }
}

/* ---------- 记分牌联动(数字滚动动画) ---------- */
const gaugeValue = document.getElementById('gaugeValue');
const gaugeBar = document.getElementById('gaugeBar');
const stepInput = document.getElementById('fStep');
let gaugeAnim = null;
function paintGauge(v) {
    v = Math.max(0, Math.min(98800, Number(v) || 0));
    if (gaugeAnim) cancelAnimationFrame(gaugeAnim);
    const start = parseInt(String(gaugeValue.textContent).replace(/,/g, ''), 10) || 0;
    const dur = 500, t0 = performance.now();
    function frame(t) {
        const k = Math.min(1, (t - t0) / dur);
        const ease = 1 - Math.pow(1 - k, 3);
        const cur = Math.round(start + (v - start) * ease);
        gaugeValue.textContent = cur.toLocaleString();
        gaugeBar.style.width = Math.min(100, cur / 98800 * 100) + '%';
        if (k < 1) gaugeAnim = requestAnimationFrame(frame);
        else gaugeAnim = null;
    }
    gaugeAnim = requestAnimationFrame(frame);
    gaugeValue.classList.remove('ok', 'err');
}
stepInput.addEventListener('input', function () { paintGauge(this.value || 0); });
document.querySelectorAll('.bib').forEach(function (b) {
    b.addEventListener('click', function () {
        stepInput.value = this.dataset.v;
        paintGauge(this.dataset.v);
        document.querySelectorAll('.bib').forEach(function (x) { x.classList.remove('active'); });
        this.classList.add('active');
    });
});
function randomStep() {
    const v = 18000 + Math.floor(Math.random() * 12001);
    stepInput.value = v;
    paintGauge(v);
    const q = document.querySelector('.bib.active');
    if (q) q.classList.remove('active');
}
paintGauge(28000);

/* ---------- API 自检(轻量 ping, 不触发登录) ---------- */
(function () {
    const pill = document.getElementById('apiPill');
    const txt = document.getElementById('apiText');
    fetch('<?php echo $base; ?>?m=ping')
        .then(function (r) { return r.json(); })
        .then(function (j) {
            if (j && j.status === 'ok') { txt.textContent = 'API 在线'; }
            else { pill.classList.add('offline'); txt.textContent = 'API 异常'; }
        })
        .catch(function () { pill.classList.add('offline'); txt.textContent = 'API 离线'; });
})();

/* ---------- 终端输出 ---------- */
const termBody = document.getElementById('termBody');
function termClear() {
    termBody.innerHTML = '';
    const empty = document.createElement('span');
    empty.className = 'line term-empty';
    empty.id = 'termEmpty';
    empty.textContent = '等待任务... 填写账号并点击提交同步';
    termBody.appendChild(empty);
}
function termLine(cls, text) {
    const empty = document.getElementById('termEmpty');
    if (empty) empty.remove();
    const line = document.createElement('span');
    line.className = 'line';
    line.innerHTML = '<span class="' + cls + '">' + escapeHtml(text) + '</span>';
    termBody.appendChild(line);
    termBody.scrollTop = termBody.scrollHeight;
}
function termCmd(text) {
    const empty = document.getElementById('termEmpty');
    if (empty) empty.remove();
    const line = document.createElement('span');
    line.className = 'line';
    line.innerHTML = '<span class="p">$</span> <span class="c">' + escapeHtml(text) + '</span>';
    termBody.appendChild(line);
    termBody.scrollTop = termBody.scrollHeight;
}
function termCursor(on) {
    if (on && !document.querySelector('#termBody .cursor')) {
        const c = document.createElement('span');
        c.className = 'cursor';
        termBody.appendChild(c);
    } else if (!on) {
        const c = document.querySelector('#termBody .cursor');
        if (c) c.remove();
    }
    termBody.scrollTop = termBody.scrollHeight;
}
function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* ---------- 账号脱敏(邮箱/手机号) ---------- */
function maskUser(u) {
    if (u.indexOf('@') !== -1) return u.replace(/(.{3}).*(@.*)/, '$1****$2');
    return u.length > 7 ? u.slice(0, 3) + '****' + u.slice(-4) : u.slice(0, 1) + '***' + u.slice(-1);
}

/* ---------- 提交 ---------- */
function doSubmit() {
    const user = document.getElementById('fUser').value.trim();
    const pwd = document.getElementById('fPwd').value.trim();
    const step = document.getElementById('fStep').value.trim();

    if (!user) { alert('请填写 Zepp 账号'); return; }
    if (!pwd) { alert('请填写密码'); return; }
    if (!step) { alert('请填写目标步数, 或点击"随机"'); return; }

    const btn = document.getElementById('submitBtn');
    btn.disabled = true;
    btn.classList.add('loading');
    gaugeValue.classList.remove('ok', 'err');
    termClear();
    termCursor(true);
    termCmd('step-engine --user ' + maskUser(user) + ' --step ' + step);

    const body = new URLSearchParams();
    body.append('user', user);
    body.append('pwd', pwd);
    body.append('step', step);
    body.append('token', '<?php echo htmlspecialchars($token, ENT_QUOTES); ?>');

    fetch('<?php echo $base; ?>', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString()
    })
    .then(function (r) {
        return r.json().catch(function () { return { raw: true }; }).then(function (j) {
            if (!r.ok && j.raw) throw new Error('HTTP ' + r.status);
            return j;
        });
    })
    .then(function (j) {
        termCursor(false);
        termLine('d', '> ' + (j.time || new Date().toLocaleString()));
        termLine('p', '> 账号: ' + (j.user || user));
        termLine('p', '> 步数: ' + (j.step || step));
        if (j.status === 'success') {
            termLine('s', '> ' + (j.message || '同步成功'));
            gaugeValue.classList.add('ok');
        } else {
            termLine('e', '> ' + (j.message || j.error || '同步失败'));
            gaugeValue.classList.add('err');
        }
    })
    .catch(function (e) {
        termCursor(false);
        termLine('e', '> 网络错误: ' + e.message);
        gaugeValue.classList.add('err');
    })
    .finally(function () {
        btn.disabled = false;
        btn.classList.remove('loading');
    });
}
</script>
</body>
</html>
<?php
    exit;
}

// ==================== API 文档页(独立一页) ====================
function showAppInfo() {
    global $token;
    $base = baseUrl();
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="STEP.ENGINE API 文档 - 小米运动 Zepp Life 步数同步接口说明">
<title>STEP.ENGINE - API 文档</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%23ff4d00'/%3E%3Cpath d='M8 21h3l2-8 4 13 3-11 1 6h3' fill='none' stroke='%23fff' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<script src="https://unpkg.com/lucide@0.462.0"></script>
<style>
:root {
    --bg: #f6f5f1;
    --bg-2: #eeede8;
    --fg: #101010;
    --muted: #6f6e67;
    --line: rgba(16,16,16,0.12);
    --card: #fcfbf8;
    --accent: #ff4d00;
    --accent-ink: #ffffff;
    --ok: #1a9c5c;
    --err: #d92d20;
    --grid: rgba(16,16,16,0.05);
    --code-bg: #101010;
    --code-fg: #e8e6df;
    --shadow: 0 1px 2px rgba(0,0,0,0.05), 0 12px 32px -20px rgba(0,0,0,0.16);
}
[data-theme="dark"] {
    --bg: #0b0b0a;
    --bg-2: #121210;
    --fg: #f2f1ec;
    --muted: #8f8e86;
    --line: rgba(242,241,236,0.13);
    --card: #141412;
    --accent: #ff5a1f;
    --accent-ink: #0b0b0a;
    --ok: #34d399;
    --err: #f87171;
    --grid: rgba(242,241,236,0.045);
    --code-bg: #000000;
    --code-fg: #e8e6df;
    --shadow: none;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
    background-color: var(--bg);
    background-image:
        linear-gradient(var(--grid) 1px, transparent 1px),
        linear-gradient(90deg, var(--grid) 1px, transparent 1px);
    background-size: 72px 72px;
    color: var(--fg);
    font-family: 'PingFang SC', 'Microsoft YaHei', 'Helvetica Neue', sans-serif;
    min-height: 100vh;
    transition: background .35s ease, color .35s ease;
    overflow-x: hidden;
}
::selection { background: var(--accent); color: var(--accent-ink); }
a { text-decoration: none; color: inherit; }

/* ---------- 顶栏 ---------- */
.topbar {
    position: sticky; top: 0; z-index: 50;
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px clamp(20px, 5vw, 64px);
    background: color-mix(in srgb, var(--bg) 86%, transparent);
    backdrop-filter: blur(14px);
    border-bottom: 1px solid var(--line);
}
.brand { display: flex; align-items: center; gap: 12px; }
.brand-mark {
    width: 36px; height: 36px; border-radius: 8px;
    background: var(--accent); color: var(--accent-ink);
    display: grid; place-items: center;
    font-family: 'JetBrains Mono', monospace; font-weight: 800; font-size: 16px;
}
.brand-name { font-weight: 700; font-size: 16px; letter-spacing: -0.02em; }
.brand-sub { display: block; font-size: 10px; color: var(--muted); letter-spacing: 0.14em; text-transform: uppercase; margin-top: 2px; font-family: 'JetBrains Mono', monospace; }
.top-actions { display: flex; align-items: center; gap: 8px; }
.icon-btn {
    width: 38px; height: 38px; border-radius: 8px;
    border: 1px solid var(--line); background: var(--card);
    color: var(--fg); display: inline-grid; place-items: center;
    cursor: pointer; transition: all .2s ease;
}
.icon-btn:hover { border-color: var(--accent); color: var(--accent); transform: translateY(-1px); }
.top-link {
    display: inline-flex; align-items: center; gap: 7px;
    padding: 9px 14px; border-radius: 8px;
    border: 1px solid var(--line); background: var(--card);
    font-size: 13px; font-weight: 600; cursor: pointer; transition: all .2s ease;
}
.top-link:hover { border-color: var(--accent); color: var(--accent); }

/* ---------- 文档页主体 ---------- */
.wrap {
    max-width: 960px; margin: 0 auto;
    padding: clamp(40px, 6vw, 72px) clamp(20px, 5vw, 64px) 90px;
}
.wrap h1 { font-size: clamp(36px, 5vw, 56px); letter-spacing: -0.04em; line-height: 1; }
.wrap h1 em { color: var(--accent); font-style: normal; }
.wrap .sub { color: var(--muted); font-family: 'JetBrains Mono', monospace; font-size: 13px; margin-top: 16px; }
.doc-card {
    border: 1px solid var(--line);
    background: var(--card);
    box-shadow: var(--shadow);
    margin-top: 26px;
}
.doc-head {
    display: flex; align-items: center; gap: 12px;
    padding: 16px 22px; border-bottom: 1px solid var(--line);
    font-size: 14px; font-weight: 600; letter-spacing: 0.03em;
}
.doc-head .pn {
    font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 700;
    color: var(--accent); letter-spacing: 0.14em;
    border: 1px solid var(--line); padding: 3px 8px;
}
.doc-head .ic { color: var(--muted); display: inline-flex; }
.doc-body { padding: clamp(18px, 2.5vw, 26px); }
.param-table { width: 100%; border-collapse: collapse; font-size: 14px; }
.param-table th {
    text-align: left; font-size: 11.5px; text-transform: uppercase; letter-spacing: .1em;
    color: var(--muted); font-family: 'JetBrains Mono', monospace;
    padding: 10px 12px; border-bottom: 1px solid var(--line);
}
.param-table td { padding: 12px; border-bottom: 1px solid var(--line); vertical-align: top; line-height: 1.65; }
.param-table tr:last-child td { border-bottom: none; }
.param-table code {
    font-family: 'JetBrains Mono', monospace; background: var(--bg-2);
    padding: 2px 7px; border-radius: 4px; font-size: 12.5px;
}
.badge { display: inline-block; font-family: 'JetBrains Mono', monospace; font-size: 11px; padding: 2px 8px; border-radius: 4px; }
.badge.ok { background: color-mix(in srgb, var(--ok) 14%, transparent); color: var(--ok); }
.badge.err { background: color-mix(in srgb, var(--err) 14%, transparent); color: var(--err); }
.req { color: var(--err); font-weight: 700; }
.code-block {
    background: var(--code-bg); color: var(--code-fg);
    font-family: 'JetBrains Mono', monospace; font-size: 13px; line-height: 1.85;
    padding: 16px 18px; border-radius: 8px; margin-top: 14px;
    overflow-x: auto; white-space: pre-wrap; word-break: break-all;
}
.code-block .cm { color: #8f8e86; }
.code-block .cc { color: #ff5a1f; }
.code-block .ok- { color: #34d399; }
.code-block .err- { color: #f87171; }
.copy-btn {
    display: inline-flex; align-items: center; gap: 6px; margin-top: 10px;
    padding: 7px 12px; border: 1px solid var(--line); background: var(--bg);
    color: var(--muted); font-size: 12px; font-family: 'JetBrains Mono', monospace;
    cursor: pointer; border-radius: 6px; transition: all .2s;
}
.copy-btn:hover { color: var(--accent); border-color: var(--accent); }
.copy-btn.copied { color: var(--ok); border-color: var(--ok); }

/* ---------- 页脚 ---------- */
.footer {
    border-top: 1px solid var(--line);
    padding: 28px clamp(20px, 5vw, 64px);
    display: flex; justify-content: space-between; align-items: center;
    flex-wrap: wrap; gap: 14px;
    color: var(--muted);
    font-family: 'JetBrains Mono', monospace; font-size: 12px;
}
.footer a { color: var(--muted); }
.footer a:hover { color: var(--accent); }
.footer .fl a { margin-left: 18px; }

/* ---------- 响应式 ---------- */
@media (max-width: 560px) {
    .brand-sub { display: none; }
    .param-table { font-size: 13px; }
}
</style>
</head>
<body>
<div class="topbar">
    <a class="brand" href="<?php echo $base; ?>">
        <span class="brand-mark">S</span>
        <span>
            <span class="brand-name">STEP.ENGINE</span>
            <span class="brand-sub">API Documentation</span>
        </span>
    </a>
    <div class="top-actions">
        <a class="top-link" href="https://github.com/1837620622/sport-xiaomi" target="_blank" rel="noopener"><i data-lucide="external-link" style="width:15px;height:15px"></i> GitHub</a>
        <button class="icon-btn" id="themeBtn" title="切换主题" onclick="toggleTheme()"><i data-lucide="moon" style="width:17px;height:17px"></i></button>
    </div>
</div>

<div class="wrap">
    <h1>API <em>文档</em></h1>
    <p class="sub" id="baseShow">GET / POST 均支持 · step 支持数字或"随机数" · 返回 JSON</p>

    <div class="doc-card">
        <div class="doc-head"><span class="pn">01</span><span class="ic"><i data-lucide="info" style="width:16px;height:16px"></i></span> 基本信息</div>
        <div class="doc-body">
            <table class="param-table">
                <tr><th>项目</th><th>内容</th></tr>
                <tr><td>接口地址 (Base URL)</td><td><code id="apiBase">(自动检测)</code></td></tr>
                <tr><td>请求方式</td><td><span class="badge ok">GET</span> 查询参数 <span class="badge ok">POST</span> 表单参数 (推荐)</td></tr>
                <tr><td>内容类型</td><td><code>application/x-www-form-urlencoded; charset=UTF-8</code></td></tr>
                <tr><td>返回格式</td><td><code>application/json; charset=utf-8</code></td></tr>
                <tr><td>频率限制</td><td>同一 IP 每分钟最多 <b>10</b> 次, 超出返回 429</td></tr>
                <tr><td>登录缓存</td><td>7 天内同一账号不重复调用上游登录接口</td></tr>
                <tr><td>版本</td><td>V3.0 · Zepp Life API</td></tr>
            </table>
        </div>
    </div>

    <div class="doc-card">
        <div class="doc-head"><span class="pn">02</span><span class="ic"><i data-lucide="list" style="width:16px;height:16px"></i></span> 请求参数</div>
        <div class="doc-body">
            <table class="param-table">
                <tr><th>参数</th><th>必填</th><th>类型</th><th>说明</th></tr>
                <tr><td><code>user</code></td><td><span class="req">是</span></td><td>string</td><td>Zepp Life(原小米运动)账号, 支持手机号或邮箱</td></tr>
                <tr><td><code>pwd</code></td><td><span class="req">是</span></td><td>string</td><td>账号登录密码, 建议用 POST 提交避免出现在 URL 中</td></tr>
                <tr><td><code>step</code></td><td><span class="req">是</span></td><td>int / string</td><td>目标步数: 数字 <code>1~98800</code>; 或字符串 <code>随机数</code> (自动生成 18000~30000)</td></tr>
                <tr><td><code>token</code></td><td><span class="req">条件</span></td><td>string</td><td>API 密钥 <code>666</code>: GET 请求 <b>必填</b>; POST 请求填了则跳过同源检查, 网页表单同源 POST 可省略</td></tr>
            </table>
            <div class="code-block"><span class="cm"># token 校验规则 (优先级从高到低)</span><br>1. POST 且请求来自本页面(同源) → 自动放行<br>2. 请求携带 token 且等于服务端密钥 → 放行<br>3. 其余情况 → 返回 401 Unauthorized</div>
        </div>
    </div>

    <div class="doc-card">
        <div class="doc-head"><span class="pn">03</span><span class="ic"><i data-lucide="terminal" style="width:16px;height:16px"></i></span> 请求示例</div>
        <div class="doc-body">
            <div class="code-block" id="code1"><span class="cm"># GET · 固定步数 (需带 token)</span><br><span class="cc">$</span> curl "<?php echo $base; ?>?user=13888888888&pwd=yourpassword&step=28000&token=<?php echo htmlspecialchars($token, ENT_QUOTES); ?>"</div>
            <button class="copy-btn" data-target="code1"><i data-lucide="copy" style="width:13px;height:13px"></i> 复制</button>
            <div class="code-block" id="code2"><span class="cm"># GET · 随机步数 18000~30000</span><br><span class="cc">$</span> curl "<?php echo $base; ?>?user=you@example.com&pwd=yourpassword&step=随机数&token=<?php echo htmlspecialchars($token, ENT_QUOTES); ?>"</div>
            <button class="copy-btn" data-target="code2"><i data-lucide="copy" style="width:13px;height:13px"></i> 复制</button>
            <div class="code-block" id="code3"><span class="cm"># POST · 表单提交, 推荐方式 (密码不进 URL)</span><br><span class="cc">$</span> curl -X POST "<?php echo $base; ?>" -d "user=you@example.com&pwd=yourpassword&step=28000&token=<?php echo htmlspecialchars($token, ENT_QUOTES); ?>"</div>
            <button class="copy-btn" data-target="code3"><i data-lucide="copy" style="width:13px;height:13px"></i> 复制</button>
            <div class="code-block" id="code4"><span class="cm"># Python 3 · requests 调用示例</span><br>import requests<br><br>r = requests.post("<?php echo $base; ?>", data={<br>&nbsp;&nbsp;&nbsp;&nbsp;"user": "you@example.com",<br>&nbsp;&nbsp;&nbsp;&nbsp;"pwd": "yourpassword",<br>&nbsp;&nbsp;&nbsp;&nbsp;"step": "随机数",<br>&nbsp;&nbsp;&nbsp;&nbsp;"token": "<?php echo htmlspecialchars($token, ENT_QUOTES); ?>"<br>})<br>print(r.json())</div>
            <button class="copy-btn" data-target="code4"><i data-lucide="copy" style="width:13px;height:13px"></i> 复制</button>
        </div>
    </div>

    <div class="doc-card">
        <div class="doc-head"><span class="pn">04</span><span class="ic"><i data-lucide="braces" style="width:16px;height:16px"></i></span> 返回结果</div>
        <div class="doc-body">
            <table class="param-table">
                <tr><th>字段</th><th>类型</th><th>说明</th></tr>
                <tr><td><code>time</code></td><td>string</td><td>提交时间 (格式 <code>Y-m-d H:i:s</code>)</td></tr>
                <tr><td><code>user</code></td><td>string</td><td>脱敏后的账号 (如 <code>138****8888</code>)</td></tr>
                <tr><td><code>step</code></td><td>int</td><td>实际提交的步数 (随机模式返回本次生成的值)</td></tr>
                <tr><td><code>status</code></td><td>string</td><td><span class="badge ok">success</span> 或 <span class="badge err">failed</span></td></tr>
                <tr><td><code>message</code></td><td>string</td><td>详细提示信息, 失败时含原因 (如账号密码错误)</td></tr>
            </table>
            <div class="code-block" id="code5"><span class="cm"># 成功响应 (HTTP 200)</span><br>{<br>&nbsp;&nbsp;"time": "<?php echo date('Y-m-d H:i:s'); ?>",<br>&nbsp;&nbsp;"user": "138****8888",<br>&nbsp;&nbsp;"step": 28000,<br>&nbsp;&nbsp;<span class="ok-">"status": "success"</span>,<br>&nbsp;&nbsp;"message": "修改步数(28000)"<br>}</div>
            <button class="copy-btn" data-target="code5"><i data-lucide="copy" style="width:13px;height:13px"></i> 复制</button>
            <div class="code-block" id="code6"><span class="cm"># 失败响应 (HTTP 200, 业务失败)</span><br>{<br>&nbsp;&nbsp;"time": "<?php echo date('Y-m-d H:i:s'); ?>",<br>&nbsp;&nbsp;"user": "138****8888",<br>&nbsp;&nbsp;"step": 28000,<br>&nbsp;&nbsp;<span class="err-">"status": "failed"</span>,<br>&nbsp;&nbsp;"message": "登录失败: 账号或密码错误!"<br>}</div>
            <button class="copy-btn" data-target="code6"><i data-lucide="copy" style="width:13px;height:13px"></i> 复制</button>
        </div>
    </div>

    <div class="doc-card">
        <div class="doc-head"><span class="pn">05</span><span class="ic"><i data-lucide="shield-alert" style="width:16px;height:16px"></i></span> 错误码 (HTTP 状态码)</div>
        <div class="doc-body">
            <table class="param-table">
                <tr><th>状态码</th><th>说明</th><th>常见场景</th></tr>
                <tr><td><span class="badge ok">200</span></td><td>请求处理完成</td><td>正常返回, 看 <code>status</code> 字段判断业务成败</td></tr>
                <tr><td><span class="badge err">400</span></td><td>参数错误</td><td>缺少 <code>user</code>/<code>pwd</code>/<code>step</code> 或步数超出 1~98800</td></tr>
                <tr><td><span class="badge err">401</span></td><td>密钥无效</td><td>GET 未带 token 或 token 错误</td></tr>
                <tr><td><span class="badge err">404</span></td><td>接口不存在</td><td>未知的 <code>m</code> 参数 (如 <code>?m=xxx</code>)</td></tr>
                <tr><td><span class="badge err">429</span></td><td>请求过于频繁</td><td>同一 IP 超过每分钟 10 次, 请稍后重试</td></tr>
                <tr><td><span class="badge err">500</span></td><td>服务器内部错误</td><td>上游服务不可达或未知异常, 稍后重试</td></tr>
            </table>
        </div>
    </div>

    <div class="doc-card">
        <div class="doc-head"><span class="pn">06</span><span class="ic"><i data-lucide="alert-triangle" style="width:16px;height:16px"></i></span> 注意事项</div>
        <div class="doc-body">
            <table class="param-table">
                <tr><td>1</td><td>账号为 <b>Zepp Life / 小米运动</b> 账号, 不是小米账号, 两者不同</td></tr>
                <tr><td>2</td><td>需要先在 Zepp Life App 中绑定微信 / 支付宝等第三方平台, 步数才会同步过去</td></tr>
                <tr><td>3</td><td>不建议使用 66666 / 88888 等特殊步数, 可能被平台判定异常</td></tr>
                <tr><td>4</td><td>登录信息缓存 7 天, 同一账号无需重复登录; 修改密码后等待缓存过期即可</td></tr>
                <tr><td>5</td><td>参数请使用 URL 编码 (curl 的 <code>--data-urlencode</code> 或 requests 的 <code>data=</code> 会自动处理)</td></tr>
                <tr><td>6</td><td>本工具仅供个人学习研究, 请勿商用</td></tr>
            </table>
        </div>
    </div>
</div>

<footer class="footer">
    <span>© 传康KK · STEP.ENGINE</span>
    <div class="fl">
        <a href="<?php echo $base; ?>">返回首页</a>
        <a href="https://github.com/1837620622/sport-xiaomi" target="_blank" rel="noopener">GitHub</a>
    </div>
</footer>

<script>
lucide.createIcons();
document.querySelectorAll('svg.lucide').forEach(function (s) { s.setAttribute('aria-hidden', 'true'); });

/* 自动填充接口地址 */
(function () {
    var box = document.getElementById('apiBase');
    if (box) { box.textContent = location.origin + location.pathname; }
})();

/* 主题切换 */
(function () {
    const saved = localStorage.getItem('step-theme');
    const prefers = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    document.documentElement.dataset.theme = saved || prefers;
    syncThemeIcon();
})();
function toggleTheme() {
    const cur = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = cur;
    localStorage.setItem('step-theme', cur);
    syncThemeIcon();
}
function syncThemeIcon() {
    const dark = document.documentElement.dataset.theme === 'dark';
    const btn = document.querySelector('#themeBtn');
    if (btn) {
        btn.innerHTML = '<i data-lucide="' + (dark ? 'sun' : 'moon') + '" style="width:17px;height:17px"></i>';
        lucide.createIcons();
    }
}

/* 复制代码(带旧浏览器降级方案) */
function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); resolve(); }
        catch (e) { reject(e); }
        document.body.removeChild(ta);
    });
}
document.querySelectorAll('.copy-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
        var block = document.getElementById(this.dataset.target);
        var text = block.textContent.replace(/^# [^\n]*\n/m, '').trim();
        var that = this;
        copyText(text).then(function () {
            that.innerHTML = '<i data-lucide="check" style="width:13px;height:13px"></i> 已复制';
            lucide.createIcons();
            setTimeout(function () {
                that.innerHTML = '<i data-lucide="copy" style="width:13px;height:13px"></i> 复制';
                lucide.createIcons();
            }, 1600);
        });
    });
});
</script>
</body>
</html>
<?php
    exit;
}

// ==================== 主执行逻辑 ====================
// GET / POST 统一处理(网页表单与 API 调用)
if ($_SERVER['REQUEST_METHOD'] === 'POST' || isset($_GET['token']) || isset($_POST['token'])) {
    // 带 m 参数的 API 调用: 文档页优先返回, 其余 m 一律 404
    if (isset($_GET['m'])) {
        if ($_GET['m'] === 'appinfo') {
            showAppInfo();
        } else {
            jsonResponse(["error" => "not found"], 404);
        }
    }

    // token 校验前置: 未认证请求不消耗限频配额
    // 网页表单(POST 同源请求)自动携带渲染的 token, 亦可通过校验
    $isWebForm = $_SERVER['REQUEST_METHOD'] === 'POST' && isSameOrigin();
    $validToken = (isset($_GET['token']) || isset($_POST['token'])) && param('token') === $token;
    if (!$validToken && !$isWebForm) {
        jsonResponse(["error" => "Token 验证失败"], 401);
    }

    // 频率限制检查
    list($rateLimitOk, $rateLimitMsg) = checkRateLimit();
    if (!$rateLimitOk) {
        jsonResponse(["error" => $rateLimitMsg], 429);
    }

    $user = param('user');
    $pwd = param('pwd');
    $step = param('step');

    if (!$user || !$pwd || $step === '') {
        jsonResponse(["error" => "参数不完整, 必须提供 user, pwd, step"], 400);
    }

    // 步数解析(支持数字 / 随机数)
    list($stepValid, $stepResult) = resolveStep($step);
    if (!$stepValid) {
        jsonResponse(["error" => $stepResult], 400);
    }

    try {
        $runner = new MiMotionRunner($user, $pwd);
        list($msg, $success) = $runner->loginAndPostStep($stepResult);
    } catch (\Throwable $e) {
        // 捕获所有错误(含 TypeError/ValueError), 避免空响应 500
        jsonResponse(["error" => "服务器内部错误: " . $e->getMessage()], 500);
    }

    $output = [
        "time" => date("Y-m-d H:i:s"),
        "user" => desensitizeUserName($user),
        "step" => $stepResult,
        "status" => $success ? "success" : "failed",
        "message" => $msg
    ];

    jsonResponse($output, 200);
}
?>