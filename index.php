<?php
/**
 * 小米运动(Zepp Life)刷步数引擎 - Zepp API 版
 *
 * 接口用法(GET / POST 均可):
 *   ?user=账号&pwd=密码&step=28000&token=666
 *   step 支持数字或"随机数"(自动生成 18000~30000 随机步数)
 *
 * 作者: 传康KK
 * 说明: 仅供个人学习研究, 修改后的步数自动同步微信/支付宝等已绑定平台
 */

$token = "666";
date_default_timezone_set('Asia/Shanghai');

// ==================== 路由处理 ====================
// 轻量自检接口(首页状态灯使用, 不消耗限频、不触发登录)
if (isset($_GET['m']) && $_GET['m'] === 'ping') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['status' => 'ok', 'time' => date('Y-m-d H:i:s')]);
    exit;
}
// 纯 GET 且无 token 参数 -> 显示网页界面
if ($_SERVER['REQUEST_METHOD'] === 'GET' && !isset($_GET['token']) && empty($_POST)) {
    showWebPage();
}

function param($key, $default = '') {
    return isset($_POST[$key]) ? trim($_POST[$key]) : (isset($_GET[$key]) ? trim($_GET[$key]) : $default);
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
    if (!is_numeric($step)) {
        return [false, 'step 参数必须是数字或"随机数"', false];
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
function checkRateLimit() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $rateLimitDir = __DIR__ . '/cache/rate_limit/';
    if (!is_dir($rateLimitDir)) {
        mkdir($rateLimitDir, 0755, true);
    }
    $rateLimitFile = $rateLimitDir . md5($ip) . '.txt';
    $currentTime = time();
    $windowSize = 60;
    $maxRequests = 10;

    $requests = [];
    if (file_exists($rateLimitFile)) {
        $data = file_get_contents($rateLimitFile);
        $requests = json_decode($data, true) ?: [];
    }
    $requests = array_filter($requests, function ($timestamp) use ($currentTime, $windowSize) {
        return ($currentTime - $timestamp) < $windowSize;
    });
    if (count($requests) >= $maxRequests) {
        return [false, '请求过于频繁, 请稍后再试(每分钟最多' . $maxRequests . '次)'];
    }
    $requests[] = $currentTime;
    file_put_contents($rateLimitFile, json_encode(array_values($requests)));
    return [true, ''];
}

// ==================== 核心: MiMotionRunner ====================
class MiMotionRunner {
    private $user;
    private $password;
    public $logStr = "";
    public $invalid = false;
    private $cacheDir = __DIR__ . '/cache/';
    private $cacheFile;

    function __construct($user, $passwd) {
        if (!$user || !$passwd) {
            $this->invalid = true;
            $this->logStr .= "用户名或密码填写有误!\n";
            return;
        }
        $this->user = $user;
        $this->password = $passwd;

        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0755, true);
        }
        $this->cacheFile = $this->cacheDir . getSafeFilename($user) . '.txt';
    }

    // 读取缓存
    private function readCache() {
        if (!file_exists($this->cacheFile)) {
            return null;
        }
        $fp = fopen($this->cacheFile, 'r');
        if (!$fp) {
            return null;
        }
        if (flock($fp, LOCK_SH)) {
            $data = file_get_contents($this->cacheFile);
            flock($fp, LOCK_UN);
            fclose($fp);
            $cache = json_decode($data, true);
            if (!$cache || !isset($cache['expire_time']) || $cache['expire_time'] < time()) {
                $this->clearCache();
                return null;
            }
            return $cache;
        }
        fclose($fp);
        return null;
    }

    // 写入缓存
    private function writeCache($access, $third_name) {
        $cacheData = [
            'access' => $access,
            'third_name' => $third_name,
            'user' => $this->user,
            'create_time' => time(),
            'expire_time' => time() + 604800 // 7天
        ];
        $jsonData = json_encode($cacheData);
        $tempFile = $this->cacheFile . '.tmp.' . uniqid();
        $fp = fopen($tempFile, 'w');
        if (!$fp) {
            return false;
        }
        if (flock($fp, LOCK_EX)) {
            fwrite($fp, $jsonData);
            fflush($fp);
            flock($fp, LOCK_UN);
            fclose($fp);
            if (rename($tempFile, $this->cacheFile)) {
                return true;
            }
            unlink($tempFile);
            return false;
        }
        fclose($fp);
        unlink($tempFile);
        return false;
    }

    // 清除缓存
    private function clearCache() {
        if (file_exists($this->cacheFile)) {
            unlink($this->cacheFile);
        }
    }

    // AES-128-CBC 加密
    private function encryptData($plain) {
        $key = 'xeNtBVqzDc6tuNTh';
        $iv = 'MAAAYAAAAAAAAABg';
        return openssl_encrypt($plain, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);
    }

    private function curl($url, $data = null, $app_token = null, $ekv = false) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
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
        if ($data) {
            if (is_array($data)) $data = http_build_query($data);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            curl_setopt($ch, CURLOPT_POST, 1);
        }
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_USERAGENT, 'MiFit6.14.0 (OPD2413; Android 15; Density/2.625)');
        curl_setopt($ch, CURLOPT_HEADER, 1);
        $ret = curl_exec($ch);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $header = substr($ret, 0, $headerSize);
        $body = substr($ret, $headerSize);
        curl_close($ch);
        return ['header' => $header, 'body' => $body];
    }

    private function getAccess($username, $password) {
        // 优先使用缓存
        $cache = $this->readCache();
        if ($cache && isset($cache['access']) && isset($cache['third_name'])) {
            return [$cache['access'], $cache['third_name']];
        }

        $third_name = strpos($username, '@') === false ? 'huami_phone' : 'email';
        if (strpos($username, '@') === false) {
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
        $response = $this->curl($url, $body, null, true);
        if (preg_match("/access=(.*?)&/", $response['header'], $access)) {
            $this->writeCache($access[1], $third_name);
            return [$access[1], $third_name];
        } elseif (preg_match("/refresh=(.*?)&/", $response['header'], $refresh)) {
            $this->writeCache($refresh[1], $third_name);
            return [$refresh[1], $third_name];
        } elseif (strpos($response['header'], 'error=')) {
            $this->clearCache();
            throw new Exception('账号或密码错误!');
        } else {
            throw new Exception('登录token接口请求失败');
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
            if (!$arr) {
                throw new Exception('登录接口请求失败');
            } elseif (isset($arr['result']) && $arr['result'] == 'ok') {
                $token = $arr['token_info']['app_token'];
                $userid = $arr['token_info']['user_id'];
                return [$token, $userid];
            } else {
                $this->clearCache();
                throw new Exception('登录失败' . $response['body']);
            }
        } catch (Exception $e) {
            $this->logStr .= "登录异常: " . $e->getMessage() . "\n";
            return [0, 0, $e->getMessage()];
        }
    }

    public function loginAndPostStep($step) {
        if ($this->invalid) return ["账号或密码配置有误", false];

        $loginResult = $this->login();
        $token = $loginResult[0] ?? 0;
        $userid = $loginResult[1] ?? 0;
        $loginError = $loginResult[2] ?? '';

        if (!$token) {
            $errorMsg = $loginError ? "登录失败: {$loginError}" : "登录失败!";
            return [$errorMsg, false];
        }

        try {
            $url = "https://api-mifit-cn.zepp.com/v1/data/band_data.json?&t=" . time();
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
                $message = isset($arr['message']) ? $arr['message'] : $response['body'];
                throw new Exception('修改步数失败: ' . $message);
            }
        } catch (Exception $e) {
            return [$e->getMessage(), false];
        }
    }
}

// ==================== 网页界面(运动竞速仪表风格) ====================
function showWebPage() {
    $self = htmlspecialchars($_SERVER['PHP_SELF'] ?? '/');
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $base = $scheme . '://' . $host . $self;
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="STEP.ENGINE - 小米运动 Zepp Life 步数同步引擎, 一键同步微信运动 / 支付宝运动">
<title>STEP.ENGINE - 把今天的目标跑出来</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%23ff4d00'/%3E%3Cpath d='M8 21h3l2-8 4 13 3-11 1 6h3' fill='none' stroke='%23fff' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700;800&display=swap" rel="stylesheet">
<script src="https://unpkg.com/lucide@latest"></script>
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
.brand-sub { font-size: 10px; color: var(--muted); letter-spacing: 0.14em; text-transform: uppercase; margin-top: 2px; font-family: 'JetBrains Mono'; }
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
    font-size: 13px; color: var(--muted);
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
            <div class="brand-sub">Zepp Life Step Sync</div>
        </span>
    </a>
    <div class="top-actions">
        <a class="top-link" href="docs/"><i data-lucide="book-open" style="width:15px;height:15px"></i> API 文档</a>
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
        <a href="docs/">API 文档</a>
        <a href="https://github.com/1837620622/sport-xiaomi" target="_blank" rel="noopener">GitHub</a>
    </div>
</footer>

<script>
lucide.createIcons();

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
    const ic = document.querySelector('#themeBtn i');
    if (ic) { ic.setAttribute('data-lucide', dark ? 'sun' : 'moon'); lucide.createIcons(); }
}

/* ---------- 密码可见 ---------- */
function togglePwd() {
    const inp = document.getElementById('fPwd');
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    document.getElementById('eyeIc').setAttribute('data-lucide', show ? 'eye-off' : 'eye');
    lucide.createIcons();
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
    const v = Math.floor(18000 + Math.random() * 12000);
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
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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
    termClear();
    termCursor(true);
    termCmd('step-engine --user ' + user.replace(/(.{3}).*(@.*)/, '$1****$2') + ' --step ' + step);

    const body = new URLSearchParams();
    body.append('user', user);
    body.append('pwd', pwd);
    body.append('step', step);

    fetch('<?php echo $base; ?>', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString()
    })
    .then(function (r) { return r.json(); })
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

// ==================== 主执行逻辑 ====================
// GET / POST 统一处理(网页表单与 API 调用)
if ($_SERVER['REQUEST_METHOD'] === 'POST' || (isset($_GET['token']) && $_GET['token'] !== '')) {
    // 频率限制检查
    list($rateLimitOk, $rateLimitMsg) = checkRateLimit();
    if (!$rateLimitOk) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(["error" => $rateLimitMsg], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }

    // GET API 调用时校验 token
    if ($_SERVER['REQUEST_METHOD'] === 'GET' && (!isset($_GET['token']) || $_GET['token'] !== $token)) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(["error" => "Token 验证失败"], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }

    $user = param('user');
    $pwd = param('pwd');
    $step = param('step');

    if (!$user || !$pwd || $step === '') {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(["error" => "参数不完整, 必须提供 user, pwd, step"], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }

    // 步数解析(支持数字 / 随机数)
    list($stepValid, $stepResult, $isRandom) = resolveStep($step);
    if (!$stepValid) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(["error" => $stepResult], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }

    $runner = new MiMotionRunner($user, $pwd);
    list($msg, $success) = $runner->loginAndPostStep($stepResult);

    $output = [
        "time" => date("Y-m-d H:i:s"),
        "user" => desensitizeUserName($user),
        "step" => $stepResult,
        "status" => $success ? "success" : "failed",
        "message" => $msg
    ];

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($output, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}
?>