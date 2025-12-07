<?php
/**
 * 小米运动刷步数 - 单账号固定步数 API 版
 * 使用方法（GET/POST均可）：
 * user  - 账号（手机号或邮箱）
 * pwd   - 密码
 * step  - 固定步数（必填，范围：1-98800）
 *
 * 示例：
 * curl "http://your-domain.com/index.php?user=your_account&pwd=your_password&step=20000&token=666"
 * 
 * 作者：传康KK
 * 微信：1837620622
 */

$token = "666";

date_default_timezone_set('Asia/Shanghai');

// ==================== 路由处理 ====================
// 如果通过 GET 访问且没有 token 参数，显示网页界面
if ($_SERVER['REQUEST_METHOD'] === 'GET' && !isset($_GET['token']) && empty($_POST)) {
    if (isset($_GET['m']) && $_GET['m'] === 'appinfo') {
        showAppInfo();
    } else {
        showWebPage();
    }
}

// ==================== 辅助函数 ====================
// 从 POST 获取参数，否则从 GET 获取
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
    // 移除可能引起路径遍历的字符
    $safeName = preg_replace('/[^a-zA-Z0-9_\-@.]/', '_', $username);
    // 限制文件名长度
    if (strlen($safeName) > 100) {
        $safeName = substr($safeName, 0, 100);
    }
    return $safeName;
}

// 验证步数范围（合理范围：1-98800，避免异常数据）
function validateStep($step) {
    $step = intval($step);
    if ($step < 1) {
        return [false, '步数不能小于1'];
    }
    if ($step > 98800) {
        return [false, '步数不能超过98800（每日最大合理步数）'];
    }
    return [true, $step];
}

// 简单的请求频率限制（基于IP，每分钟最多10次请求）
function checkRateLimit() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $rateLimitDir = __DIR__ . '/cache/rate_limit/';
    
    if (!is_dir($rateLimitDir)) {
        mkdir($rateLimitDir, 0755, true);
    }
    
    $rateLimitFile = $rateLimitDir . md5($ip) . '.txt';
    $currentTime = time();
    $windowSize = 60; // 60秒时间窗口
    $maxRequests = 10; // 最大请求次数
    
    $requests = [];
    if (file_exists($rateLimitFile)) {
        $data = file_get_contents($rateLimitFile);
        $requests = json_decode($data, true) ?: [];
    }
    
    // 过滤掉过期的请求记录
    $requests = array_filter($requests, function($timestamp) use ($currentTime, $windowSize) {
        return ($currentTime - $timestamp) < $windowSize;
    });
    
    if (count($requests) >= $maxRequests) {
        return [false, '请求过于频繁，请稍后再试（每分钟最多' . $maxRequests . '次）'];
    }
    
    // 添加当前请求时间戳
    $requests[] = $currentTime;
    file_put_contents($rateLimitFile, json_encode(array_values($requests)));
    
    return [true, ''];
}

class MiMotionRunner {
    private $user;
    private $password;
    public $logStr = "";
    public $invalid = false;
    private $cacheDir = __DIR__ . '/cache/'; // 缓存目录，可自定义
    private $cacheFile;

    function __construct($user, $passwd) {
        if (!$user || !$passwd) {
            $this->invalid = true;
            $this->logStr .= "用户名或密码填写有误！\n";
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
        } else {
            fclose($fp);
            return null;
        }
    }

	// 写入缓存
    private function writeCache($access, $third_name) {
        $cacheData = [
            'access' => $access,
            'third_name' => $third_name,
            'user' => $this->user,
            'create_time' => time(),
            'expire_time' => time() + 604800 // 7天后过期（暂时还不知道具体多久过期，后续可能修改）
        ];
        
        $jsonData = json_encode($cacheData);
        
        // 保险起见先写入临时文件，然后重命名
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
            } else {
                unlink($tempFile);
                return false;
            }
        } else {
            fclose($fp);
            unlink($tempFile);
            return false;
        }
    }

	// 清除缓存
    private function clearCache() {
        if (file_exists($this->cacheFile)) {
            unlink($this->cacheFile);
        }
    }

    private function encryptData($plain) {
        $key = 'xeNtBVqzDc6tuNTh';
        $iv = 'MAAAYAAAAAAAAABg';
        $cipher = openssl_encrypt($plain, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return $cipher;
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
        curl_setopt($ch, CURLOPT_TIMEOUT, 30); // 总超时时间30秒
        curl_setopt($ch, CURLOPT_USERAGENT, 'MiFit6.14.0 (OPD2413; Android 15; Density/2.625)');
        curl_setopt($ch, CURLOPT_HEADER, 1);
        $ret = curl_exec($ch);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $header = substr($ret, 0, $headerSize);
        $body = substr($ret, $headerSize);
        $ret = array();
        $ret['header'] = $header;
        $ret['body'] = $body;
        curl_close($ch);
        return $ret;
    }

    private function getAccess($username, $password) {
        // 首先尝试从缓存读取
        $cache = $this->readCache();
        if ($cache && isset($cache['access']) && isset($cache['third_name'])) {
            return [$cache['access'], $cache['third_name']];
        }

        // 缓存不存在或已过期，从API获取
        $third_name = strpos($username, '@') === false ? 'huami_phone' : 'email';
        
        // 修复：使用 strpos !== false 正确判断是否包含 @
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
            // 成功获取，写入缓存
            $this->writeCache($access[1], $third_name);
            return [$access[1], $third_name];
        } elseif (preg_match("/refresh=(.*?)&/", $response['header'], $refresh)) {
            // 成功获取，写入缓存
            $this->writeCache($refresh[1], $third_name);
            return [$refresh[1], $third_name];
        } elseif (strpos($response['header'], 'error=')) {
            // 登录失败时清除可能存在的旧缓存
            $this->clearCache();
            throw new Exception('账号或密码错误！');
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
                // 登录失败时清除缓存，因为token可能已失效
                $this->clearCache();
                throw new Exception('登录失败' . $response['body']);
            }
        } catch (Exception $e) {
            $this->logStr .= "登录异常：" . $e->getMessage() . "\n";
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
            $errorMsg = $loginError ? "登录失败：{$loginError}" : "登录失败！";
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
                return ["修改步数（{$step}）", true];
            } else {
                $message = isset($arr['message']) ? $arr['message'] : $response['body'];
                throw new Exception('修改步数失败：' . $message);
            }
        } catch (Exception $e) {
            return [$e->getMessage(), false];
        }
    }
}

// ==================== 显示网页界面 ====================
function showWebPage() {
    $file = basename($_SERVER['PHP_SELF']);
    ?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <title>小米运动刷步数工具 - 传康优创互联网</title>
    <link rel="stylesheet" href="https://www.layuicdn.com/layui-v2.6.8/css/layui.css" media="all">
    <script src="https://www.layuicdn.com/layui-v2.6.8/layui.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            font-family: 'Microsoft YaHei', 'PingFang SC', sans-serif;
        }
        
        .container {
            max-width: 600px;
            margin: 0 auto;
        }
        
        .main-card {
            background: rgba(255, 255, 255, 0.98);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
            animation: slideUp 0.5s ease-out;
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px;
            text-align: center;
            color: white;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: rotate 20s linear infinite;
        }
        
        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        .header-content {
            position: relative;
            z-index: 1;
        }
        
        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
            font-weight: bold;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        
        .header p {
            font-size: 14px;
            opacity: 0.95;
        }
        
        .alert-box {
            margin: 20px;
            padding: 15px;
            border-radius: 12px;
            border-left: 4px solid;
        }
        
        .alert-danger {
            background: linear-gradient(135deg, #fff5f5 0%, #ffe5e5 100%);
            border-left-color: #ff4757;
            color: #c23616;
        }
        
        .alert-info {
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            border-left-color: #3742fa;
            color: #2c3e50;
        }
        
        .alert-box p {
            margin: 5px 0;
            line-height: 1.6;
        }
        
        .alert-box strong {
            font-size: 16px;
        }
        
        .form-section {
            padding: 40px 35px 35px 35px;
        }
        
        .layui-form-item {
            margin-bottom: 28px;
        }
        
        .layui-form-pane .layui-form-item[pane] {
            margin: 0;
        }
        
        .layui-form-label {
            width: 110px;
            font-weight: 600;
            color: #333;
            font-size: 15px;
        }
        
        .layui-input, .layui-textarea {
            border-radius: 8px;
            border: 2px solid #e8e8e8;
            transition: all 0.3s;
            padding: 10px 15px;
        }
        
        .layui-input:focus, .layui-textarea:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .submit-btn-wrapper {
            text-align: center;
            margin-top: 40px;
            margin-bottom: 10px;
        }
        
        .submit-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 50px;
            padding: 14px 45px;
            font-size: 16px;
            font-weight: bold;
            color: white;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 8px 20px rgba(102, 126, 234, 0.35);
            letter-spacing: 1px;
            position: relative;
            overflow: hidden;
            min-width: 180px;
            display: inline-block;
            line-height: 1.5;
        }
        
        .submit-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            transition: left 0.5s;
        }
        
        .submit-btn:hover::before {
            left: 100%;
        }
        
        .submit-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 12px 30px rgba(102, 126, 234, 0.5);
        }
        
        .submit-btn:active {
            transform: translateY(-1px);
            box-shadow: 0 6px 15px rgba(102, 126, 234, 0.4);
        }
        
        .info-card {
            margin: 20px;
            padding: 20px;
            background: linear-gradient(135deg, #f5f7fa 0%, #e8ecf1 100%);
            border-radius: 12px;
            border: 1px solid #ddd;
        }
        
        .info-card-header {
            font-size: 18px;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        .info-card p {
            margin: 10px 0;
            line-height: 1.8;
            color: #555;
            padding-left: 20px;
            position: relative;
        }
        
        .info-card p::before {
            content: '●';
            position: absolute;
            left: 0;
            color: #667eea;
        }
        
        .api-section {
            background: linear-gradient(135deg, #fff9e6 0%, #fff3cc 100%);
            border: 1px solid #ffd700;
        }
        
        .api-section .info-card-header {
            color: #f39c12;
            border-bottom-color: #f39c12;
        }
        
        .api-section p::before {
            color: #f39c12;
        }
        
        .api-section ul {
            margin: 10px 0;
            padding-left: 40px;
        }
        
        .api-section li {
            margin: 8px 0;
            line-height: 1.8;
            color: #555;
        }
        
        .api-section strong {
            color: #f39c12;
        }
        
        .api-section a {
            color: #667eea;
            text-decoration: none;
            font-weight: bold;
            padding: 5px 15px;
            background: white;
            border-radius: 5px;
            display: inline-block;
            margin-top: 5px;
            transition: all 0.3s;
        }
        
        .api-section a:hover {
            background: #667eea;
            color: white;
            transform: translateX(5px);
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: white;
            font-size: 14px;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
        }
        
        .loading-text {
            color: #667eea;
            font-size: 16px;
            font-weight: bold;
            animation: pulse 1.5s ease-in-out infinite;
            padding: 10px 0;
        }
        
        @keyframes pulse {
            0%, 100% {
                opacity: 1;
            }
            50% {
                opacity: 0.5;
            }
        }
        
        @media (max-width: 768px) {
            .header h1 {
                font-size: 22px;
            }
            
            .form-section {
                padding: 25px 20px;
            }
            
            .layui-form-label {
                width: 90px;
                font-size: 13px;
            }
            
            .submit-btn {
                padding: 12px 35px;
                font-size: 15px;
                min-width: 150px;
                letter-spacing: 0.5px;
            }
            
            .alert-box {
                margin: 15px;
                padding: 12px;
            }
            
            .info-card {
                margin: 15px;
                padding: 15px;
            }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="main-card">
        <!-- 顶部标题区域 -->
        <div class="header">
            <div class="header-content">
                <h1>🏃 小米运动刷步数工具</h1>
                <p>传康优创互联网科技 | 智能运动数据管理</p>
            </div>
        </div>
        
        <!-- 提示信息区域 -->
        <div class="alert-box alert-danger">
            <p><strong>⚠️ 安全提示</strong></p>
            <p>本工具不记录您的账号密码，但建议您使用小号进行测试！</p>
        </div>
        
        <div class="alert-box alert-info">
            <p><strong>✨ 功能特性</strong></p>
            <p>使用最新的 Zepp API 接口，支持 7 天登录缓存机制，提高访问速度！</p>
        </div>

        <!-- 表单区域 -->
        <div class="form-section">
            <form class="layui-form layui-form-pane" action="">
                <div class="layui-form-item">
                    <label class="layui-form-label">📱 Zepp账号</label>
                    <div class="layui-input-block">
                        <input type="text" name="user" placeholder="请输入Zepp账号(手机号或邮箱)" autocomplete="off" class="layui-input">
                    </div>
                </div>
                
                <div class="layui-form-item">
                    <label class="layui-form-label">🔐 密码</label>
                    <div class="layui-input-block">
                        <input type="password" name="pwd" placeholder="请输入密码" autocomplete="off" class="layui-input">
                    </div>
                </div>
                
                <div class="layui-form-item">
                    <label class="layui-form-label">👟 修改步数</label>
                    <div class="layui-input-block">
                        <input type="text" name="step" placeholder="请输入需要修改的步数" autocomplete="off" class="layui-input">
                    </div>
                </div>
                
                <div class="submit-btn-wrapper" id="button">
                    <button class="layui-btn submit-btn" lay-submit="" lay-filter="submitForm">立即提交</button>
                </div>
            </form>
        </div>

        <!-- 使用说明区域 -->
        <div class="info-card">
            <div class="info-card-header">📖 使用说明</div>
            <p>本工具仅供个人学习、研究，不可商用！</p>
            <p>使用工具前，需要下载小米运动APP（或 Zepp Life），接入第三方平台（微信、QQ、支付宝、新浪微博、阿里体育）</p>
            <p>接入第三方后可卸载小米运动APP，使用本工具会自动同步数据</p>
            <p>不建议使用 66666、88888 等特殊步数，可能因被举报而无法同步</p>
            <p>本工具使用缓存机制，登录信息会缓存7天，提高访问速度</p>
            <p>本工具不记录您的账号信息，但建议使用小米小号进行测试</p>
        </div>

        <!-- API 接口说明区域 -->
        <div class="info-card api-section">
            <div class="info-card-header">🔌 API 接口说明</div>
            <p><strong>接口地址：</strong><?php echo 'http://'.$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF']; ?></p>
            <p><strong>请求方式：</strong>GET / POST</p>
            <p><strong>参数说明：</strong></p>
            <ul>
                <li>user - 账号（手机号或邮箱）</li>
                <li>pwd - 密码</li>
                <li>step - 步数</li>
                <li>token - API密钥（固定值：666，网页提交不需要）</li>
            </ul>
            <p><a href="?m=appinfo" target="_blank">📄 查看详细 API 文档</a></p>
        </div>
    </div>
    
    <!-- 底部信息 -->
    <div class="footer">
        <p>💡 生命在于运动，可别忘了出门锻炼哦！</p>
        <p style="margin-top: 5px; opacity: 0.8;">© 2025传康KK</p>
    </div>
</div>

<script>
layui.use(['layer', 'form'], function(){
    var form = layui.form,
        layer = layui.layer,
        $ = layui.$;
    
    form.on('submit(submitForm)', function(data){
        var da = data.field;
        
        if (da.user == '') {
            layer.msg('账号不能为空！');
            return false;
        }
        
        if (da.pwd == '') {
            layer.msg('请输入密码！');
            return false;
        }
        
        if (da.step == '') {
            layer.msg('步数不能为空！');
            return false;
        }
        
        document.getElementById('button').innerHTML = '<p class="loading-text">⏳ 提交中，请稍后...</p>';
        
        $.ajax({
            type: 'post',
            url: '<?php echo $file; ?>',
            data: {
                user: da.user,
                pwd: da.pwd,
                step: da.step
            },
            success: function(s){
                if (typeof s === 'string') {
                    try {
                        s = JSON.parse(s);
                    } catch(e) {}
                }
                if (s.message) {
                    layer.msg(s.message);
                } else if (s.error) {
                    layer.msg(s.error);
                } else {
                    layer.msg('提交成功！');
                }
                resetButton();
            },
            error: function(){
                layer.msg('接口请求失败，请重试！');
                resetButton();
            }
        });
        
        return false;
    });
    
    function resetButton(){
        document.getElementById('button').innerHTML = '<button class="layui-btn submit-btn" lay-submit="" lay-filter="submitForm">立即提交</button>';
    }
});
</script>
</body>
</html>
    <?php
    exit;
}

// ==================== API 信息页面 ====================
function showAppInfo() {
    $url = 'http://'.$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF'];
    ?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <title>API 文档 - 小米运动刷步数工具</title>
    <link rel="stylesheet" href="https://www.layuicdn.com/layui-v2.6.8/css/layui.css" media="all">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            font-family: 'Microsoft YaHei', 'PingFang SC', sans-serif;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
        }
        
        .doc-card {
            background: rgba(255, 255, 255, 0.98);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
            animation: slideUp 0.5s ease-out;
            margin-bottom: 20px;
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .doc-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px 30px;
            text-align: center;
            color: white;
            position: relative;
            overflow: hidden;
        }
        
        .doc-header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: rotate 20s linear infinite;
        }
        
        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        .doc-header-content {
            position: relative;
            z-index: 1;
        }
        
        .doc-header h1 {
            font-size: 32px;
            margin-bottom: 15px;
            font-weight: bold;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        
        .doc-header .version {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 5px 20px;
            border-radius: 20px;
            margin-top: 10px;
            font-size: 14px;
        }
        
        .doc-section {
            padding: 30px;
            border-bottom: 1px solid #eee;
        }
        
        .doc-section:last-child {
            border-bottom: none;
        }
        
        .section-title {
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            display: flex;
            align-items: center;
        }
        
        .section-title::before {
            content: '●';
            margin-right: 10px;
            font-size: 20px;
        }
        
        .param-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .param-table th {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: bold;
        }
        
        .param-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #f0f0f0;
        }
        
        .param-table tr:last-child td {
            border-bottom: none;
        }
        
        .param-table tr:hover {
            background: #f8f9ff;
        }
        
        .param-name {
            color: #667eea;
            font-weight: bold;
            font-family: 'Courier New', monospace;
        }
        
        .code-block {
            background: #2d3748;
            color: #a0aec0;
            padding: 20px;
            border-radius: 10px;
            margin: 15px 0;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            box-shadow: inset 0 2px 10px rgba(0,0,0,0.3);
        }
        
        .code-block code {
            color: #68d391;
            word-break: break-all;
        }
        
        .feature-list {
            list-style: none;
            padding: 0;
        }
        
        .feature-list li {
            padding: 12px 0 12px 35px;
            position: relative;
            line-height: 1.8;
            color: #555;
        }
        
        .feature-list li::before {
            content: '✓';
            position: absolute;
            left: 0;
            top: 12px;
            width: 25px;
            height: 25px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }
        
        .badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .badge-success {
            background: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%);
            color: #1a5d3a;
        }
        
        .badge-error {
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
            color: #8b1e1e;
        }
        
        .badge-info {
            background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
            color: #1e4d8b;
        }
        
        .back-btn {
            display: inline-block;
            padding: 12px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 25px;
            margin: 20px 0;
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
            font-weight: bold;
        }
        
        .back-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
            color: white;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: white;
            font-size: 14px;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
        }
        
        @media (max-width: 768px) {
            .doc-header h1 {
                font-size: 24px;
            }
            
            .doc-section {
                padding: 20px 15px;
            }
            
            .section-title {
                font-size: 20px;
            }
            
            .param-table {
                font-size: 14px;
            }
            
            .code-block {
                font-size: 12px;
                padding: 15px;
            }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="doc-card">
        <div class="doc-header">
            <div class="doc-header-content">
                <h1>📚 API 开发文档</h1>
                <p style="margin-top: 10px; font-size: 16px;">小米运动刷步数工具 - Zepp API 版本</p>
                <span class="version">Version 2.0</span>
            </div>
        </div>
        
        <!-- 基本信息 -->
        <div class="doc-section">
            <div class="section-title">📋 基本信息</div>
            <table class="param-table">
                <tr>
                    <th width="150">项目</th>
                    <th>内容</th>
                </tr>
                <tr>
                    <td><span class="param-name">工具名称</span></td>
                    <td>小米运动刷步数工具（Zepp API 版本）</td>
                </tr>
                <tr>
                    <td><span class="param-name">版本号</span></td>
                    <td>V2.0</td>
                </tr>
                <tr>
                    <td><span class="param-name">作者</span></td>
                    <td>传康KK</td>
                </tr>
                <tr>
                    <td><span class="param-name">API地址</span></td>
                    <td><code><?php echo $url; ?></code></td>
                </tr>
                <tr>
                    <td><span class="param-name">请求方式</span></td>
                    <td><span class="badge badge-info">GET</span> <span class="badge badge-info">POST</span></td>
                </tr>
            </table>
        </div>
        
        <!-- 接口参数 -->
        <div class="doc-section">
            <div class="section-title">🔧 接口参数</div>
            <table class="param-table">
                <tr>
                    <th width="120">参数名</th>
                    <th width="100">必填</th>
                    <th>说明</th>
                </tr>
                <tr>
                    <td><span class="param-name">user</span></td>
                    <td><span class="badge badge-error">必填</span></td>
                    <td>账号（手机号或邮箱）</td>
                </tr>
                <tr>
                    <td><span class="param-name">pwd</span></td>
                    <td><span class="badge badge-error">必填</span></td>
                    <td>登录密码</td>
                </tr>
                <tr>
                    <td><span class="param-name">step</span></td>
                    <td><span class="badge badge-error">必填</span></td>
                    <td>需要修改的步数（整数）</td>
                </tr>
                <tr>
                    <td><span class="param-name">token</span></td>
                    <td><span class="badge badge-info">API调用时必填</span></td>
                    <td>API密钥（固定值：666，网页提交不需要）</td>
                </tr>
            </table>
        </div>
        
        <!-- 请求示例 -->
        <div class="doc-section">
            <div class="section-title">💻 请求示例</div>
            <p style="margin-bottom: 15px; color: #666;"><strong>GET 请求：</strong></p>
            <div class="code-block">
                <code><?php echo $url; ?>?user=13888888888&pwd=yourpassword&step=20000&token=666</code>
            </div>
            
            <p style="margin: 20px 0 15px 0; color: #666;"><strong>POST 请求（网页提交，无需 token）：</strong></p>
            <div class="code-block">
                <code>
POST <?php echo $url; ?><br>
Content-Type: application/x-www-form-urlencoded<br><br>
user=13888888888&pwd=yourpassword&step=20000
                </code>
            </div>
        </div>
        
        <!-- 返回结果 -->
        <div class="doc-section">
            <div class="section-title">📤 返回结果</div>
            <table class="param-table">
                <tr>
                    <th width="150">字段</th>
                    <th>说明</th>
                </tr>
                <tr>
                    <td><span class="param-name">time</span></td>
                    <td>提交时间</td>
                </tr>
                <tr>
                    <td><span class="param-name">user</span></td>
                    <td>脱敏后的账号</td>
                </tr>
                <tr>
                    <td><span class="param-name">step</span></td>
                    <td>修改的步数</td>
                </tr>
                <tr>
                    <td><span class="param-name">status</span></td>
                    <td>状态（success / failed）</td>
                </tr>
                <tr>
                    <td><span class="param-name">message</span></td>
                    <td>详细提示信息</td>
                </tr>
            </table>
            
            <p style="margin: 20px 0 15px 0; color: #666;"><strong>成功示例：</strong></p>
            <div class="code-block">
                <code>
{<br>
&nbsp;&nbsp;"time": "2025-01-01 12:00:00",<br>
&nbsp;&nbsp;"user": "138****8888",<br>
&nbsp;&nbsp;"step": 20000,<br>
&nbsp;&nbsp;"status": "success",<br>
&nbsp;&nbsp;"message": "修改步数（20000）"<br>
}
                </code>
            </div>
        </div>
        
        <!-- 功能特性 -->
        <div class="doc-section">
            <div class="section-title">✨ 功能特性</div>
            <ul class="feature-list">
                <li>使用最新的 Zepp API 接口（api-user.zepp.com）</li>
                <li>支持登录信息缓存（7天有效期）</li>
                <li>支持手机号和邮箱两种账号类型</li>
                <li>安全的文件名过滤和路径保护</li>
                <li>文件锁机制防止并发冲突</li>
            </ul>
        </div>
        
        <!-- 常见问题 -->
        <div class="doc-section">
            <div class="section-title">❓ 常见问题</div>
            <ul class="feature-list">
                <li>只支持小米运动手机号 + 密码登录方式</li>
                <li>小米运动APP登录成功后可绑定第三方进行数据同步（支付宝、微信等）</li>
                <li>只要显示提交成功，就一定提交成功了（结果由小米运动服务器返回）</li>
                <li>如果第三方未同步，可尝试解绑后重新绑定</li>
            </ul>
        </div>
        
        <!-- 使用须知 -->
        <div class="doc-section">
            <div class="section-title">⚠️ 使用须知</div>
            <ul class="feature-list">
                <li>本工具仅供个人学习、研究，不可商用！</li>
                <li>本工具不记录您的密码信息，但建议使用小米小号进行测试</li>
                <li>支持缓存机制，登录信息缓存7天，提高访问速度</li>
                <li>生命在于运动，可别忘了出门锻炼哦！</li>
            </ul>
        </div>
        
        <!-- 返回按钮 -->
        <div class="doc-section" style="text-align: center; border-bottom: none;">
            <a href="<?php echo $url; ?>" class="back-btn">🏠 返回首页</a>
        </div>
    </div>
    
    <div class="footer">
        <p>💡 生命在于运动，可别忘了出门锻炼哦！</p>
        <p style="margin-top: 5px; opacity: 0.8;">© 2025传康KK</p>
    </div>
</div>
</body>
</html>
    <?php
    exit;
}

// ==================== 主执行逻辑 ====================
// 处理 POST 请求（网页提交）
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 频率限制检查
    list($rateLimitOk, $rateLimitMsg) = checkRateLimit();
    if (!$rateLimitOk) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(["error" => $rateLimitMsg], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }
    
    $user = param('user');
    $pwd = param('pwd');
    $step = param('step');

    if (!$user || !$pwd || !$step) {
        echo json_encode([
            "error" => "参数不完整，必须提供 user, pwd, step"
        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }
    
    // 步数验证
    list($stepValid, $stepResult) = validateStep($step);
    if (!$stepValid) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(["error" => $stepResult], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }
    $step = $stepResult;

    $runner = new MiMotionRunner($user, $pwd);
    list($msg, $success) = $runner->loginAndPostStep($step);

    $output = [
        "time" => date("Y-m-d H:i:s"),
        "user" => desensitizeUserName($user),
        "step" => $step,
        "status" => $success ? "success" : "failed",
        "message" => $msg
    ];

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($output, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

// 处理 GET 请求（API 调用，需要 token）
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['token'])) {
    // 频率限制检查
    list($rateLimitOk, $rateLimitMsg) = checkRateLimit();
    if (!$rateLimitOk) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(["error" => $rateLimitMsg], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }
    
    if ($_GET['token'] !== $token) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            "error" => "Token 验证失败"
        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }

    $user = param('user');
    $pwd = param('pwd');
    $step = param('step');

    if (!$user || !$pwd || !$step) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            "error" => "参数不完整，必须提供 user, pwd, step"
        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }
    
    // 步数验证
    list($stepValid, $stepResult) = validateStep($step);
    if (!$stepValid) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(["error" => $stepResult], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }
    $step = $stepResult;

    $runner = new MiMotionRunner($user, $pwd);
    list($msg, $success) = $runner->loginAndPostStep($step);

    $output = [
        "time" => date("Y-m-d H:i:s"),
        "user" => desensitizeUserName($user),
        "step" => $step,
        "status" => $success ? "success" : "failed",
        "message" => $msg
    ];

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($output, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}
?>