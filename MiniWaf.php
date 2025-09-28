<?php
error_reporting(1);

class MiniWaf {
    private $config;
    private $requestId;
    private $logData;
    private $blocked = false;
    private $bannedIPs = array();
    private $config_json_path = '/MiniWafConfig.json';
    private $log_file = '/WafLog.txt';
    
    public function __construct() {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }

        $this->requestId = uniqid('req_', true);

        $jsonConfig = file_get_contents($this->config_json_path);
        $this->config = json_decode($jsonConfig, true);

        // 初始化 tokens (如果不存在)
        if (!isset($this->config['general']['tokens'])) {
            $this->config['general']['tokens'] = array();
        }

        $this->initializeLogData();

        // 随机清理过期token (分散清理，避免一次性大量操作)
        if (rand(1, 10) === 1) {
            $this->cleanupExpiredTokens();
        }

        $this->handleAuthRequests();
        $this->bannedIPs = isset($this->config['general']['banned_ips']) ? $this->config['general']['banned_ips'] : array(); // 加载封禁的ip数组

        if ($this->checkBannedIP()) {
            $this->addThreat("Banned IP", "IP address is in banned list: " . $this->getClientIP());
            $this->blockRequest("Access denied: Your IP address has been banned");
            $this->writeLog();
            $this->sendBlockedResponse();
            exit;
        }

        $this->logRequestPacket();
        $this->captureUploadedFilesContent();
        $this->run();

        if ($this->blocked) {
            $this->sendBlockedResponse();
        } else {
            register_shutdown_function(array($this, 'captureCompleteResponse')); // 对于ALLOWED的请求，注册shutdown函数来捕获完整响应
        }
    }


/*
    日志相关(不包含控制台对日志解析的内容)
*/
    // 初始化日志数据
    private function initializeLogData() {
        $this->logData = array(
            'request_id' => $this->requestId,
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $this->getClientIP(),
            'method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'UNKNOWN',
            'uri' => isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'UNKNOWN',
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'UNKNOWN',
            'get_params' => $_GET,
            'post_params' => $_POST,
            'cookie_params' => $_COOKIE,
            'files' => $_FILES,
            'headers' => function_exists('getallheaders') ? $this->getAllHeaders() : array(),
            'detected_threats' => array(),
            'action_taken' => 'ALLOWED',
            'upload_files_content' => array(),
            'response_code' => 200,
            'response_headers' => array(),
            'response_body'    => '',
        );
    }

    private function captureUploadedFilesContent() {
        if (!empty($_FILES)) {
            $maxLength = (int)$this->config['general']['upload_content_max_length'];
            
            foreach ($_FILES as $fileKey => $fileInfo) {
                if ($fileInfo['error'] === UPLOAD_ERR_OK && is_uploaded_file($fileInfo['tmp_name'])) {
                    $content = @file_get_contents($fileInfo['tmp_name'], false, null, 0, $maxLength + 100);
                    
                    if ($content !== false) {
                        $contentLength = strlen($content);
                        $isTruncated = ($contentLength > $maxLength);

                        $preview = substr($content, 0, $maxLength); // 截取指定长度
                        
                        if ($isTruncated) {
                            $preview .= "...[TRUNCATED " . ($contentLength - $maxLength) . " bytes]";
                        }
                        
                        // 对二进制内容进行安全编码
                        if (!preg_match('/^[\x20-\x7E\n\r\t]*$/', $preview)) {
                            $preview = bin2hex($preview);
                            if ($isTruncated) {
                                $preview = "HEX: " . $preview . "...[TRUNCATED]";
                            } else {
                                $preview = "HEX: " . $preview;
                            }
                        }
                        
                        $this->logData['upload_files_content'][] = array(
                            'name' => $fileInfo['name'],
                            'type' => $fileInfo['type'],
                            'size' => $fileInfo['size'],
                            'content_length' => $contentLength,
                            'content_preview' => $preview,
                            'is_truncated' => $isTruncated
                        );
                    }
                }
            }
        }
    }

    // 获取所有头部信息，用于日志记录
    private function getAllHeaders() {
        if (function_exists('getallheaders')) {
            return getallheaders();
        }
        
        $headers = array();
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
                $headers[$name] = $value;
            }
        }
        return $headers;
    }

    // 获取完整的返回包
    public function captureCompleteResponse() {
        if (function_exists('ob_get_contents') && ob_get_length() > 0) {
            $this->logData['response_body'] = ob_get_contents();
        }
        $this->logData['response_headers'] = headers_list();
        $this->writeLog();
    }

    // 日志中记载攻击方式的内容
    private function addThreat($type, $details) {
        $this->logData['detected_threats'][] = array(
            'type' => $type,
            'details' => $details,
            'timestamp' => microtime(true)
        );
    }
    
    // 写入日志的方法
    private function writeLog() {
        $maxRequestLength = (int)$this->config['general']['request_body_log_max_length'];
        $maxResponseLength = (int)$this->config['general']['response_body_log_max_length'];
        
        $log = "========== REQUEST #{$this->requestId} ==========\n";
        $log .= "[Time: " . $this->logData['timestamp'] . "]\n";
        $log .= "[SourceIp: " . $this->logData['ip'] . "]\n";
        $log .= "\n";
        $log .= "=== REQUEST ===\n{$this->logData['method']} {$this->logData['uri']} HTTP/1.1\n";

        $headers = isset($this->logData['headers']) ? $this->logData['headers'] : array();
        $host = isset($headers['Host']) ? $headers['Host'] : (isset($headers['host']) ? $headers['host'] : (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : null)));
        if ($host) {
            $log .= "Host: {$host}\n";
        }

        $seen = array();
        foreach ($headers as $name => $value) {
            $key = strtolower($name);
            if ($key !== 'host' && !isset($seen[$key])) {
                $log .= "{$name}: {$value}\n";
                $seen[$key] = true;
            }
        }
        $log .= "\n";

        // 限制请求体长度
        if (!empty($this->logData['post_params'])) {
            $requestBody = http_build_query($this->logData['post_params']);
            if (strlen($requestBody) > $maxRequestLength) {
                $requestBody = substr($requestBody, 0, $maxRequestLength) . "...[TRUNCATED " . (strlen($requestBody) - $maxRequestLength) . " chars]";
            }
            $log .= $requestBody . "\n";
        }
        
        // 输出上传的文件体
        if (!empty($this->logData['upload_files_content'])) {
            $log .= "\n=== UPLOADED FILES CONTENT ===\n";
            foreach ($this->logData['upload_files_content'] as $fileInfo) {
                $log .= "FileInfo: " . $fileInfo['name'] . " (" . $fileInfo['type'] . ", " . $fileInfo['size'] . " bytes)\n";
                $log .= "Content preview (first " . strlen($fileInfo['content_preview']) . " chars):\n";
                $log .= $fileInfo['content_preview'] . "\n";
            }
        }

        $log .= "\n";
        $log .= "=== RESPONSE ===\nHTTP/1.1 {$this->logData['response_code']}\nAction: {$this->logData['action_taken']}\n";

        // 输出响应头
        if (!empty($this->logData['response_headers'])) {
            foreach ($this->logData['response_headers'] as $header) {
                $log .= $header . "\n";
            }
        }

        $log .= "\n";

        // 限制响应体长度
        if (!empty($this->logData['response_body'])) {
            $responseBody = $this->logData['response_body'];
            if (strlen($responseBody) > $maxResponseLength) {
                $responseBody = substr($responseBody, 0, $maxResponseLength) . "...[TRUNCATED " . (strlen($responseBody) - $maxResponseLength) . " chars]";
            }
            $log .= $responseBody . "\n";
        }

        if (!empty($this->logData['detected_threats'])) {
            $log .= "\n=== Threats Detected ===\n";
            foreach ($this->logData['detected_threats'] as $t) {
                $log .= "- {$t['type']}: {$t['details']}\n";
            }
        }

        $log .= "========== END REQUEST #{$this->requestId} ==========\n\n";

        @file_put_contents($this->log_file, $log, FILE_APPEND | LOCK_EX);
    }

/*
    操作凭证-token相关
*/
    // 生成随机字节，兼容php5及以上以及多个备选方案
    private function random_bytes($length) {
        $bytes = '';
        if (function_exists('random_bytes')) {return random_bytes($length);} 
        elseif (function_exists('openssl_random_pseudo_bytes')) {
            $bytes = openssl_random_pseudo_bytes($length, $strong);
            if ($strong === true) {return $bytes;}
        } elseif (function_exists('mcrypt_create_iv')) {
            $bytes = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
            if ($bytes !== false && strlen($bytes) === $length) {return $bytes;}
        }
        // 备用方案：使用 /dev/urandom (Unix) 或混合熵源
        if (is_readable('/dev/urandom') && ($fh = @fopen('/dev/urandom', 'rb'))) {
            $bytes = fread($fh, $length);
            fclose($fh);
            if (strlen($bytes) === $length) {return $bytes;}
        }
        // 最后备用：使用混合熵源（安全性较低但兼容性最好）
        $bytes = '';
        for ($i = 0; $i < $length; $i++) {$bytes .= chr(mt_rand(0, 255));}
        return $bytes;
    }
    
    // 生成十六进制编码
    private function bin2hex_compatible($data) {
        if (function_exists('bin2hex')) {
            return bin2hex($data);
        }
        
        $hex = '';
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $hex .= sprintf('%02x', ord($data[$i]));
        }
        return $hex;
    }
    
    // 生成token
    private function generateSecureToken($length = 32) {
        $bytes = $this->random_bytes($length);
        return $this->bin2hex_compatible($bytes);
    }

    // 获取token
    private function getTokenData() {
        return isset($this->config['general']['tokens']) ? $this->config['general']['tokens'] : array();
    }

    // 把token写入json
    private function saveToken($token, $data) {
        $this->config['general']['tokens'][$token] = $data;
        $this->saveConfig();
    }

    // 检查token
    private function validateToken($token) {
        $tokens = $this->getTokenData();
        if (!isset($tokens[$token])) {
            return false;
        }

        $data = $tokens[$token];

        // 检查token是否过期
        if (time() > $data['expire_time']) {
            $this->destroyToken($token);
            return false;
        }

        // 检查IP地址是否匹配
        $currentIP = $this->getClientIP();
        if (isset($data['ip']) && $data['ip'] !== $currentIP) {
            return false;
        }

        return true;
    }

    // 销毁token
    private function destroyToken($token) {
        unset($this->config['general']['tokens'][$token]);
        $this->saveConfig();
    }

    // 清理过期token
    private function cleanupExpiredTokens() {
        $changed = false;
        foreach ($this->config['general']['tokens'] as $token => $data) {
            if (time() > $data['expire_time']) {
                unset($this->config['general']['tokens'][$token]);
                $changed = true;
            }
        }
        if ($changed) {
            $this->saveConfig();
        }
    }

    // 清理指定ip的token，避免同一个ip生成多个token(如果重新登录就覆盖原先的)
    private function cleanupTokensByIP($ip) {
        $changed = false;
        $tokens = $this->getTokenData();
        
        foreach ($tokens as $token => $data) {
            if (isset($data['ip']) && $data['ip'] === $ip) {
                unset($this->config['general']['tokens'][$token]);
                $changed = true;
            }
        }
        
        if ($changed) {
            $this->saveConfig();
        }
        return $changed;
    }

    // 仅用于token的写入
    private function saveConfig() {
        file_put_contents($this->config_json_path, json_encode($this->config, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }


/*
    登录相关
*/
    private function handleAuthRequests() {
        $logoutParam = $this->config['general']['logout_param'];
        $loginParam = $this->config['general']['login_param'];
        $dashboardParam = $this->config['general']['dashboard_param'];
        $tokenParam = $this->config['general']['token_param'];
        $tokenDuration = $this->config['general']['token_duration'];

        // 处理登出
        if (isset($_GET[$logoutParam]) && isset($_GET[$tokenParam])) {
            $token = $_GET[$tokenParam];
            $this->destroyToken($token);
            $cleanUrl = strtok($_SERVER['REQUEST_URI'], '?');
            header('Location: ' . $cleanUrl);
            exit;
        }

        // 处理登录(post)
        if (isset($_POST[$loginParam])) {
            $password = $_POST[$loginParam];
            if ($password === $this->config['general']['login_password']) {
                $clientIP = $this->getClientIP(); //获取客户端ip(一个ip同时只有一个token)
                $this->cleanupTokensByIP($clientIP); // 先清理该IP的所有现有token
                $token = $this->generateSecureToken(32); //生成token
                $this->saveToken($token, [
                    'authenticated' => true,
                    'login_time' => time(),
                    'expire_time' => time() + $tokenDuration,
                    'ip' => $clientIP,
                ]);
                $redirectUrl = '?' . $dashboardParam . '=1&' . $tokenParam . '=' . urlencode($token);
                header('Location: ' . $redirectUrl);
                exit;
            } else {
                $this->showLoginForm('密码错误，请重试！');
                exit;
            }
        }

        // 登录成功后显示后台
        if (isset($_GET[$dashboardParam])) {
            $token = isset($_GET[$tokenParam]) ? $_GET[$tokenParam] : null;
            
            // 如果没有token或者token无效，显示登录表单
            if (!$token || !$this->validateToken($token)) {
                $this->showLoginForm(null, true);
                exit;
            }
            $this->showDashboard();
            exit;
        }

        // 显示登录页
        if (isset($_GET[$loginParam])) {
            $this->showLoginForm(null, true);
            exit;
        }
    }

    private function showLoginForm($errorMessage = '') {
        $loginParam = $this->config['general']['login_param'];
        $dashboardParam = $this->config['general']['dashboard_param'];
        $tokenParam = $this->config['general']['token_param'];

        $currentUrl = '?' . $dashboardParam . '=1';
        
        $escapedLoginParam = htmlspecialchars($loginParam, ENT_QUOTES);
        $escapedCurrentUrl = htmlspecialchars($currentUrl, ENT_QUOTES);
        ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>MiniWaf Login</title>
        <meta charset="UTF-8">
    </head>
    <body>
        <script>
            <?php if ($errorMessage): ?>
                alert('<?php echo addslashes($errorMessage); ?>');
            <?php endif; ?>

            function doLogin() {
                var password = prompt('请输入密码访问 MiniWaf 控制台：');
                if (password === null) return;
                
                if (password.trim() === '') {
                    alert('密码不能为空！');
                    doLogin();
                    return;
                }

                var form = document.createElement('form');
                form.method = 'POST';
                form.action = '<?php echo $escapedCurrentUrl; ?>';
                
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = '<?php echo $escapedLoginParam; ?>';
                input.value = password;
                
                form.appendChild(input);
                document.body.appendChild(form);
                form.submit();
            }

            doLogin();
        </script>
    </body>
    </html>
    <?php
    }
    

/*
    控制台相关
*/
    // 控制台操作的逻辑
    private function handlePostRequests($activePage, $token) {
        $tokenParam = $this->config['general']['token_param'];
        $postToken = isset($_POST[$tokenParam]) ? $_POST[$tokenParam] : '';
        
        // 使用$postToken进行验证
        if (!empty($_POST) && !$this->validateToken($postToken)) {
            $_SESSION['dashboard_msg'] = "Token 无效或已过期";
            $_SESSION['dashboard_type'] = 'error';
            
            $redirectUrl = '?' . $this->config['general']['dashboard_param'] . '=1&' . $tokenParam . '=' . urlencode($token);
            header('Location: ' . $redirectUrl);
            exit;
        }
        
        // 处理IP封禁
        if (isset($_POST['ban_ip']) && !empty($_POST['ban_ip'])) {
            $this->handleBanIpRequest($token);
            return;
        }
        // 处理移除封禁IP
        if (isset($_POST['remove_ip']) && !empty($_POST['remove_ip'])) {
            $this->handleRemoveIpRequest($token);
            return;
        }

        // 处理防护规则开关更新
        if (isset($_POST['update_rule_status'])) {
            $this->handleUpdateRuleStatus($token);
            return;
        }
    }

    // 进入后台
    private function showDashboard() {
        $tokenParam = $this->config['general']['token_param'];
        $token = isset($_GET[$tokenParam]) ? $_GET[$tokenParam] : '';
        
        if (!$token || !$this->validateToken($token)) {
            $this->showLoginForm('Token无效或已过期');
            exit;
        }

        $activePage = $this->determineActivePage();
        $this->handlePostRequests($activePage, $token);

        $viewData = $this->prepareViewData($activePage, $token, $tokenParam);
        $this->renderDashboard($activePage, $viewData, $token);
    }

    // 控制台包含的页面
    private function determineActivePage() {
        $validPages = array('home', 'ip', 'logs', 'settings');
        $activePage = isset($_GET['page']) ? $_GET['page'] : 'home';
        return in_array($activePage, $validPages) ? $activePage : 'home';
    }

    // IP管理页面：封禁ip操作
    private function handleBanIpRequest($token) {
        $ban_ip = trim($_POST['ban_ip']);
        $message = '';
        $type = 'error';

        if (filter_var($ban_ip, FILTER_VALIDATE_IP) || preg_match($this->config['patterns']['ip'][0], $ban_ip)) {
            // 直接从配置中获取封禁IP列表
            $bannedIPs = isset($this->config['general']['banned_ips']) ? 
                        $this->config['general']['banned_ips'] : array();
            
            $exists = in_array($ban_ip, $bannedIPs);

            if (!$exists) {
                // 添加到封禁IP数组
                $this->config['general']['banned_ips'][] = $ban_ip;
                $this->saveConfig();
                
                $message = "IP {$ban_ip} 封禁成功";
                $type = 'success';
            } else {
                $message = "IP {$ban_ip} 已存在";
            }
        } else {
            $message = "IP格式无效";
        }

        $_SESSION['dashboard_msg'] = $message;
        $_SESSION['dashboard_type'] = $type;
        
        $redirectUrl = '?' . $this->config['general']['dashboard_param'] . '=1&page=ip&' . $this->config['general']['token_param'] . '=' . urlencode($token);
        header('Location: ' . $redirectUrl);
        exit;
    }

    // IP管理页面：移除封禁的ip操作
    private function handleRemoveIpRequest($token) {
        $remove_ip = trim($_POST['remove_ip']);
        
        // 直接从配置中获取封禁IP列表
        if (isset($this->config['general']['banned_ips'])) {
            $bannedIPs = $this->config['general']['banned_ips'];
            $new_ips = array();
            
            foreach ($bannedIPs as $ip) {
                $ip = trim($ip);
                if (!empty($ip) && $ip !== $remove_ip) {
                    $new_ips[] = $ip;
                }
            }
            
            // 更新配置
            $this->config['general']['banned_ips'] = $new_ips;
            $this->saveConfig();
            
            $_SESSION['dashboard_msg'] = "IP {$remove_ip} 已移除封禁";
            $_SESSION['dashboard_type'] = 'success';
        }

        $redirectUrl = '?' . $this->config['general']['dashboard_param'] . '=1&page=ip&' . $this->config['general']['token_param'] . '=' . urlencode($token);
        header('Location: ' . $redirectUrl);
        exit;
    }

    // 解析txt文件的日志数据
    private function parseLogEntries() {
        $logs = file_exists($this->log_file) ? file_get_contents($this->log_file) : '';
        $entries = array();

        if (!empty($logs)) {
            // 使用正则匹配完整的日志块，更可靠
            $pattern = '/========== REQUEST #([^\s=]+) ==========(.*?)========== END REQUEST #\1 ==========([\r\n]+)/s';
            preg_match_all($pattern, $logs, $matches, PREG_SET_ORDER);

            foreach ($matches as $match) {
                $id = $match[1];
                $content = $match[2];

                preg_match('/\[Time: ([^\]]+)\]/', $content, $tm);
                preg_match('/\[SourceIp: ([^\]]+)\]/', $content, $ipm);
                preg_match('/=== REQUEST ===\n([A-Z]+) ([^\s]+)/', $content, $reqm);
                preg_match('/Action: ([^\n]+)/', $content, $actm);

                $entry = array(
                    'id' => $id,
                    'time' => isset($tm[1]) ? $tm[1] : '未知',
                    'ip' => isset($ipm[1]) ? $ipm[1] : '未知',
                    'method' => isset($reqm[1]) ? $reqm[1] : 'GET',
                    'uri' => isset($reqm[2]) ? $reqm[2] : '/',
                    'action' => isset($actm[1]) ? $actm[1] : 'ALLOWED',
                    'log' => "========== REQUEST #{$id} =========={$content}========== END REQUEST #{$id} =========="
                );

                $entries[] = $entry;
            }
        }

        return $entries;
    }

    // 筛选日志逻辑
    private function filterLogEntries($entries, $filter_query) {
        $filtered_entries = array();
        $query_lower = strtolower($filter_query);

        foreach ($entries as $entry) {
            $match = false;
            $entry_lower = strtolower($entry['log']);

            // 检查是否匹配IP地址
            if (strpos($entry['ip'], $filter_query) !== false) {
                $match = true;
            }
            // 检查是否匹配操作类型 (BLOCKED/ALLOWED)
            else if (strpos(strtolower($entry['action']), $query_lower) !== false) {
                $match = true;
            }
            // 检查是否匹配攻击方式 (从Threat字段中查找)
            else if (preg_match_all('/Threat: ([^\n]+)/i', $entry['log'], $matches)) {
                foreach ($matches[1] as $threat) {
                    if (stripos($threat, $filter_query) !== false) {
                        $match = true;
                        break;
                    }
                }
            }
            // 检查是否匹配请求方法
            else if (strpos(strtolower($entry['method']), $query_lower) !== false) {
                $match = true;
            }
            // 检查是否匹配URI
            else if (strpos(strtolower($entry['uri']), $query_lower) !== false) {
                $match = true;
            }
            // 通用搜索：在完整日志中搜索关键词
            else if (strpos($entry_lower, $query_lower) !== false) {
                $match = true;
            }

            if ($match) {
                $filtered_entries[] = $entry;
            }
        }

        return $filtered_entries;
    }

    // 响应前端首页防护规则的点击，配置文件中的防护规则修改
    private function handleUpdateRuleStatus($token) {
        $ruleKey = isset($_POST['rule_key']) ? $_POST['rule_key'] : '';
        $newStatus = isset($_POST['new_status']) ? $_POST['new_status'] : '';
        
        $validRules = array(
            'check_sql', 'check_rce', 'check_lfi', 'check_deserialization',
            'check_xss', 'check_xxe', 'check_ssrf', 'check_flag_file', 'check_upload'
        );
        
        if (in_array($ruleKey, $validRules) && ($newStatus === 'on' || $newStatus === 'off')) {
            $this->config['general'][$ruleKey] = ($newStatus === 'on');
            $this->saveConfig();
            
            $_SESSION['dashboard_msg'] = "防护规则状态已更新";
            $_SESSION['dashboard_type'] = 'success';
        } else {
            $_SESSION['dashboard_msg'] = "无效的请求参数";
            $_SESSION['dashboard_type'] = 'error';
        }
        
        $redirectUrl = '?' . $this->config['general']['dashboard_param'] . '=1&page=home&' . $this->config['general']['token_param'] . '=' . urlencode($token);
        header('Location: ' . $redirectUrl);
        exit;
    }
    

/*
    waf逻辑相关
*/
    private function run() {
        // 统一检查所有输入源
        $loginParam = $this->config['general']['login_param'];
        $sources = array(
            'GET' => array_diff_key($_GET, array($loginParam => '')),
            'POST' => array_diff_key($_POST, array($loginParam => '')),
            'COOKIE' => $this->getFilteredCookies()
        );
        
        foreach ($sources as $type => $data) {
            foreach ($data as $key => $value) {
                if (is_string($value) || is_numeric($value)) {
                    $this->checkInput($value, $key, $type);
                    if ($this->blocked) return;
                } elseif (is_array($value)) {
                    $this->checkArrayInput($value, $key, $type);
                    if ($this->blocked) return;
                }
            }
        }
        
        if ($this->config['general']['check_upload'] && !empty($_FILES)) {
            $this->checkUpload();
            if ($this->blocked) return;
        }
        
        $this->checkHeaders();
    }

    // 处理数组参数的递归检查
    private function checkArrayInput($array, $baseKey, $type) {
        foreach ($array as $key => $value) {
            $fullKey = $baseKey . '[' . $key . ']';
            if (is_array($value)) {
                $this->checkArrayInput($value, $fullKey, $type);
                if ($this->blocked) return;
            } else {
                $this->checkInput($value, $fullKey, $type);
                if ($this->blocked) return;
            }
        }
    }

    private function checkInput($input, $key, $type) {
        $decoded = $this->deepUrlDecode($input);
        
        $checks = array( // 常规检查处理
            'xxe' => array('check_xxe', 'XXE Attack'),
            'sql' => array('check_sql', 'SQL Injection'),
            'rce' => array('check_rce', 'RCE'),
            'deserialization' => array('check_deserialization', 'Deserialization'),
            'xss' => array('check_xss', 'XSS Attack'),
            'flag_file' => array('check_flag_file', 'Flag Probing'),
        );
        
        foreach ($checks as $patternType => $checkInfo) {
            list($configKey, $threatName) = $checkInfo;
            if ($this->config['general'][$configKey] && $this->matchPatterns($decoded, $this->config['patterns'][$patternType])) {
                $this->addThreat($threatName, "$type parameter '$key': $decoded");
                $this->blockRequest("$threatName detected in $type parameter '$key': $decoded");
                return;
            }
        }
        
        // LFI 特殊处理（不检查 HEADER）
        if ($type !== 'HEADER' && $this->config['general']['check_lfi'] && 
            $this->matchPatterns($decoded, $this->config['patterns']['lfi']) && 
            !$this->matchPatterns($decoded, $this->config['patterns']['lfi_whitelist'])) {
            $this->addThreat("LFI/LFR", "$type parameter '$key': $decoded");
            $this->blockRequest("LFI/LFR detected in $type parameter '$key': $decoded");
            return;
        }
        
        // SSRF 特殊处理
        if ($this->config['general']['check_ssrf'] && $this->checkSSRF($decoded, $key, $type)) {
            return;
        }
    }

    private function checkSSRF($input, $key, $type) {
        // 首先检查是否是URL格式
        if (!preg_match('/^[a-zA-Z][a-zA-Z0-9+\-.]*:/', $input)) {
            return false;
        }
        
        // IP混淆检测
        if ($this->matchPatterns($input, $this->config['patterns']['ssrf']['ip_obfuscation_patterns'])) {
            $this->addThreat("SSRF (IP Obfuscation)", "$type parameter '$key': $input");
            $this->blockRequest("SSRF IP obfuscation detected in $type parameter '$key': $input");
            return true;
        }
        
        // 解析URL
        $urlParts = parse_url($input);
        if (!$urlParts || !isset($urlParts['scheme'])) {
            return false;
        }
        
        $protocol = strtolower($urlParts['scheme']);
        $host = isset($urlParts['host']) ? $urlParts['host'] : '';
        
        // 检查协议黑名单
        $blacklist = isset($this->config['patterns']['ssrf']['protocol_blacklist']) ? 
                    $this->config['patterns']['ssrf']['protocol_blacklist'] : array();
        $whitelist = isset($this->config['patterns']['ssrf']['protocol_whitelist']) ? 
                    $this->config['patterns']['ssrf']['protocol_whitelist'] : array();
        
        if (in_array($protocol, $blacklist)) {
            $this->addThreat("SSRF (Blacklisted Protocol)", "$type parameter '$key': $input");
            $this->blockRequest("SSRF blacklisted protocol detected in $type parameter '$key': $input");
            return true;
        }
        
        // 检查协议白名单（如果配置了白名单）
        if (!empty($whitelist) && !in_array($protocol, $whitelist)) {
            $this->addThreat("SSRF (Non-Whitelisted Protocol)", "$type parameter '$key': $input");
            $this->blockRequest("SSRF non-whitelisted protocol detected in $type parameter '$key': $input");
            return true;
        }
        
        // 检查内网域名黑名单
        if ($host) {
            $bannedDomains = isset($this->config['patterns']['ssrf']['banned_visit_domain_blacklist']) ? 
                            $this->config['patterns']['ssrf']['banned_visit_domain_blacklist'] : array();
            foreach ($bannedDomains as $bannedDomain) {
                $pattern = str_replace('*', '.*', $bannedDomain);
                if (preg_match('/' . $pattern . '$/i', $host)) {
                    $this->addThreat("SSRF (Banned Domain)", "$type parameter '$key': $input");
                    $this->blockRequest("SSRF banned domain detected in $type parameter '$key': $input");
                    return true;
                }
            }
        }
        
        return false;
    }

    private function getFilteredCookies() {
        $filtered = array();
        $skipCookies = $this->config['general']['skip_cookies'];
        
        foreach ($_COOKIE as $key => $value) {
            if (in_array($key, $skipCookies)) {
                continue;
            }
            $filtered[$key] = $value;
        }
        return $filtered;
    }

    private function checkHeaders() {
        $headers = $this->getAllHeaders();
        
        $safeHeaders = $this->config['headers']['safe_headers'];
        
        foreach ($headers as $name => $value) {
            // 跳过Cookie Header，避免重复检查
            if (strtolower($name) === 'cookie') {
                continue;
            }

            if (in_array($name, $safeHeaders)) {
                $this->checkSafeHeader($value, $name);
            } else {
                $this->checkInput($value, $name, 'HEADER');
            }
            if ($this->blocked) return;
        }
    }

    private function checkSafeHeader($input, $name) {
        $decoded = $this->deepUrlDecode($input);
        
        $dangerPatterns = $this->config['headers']['danger_patterns'];
        
        if ($this->matchPatterns($decoded, $dangerPatterns)) {
            $this->addThreat("Dangerous Header", "Safe header '$name': $decoded");
            $this->blockRequest("Dangerous pattern detected in safe header '$name': $decoded");
        }
    }

    private function checkUpload() {
        foreach ($_FILES as $file) {
            if (isset($file['error']) && $file['error'] == 0) {
                $filename = isset($file['name']) ? $file['name'] : '';
                
                // 检查扩展名
                $blackExt = isset($this->config['upload']['black_ext']) ? 
                           $this->config['upload']['black_ext'] : '';
                $whitelist = isset($this->config['upload']['whitelist']) ? 
                            $this->config['upload']['whitelist'] : '';
                
                if ($this->matchPatterns($filename, array($blackExt)) ||
                    !$this->matchPatterns($filename, array($whitelist))) {
                    $this->addThreat("Invalid File Type", "Uploaded file: $filename");
                    $this->blockRequest("Invalid file type uploaded: " . $filename);
                    return;
                }
                
                // 检查文件内容
                if (isset($file['tmp_name']) && is_readable($file['tmp_name'])) {
                    $content = file_get_contents($file['tmp_name']);
                    if ($content !== false) {
                        $contentCheck = isset($this->config['upload']['content_check']) ? 
                                      $this->config['upload']['content_check'] : array();
                        if ($this->matchPatterns($content, $contentCheck)) {
                            $this->addThreat("PHP Code in File", "Uploaded file: $filename");
                            $this->blockRequest("PHP code detected in uploaded file: " . $filename);
                            return;
                        }
                    }
                }
            }
        }
    }

    private function matchPatterns($input, $patterns) {
        if (!is_string($input)) return false;
        
        if (!is_array($patterns)) {
            $patterns = array($patterns);
        }
        
        foreach ($patterns as $pattern) {
            if (@preg_match($pattern, $input)) {
                return true;
            }
        }
        return false;
    }

    private function checkBannedIP() {
        $clientIP = $this->getClientIP();
        
        $bannedIPs = isset($this->config['general']['banned_ips']) ? $this->config['general']['banned_ips'] : array();
        
        foreach ($bannedIPs as $bannedIP) {
            $bannedIP = trim($bannedIP);
            if (empty($bannedIP) || strpos($bannedIP, '#') === 0) {
                continue;
            }
            
            if (strpos($bannedIP, '/') !== false) {
                $parts = explode('/', $bannedIP, 2);
                $subnet = $parts[0];
                $mask = isset($parts[1]) ? $parts[1] : '';
                if ($this->ipInRange($clientIP, $subnet, $mask)) {
                    return true;
                }
            } else if ($clientIP === $bannedIP) {
                return true;
            }
        }
        
        return false;
    }
    
    private function deepUrlDecode($input) {
        if (!is_string($input)) return $input;
        
        $maxDepth =$this->config['general']['max_decode_depth'];
        $decoded = $input;
        
        for ($i = 0; $i < $maxDepth; $i++) {
            $temp = urldecode($decoded);
            if ($temp === $decoded) break;
            $decoded = $temp;
        }
        
        return $decoded;
    }
    
    private function blockRequest($reason) {
        $this->blocked = true;
        $this->logData['action_taken'] = 'BLOCKED';
        $this->logData['response_code'] = 403;
    }

    // 统一处理被阻止请求的响应
    private function sendBlockedResponse() {
        header('HTTP/1.1 403 Forbidden');
        header('Content-Type: text/plain');
        $this->writeLog();
        die($this->config['general']['blockRequestText']);
        exit;
    }


/*
    通用方法：获取客户端ip，获取日志里的数据
*/
    private function getClientIP() {
        // 优先使用 X-Forwarded-For
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($ips[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
        
        // 使用 X-Real-IP
        if (!empty($_SERVER['HTTP_X_REAL_IP']) && filter_var($_SERVER['HTTP_X_REAL_IP'], FILTER_VALIDATE_IP)) {
            return $_SERVER['HTTP_X_REAL_IP'];
        }
        
        // 使用 REMOTE_ADDR
        if (!empty($_SERVER['REMOTE_ADDR']) && filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP)) {
            return $_SERVER['REMOTE_ADDR'];
        }
        
        return 'unknown';
    }

    // 获取攻击最多的方式
    private function getTopAttackMethod($entries) {
        $attackCounts = array();
        
        foreach ($entries as $entry) {
            if (isset($entry['log']) && preg_match_all('/- ([^:]+): ([^\n]+)/', $entry['log'], $matches)) {
                foreach ($matches[1] as $index => $threat) {
                    $threat = trim($threat);
                    if (!isset($attackCounts[$threat])) {
                        $attackCounts[$threat] = 0;
                    }
                    $attackCounts[$threat]++;
                }
            }
        }
        
        if (empty($attackCounts)) {
            return "暂无数据";
        }
        
        arsort($attackCounts);
        $topMethod = key($attackCounts);
        $count = current($attackCounts);
        
        return $topMethod . " (" . $count . "次)";
    }

    // 获取被拦截的请求总数
    private function getTotalBlockedRequests($entries) {
        $blockedCount = 0;
        
        foreach ($entries as $entry) {
            if (isset($entry['log']) && strpos($entry['log'], 'Action: BLOCKED') !== false) {
                $blockedCount++;
            }
        }
        
        return $blockedCount;
    }
    
    // 获取访问最多的IP
    private function getTopAttackIP($entries) {
        $ipCounts = array();
        
        foreach ($entries as $entry) {
            $ip = isset($entry['ip']) ? $entry['ip'] : 'unknown';
            if (!isset($ipCounts[$ip])) {
                $ipCounts[$ip] = 0;
            }
            $ipCounts[$ip]++;
        }
        
        if (empty($ipCounts)) {
            return "暂无数据";
        }
        
        arsort($ipCounts);
        $topIP = key($ipCounts);
        $count = current($ipCounts);
        
        return $topIP . " (" . $count . "次)";
    }

    private function logRequestPacket() {
        $this->logData['request_time'] = isset($_SERVER['REQUEST_TIME']) ? $_SERVER['REQUEST_TIME'] : time();
        $this->logData['query_string'] = isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '';
        $this->logData['http_referer'] = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
        $this->logData['https'] = isset($_SERVER['HTTPS']) ? 'Yes' : 'No';
    }

    private function prepareViewData($activePage, $token, $tokenParam) {
        $data = array();

        // 获取所有必要数据
        list($data['msg'], $data['msg_type']) = $this->fetchAndClearMessage();
        
        $logData = $this->prepareLogData($activePage);
        $data = array_merge($data, $logData);
        
        $data['banned_ips'] = $this->getBannedIps();
        $data['active_ips_count'] = count($data['banned_ips']);
        
        $data['base_url'] = '?' . $this->config['general']['dashboard_param'] . '=1&' . $tokenParam . '=' . urlencode($token);
        
        $data['active_page'] = $activePage;
        
        // 首页统计数据
        $data['total_blocked'] = $this->getTotalBlockedRequests($data['entries']);
        $data['top_attack_method'] = $this->getTopAttackMethod($data['entries']);
        $data['top_attack_ip'] = $this->getTopAttackIP($data['entries']);

        $data['dashboard_param'] = $this->config['general']['dashboard_param'];
        $data['logout_param'] = $this->config['general']['logout_param'];
        $data['token_param'] = $tokenParam;

        return $data;
    }

    // 日志管理页面：日志数据的排版
    private function prepareLogData($activePage) {
        $logData = array();

        // 分页设置
        $logPage = isset($_GET['log_page']) ? max(1, (int)$_GET['log_page']) : 1;
        $per_page = 10;
        $logData['log_page'] = $logPage;
        $logData['per_page'] = $per_page;

        // 读取并解析日志
        $entries = $this->parseLogEntries();

        // 应用智能筛选条件
        $filter_query = trim(isset($_GET['filter_query']) ? $_GET['filter_query'] : '');
        if (!empty($filter_query)) {
            $entries = $this->filterLogEntries($entries, $filter_query);
        }

        // 反转数组，使最新日志在前
        $entries = array_reverse($entries);

        // 计算总数和总页数
        $total = count($entries);
        $total_pages = ceil($total / $per_page);
        $offset = ($logPage - 1) * $per_page;
        $paged_entries = array_slice($entries, $offset, $per_page);

        $logData['entries'] = $entries;
        $logData['paged_entries'] = $paged_entries;
        $logData['total_entries'] = $total;
        $logData['total_pages'] = $total_pages;
        $logData['filter_query'] = $filter_query;

        return $logData;
    }


    // 弹窗消息函数以及包含的参数
    private function fetchAndClearMessage() {
        $msg = $type = '';
        if (isset($_SESSION['dashboard_msg'])) {
            $msg = $_SESSION['dashboard_msg'];
            $type = isset($_SESSION['dashboard_type']) ? $_SESSION['dashboard_type'] : 'info';
            unset($_SESSION['dashboard_msg'], $_SESSION['dashboard_type']);
        }
        return array($msg, $type);
    }

    private function getBannedIps() {
        return isset($this->config['general']['banned_ips']) ? $this->config['general']['banned_ips'] : array();
    }

    private function renderDashboard($activePage, $viewData, $token) {        
        // 查看ViewData
        // echo '<script>';
        // echo 'console.log("ViewData 结构:", ' . json_encode($viewData) . ');';
        // echo '</script>';

        extract($viewData);
        $dashboardParam = $viewData['dashboard_param'];
        $tokenParam = $viewData['token_param'];
        $logoutParam = $viewData['logout_param'];

        // 预先计算每个链接的 active 类
        $homeClass    = $activePage === 'home'    ? 'active' : '';
        $ipClass      = $activePage === 'ip'      ? 'active' : '';
        $logsClass    = $activePage === 'logs'    ? 'active' : '';
        $settingsClass = $activePage === 'settings' ? 'active' : '';
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>MiniWaf Dashboard</title>
            <meta charset="UTF-8">
            <style>
                :root {
                    --primary-color: #3498db;
                    --secondary-color: #2c3e50;
                    --success-color: #2ecc71;
                    --danger-color: #e74c3c;
                    --warning-color: #f39c12;
                    --light-bg: #f8f9fa;
                    --dark-bg: #343a40;
                    --border-color: #dee2e6;
                }
                
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #f5f7f9;
                    color: #333;
                    line-height: 1.6;
                }
                
                .dashboard-container {
                    display: flex;
                    min-height: 100vh;
                }
                
                /* 侧边栏样式 */
                .sidebar {
                    width: 250px;
                    background: var(--secondary-color);
                    color: white;
                    position: fixed;
                    height: 100vh;
                    overflow-y: auto;
                }

                .sidebar-header {
                    padding: 20px;
                    background: rgba(0, 0, 0, 0.2);
                    text-align: center;
                }
                
                .sidebar-menu {
                    padding: 10px 0;
                }
                
                .menu-item {
                    padding: 12px 20px;
                    display: block;
                    color: #b8c7ce;
                    text-decoration: none;
                    transition: all 0.3s;
                }
                
                .menu-item:hover {
                    background: rgba(255, 255, 255, 0.1);
                    color: white;
                }
                
                .menu-item.active {
                    background: var(--primary-color);
                    color: white;
                    border-left: 4px solid white;
                }
                
                /* 顶部导航栏样式 */
                .top-navbar {
                    background: white;
                    padding: 0 20px;
                    height: 60px;
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                    position: fixed;
                    top: 0;
                    left: 250px;
                    right: 0;
                    z-index: 1000;
                }
                
                .main-content {
                    flex: 1;
                    margin-left: 250px;
                    padding: 80px 20px 20px;
                }
                
                .content-card {
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
                    padding: 20px;
                    margin-bottom: 20px;
                }
                
                .content-card h3 {
                    margin-bottom: 15px;
                    padding-bottom: 10px;
                    border-bottom: 1px solid var(--border-color);
                }
                
                /* 首页统计卡片 */
                .stats-container {
                    display: grid;
                    grid-template-columns: repeat(5, 1fr);
                    gap: 20px;
                    margin-bottom: 20px;
                }
                
                .stat-card {
                    background: white;
                    border-radius: 8px;
                    padding: 20px;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
                    text-align: center;
                }
                
                .stat-number {
                    font-size: 2.5rem;
                    font-weight: bold;
                    color: var(--primary-color);
                    margin: 10px 0;
                }
                
                .stat-title {
                    color: #6c757d;
                    font-size: 14px;
                }
                
                /* 规则网格 - 优化样式 */
                .rules-grid {
                    display: grid;
                    grid-template-columns: repeat(5, 1fr);
                    gap: 15px;
                    margin-top: 20px;
                }
                
                .rule-item {
                    padding: 20px 12px;
                    border-radius: 8px;
                    text-align: center;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    display: flex;
                    flex-direction: column;
                    justify-content: center;
                    align-items: center;
                    min-height: 100px;
                    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
                }

                .rule-item:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
                }

                .rule-item.on {
                    background: linear-gradient(135deg, #d4edda, #c3e6cb);
                    color: #155724;
                }

                .rule-item.off {
                    background: linear-gradient(135deg, #f8d7da, #f5c6cb);
                    color: #721c24;
                }

                .rule-item.on:hover {
                    background: linear-gradient(135deg, #c3e6cb, #b1dfbb);
                }

                .rule-item.off:hover {
                    background: linear-gradient(135deg, #f5c6cb, #f1b0b7);
                }
                
                .rule-title {
                    font-weight: bold;
                    font-size: 14px;
                    line-height: 1.3;
                    text-align: center;
                }
                
                /* 表单样式 */
                .form-group {
                    margin-bottom: 15px;
                }
                
                .form-control {
                    width: 100%;
                    padding: 10px;
                    border: 1px solid var(--border-color);
                    border-radius: 4px;
                    font-size: 14px;
                }
                
                .btn {
                    padding: 10px 15px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 14px;
                    transition: all 0.3s;
                }
                
                .btn-primary {
                    background: var(--primary-color);
                    color: white;
                }
                
                .btn-primary:hover {
                    background: #2980b9;
                }
                
                .btn-danger {
                    background: var(--danger-color);
                    color: white;
                }
                
                .btn-danger:hover {
                    background: #c0392b;
                }
                
                /* 日志样式 */
                .log-container {
                    max-height: 500px;
                    overflow-y: auto;
                }
                
                .log-item {
                    padding: 12px;
                    margin: 8px 0;
                    border: 1px solid #eee;
                    border-radius: 4px;
                    cursor: pointer;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .log-item:hover {
                    background: #f9f9f9;
                }
                
                .log-info {
                    flex: 1;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    white-space: nowrap;
                    margin-right: 15px;
                }
                
                .log-number {
                    font-weight: bold;
                    margin-right: 10px;
                    color: #666;
                    min-width: 30px;
                }
                
                .log-details {
                    display: none;
                    padding: 15px;
                    background: #f8f9fa;
                    white-space: pre-wrap;
                    font-family: monospace;
                    font-size: 12px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    margin-bottom: 10px;
                    max-height: 300px;
                    overflow-y: auto;
                }
                
                .log-status {
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: bold;
                }
                
                .status-blocked {
                    background: #f8d7da;
                    color: #721c24;
                }
                
                .status-allowed {
                    background: #d4edda;
                    color: #155724;
                }
                
                /* 分页样式 */
                .pagination {
                    margin: 20px 0;
                    text-align: center;
                }
                
                .pagination a, .pagination span {
                    display: inline-block;
                    padding: 6px 12px;
                    margin: 0 3px;
                    text-decoration: none;
                    border: 1px solid var(--border-color);
                    border-radius: 4px;
                    color: var(--primary-color);
                }
                
                .pagination .current {
                    background: var(--primary-color);
                    color: white;
                    border-color: var(--primary-color);
                }
                
                .pagination .ellipsis {
                    border: none;
                    padding: 6px 3px;
                }
                
                /* 封禁IP列表 */
                .banned-ips-list {
                    max-height: 300px;
                    overflow-y: auto;
                    margin: 10px 0;
                    padding: 10px;
                    background: #f8f9fa;
                    border-radius: 4px;
                    border: 1px solid #eee;
                }
                
                .banned-ips-list ul {
                    margin: 0;
                    padding-left: 20px;
                }
                
                .banned-ips-list li {
                    margin: 5px 0;
                    word-break: break-all;
                }
                
                /* 筛选表单样式 */
                .filter-form {
                    background: #f8f9fa;
                    padding: 16px;
                    border-radius: 8px;
                    border: 1px solid #dee2e6;
                    margin-bottom: 20px;
                }

                .filter-form .form-control {
                    width: 100%;
                    padding: 8px 12px;
                    border: 1px solid #ced4da;
                    border-radius: 4px;
                    font-size: 14px;
                    height: 36px;
                }

                .filter-form .btn {
                    height: 36px;
                    padding: 0 20px;
                    font-size: 14px;
                }

                /* 响应式设计 */
               @media (max-width: 1200px) {
                    .rules-grid {
                        grid-template-columns: repeat(4, 1fr);
                    }
                }
                
                @media (max-width: 900px) {
                    .rules-grid {
                        grid-template-columns: repeat(3, 1fr);
                    }
                }
                
                @media (max-width: 600px) {
                    .rules-grid {
                        grid-template-columns: repeat(2, 1fr);
                    }
                    
                    .rule-item {
                        padding: 15px 10px;
                        min-height: 90px;
                    }
                    
                    .rule-title {
                        font-size: 13px;
                    }
                }
                
                @media (max-width: 400px) {
                    .rules-grid {
                        grid-template-columns: 1fr;
                    }
                }
            </style>
        </head>
        <body>
            <div class="dashboard-container">
                <!-- 侧边栏 -->
                <div class="sidebar">
                    <div class="sidebar-header">
                        <h2>MiniWaf</h2>
                    </div>
                    <div class="sidebar-menu">
                        <a href="<?= $base_url ?>&page=home" class="menu-item <?= $homeClass ?>">首页</a>
                        <a href="<?= $base_url ?>&page=ip" class="menu-item <?= $ipClass ?>">IP管理</a>
                        <a href="<?= $base_url ?>&page=logs" class="menu-item <?= $logsClass ?>">日志管理</a>
                    </div>
                </div>

                <!-- 顶部导航栏 -->
                <div class="top-navbar">
                    <div class="navbar-brand">
                        <h3>控制台</h3>
                    </div>
                    <div class="navbar-menu">
                        <a href="?<?= $logoutParam ?>=1&<?= $tokenParam ?>=<?= urlencode($token) ?>" class="btn btn-danger">退出</a>
                    </div>
                </div>

                <!-- 主内容区域 -->
                <div class="main-content">
                    <?php if ($activePage == 'home'): ?>
                        <div class="content-card">
                            <h3>安全概览</h3>
                            <div class="stats-container">
                                <div class="stat-card">
                                    <div class="stat-title">封禁的IP数量</div>
                                    <div class="stat-number"><?= $active_ips_count ?></div>
                                </div>

                                <div class="stat-card">
                                    <div class="stat-title">请求总数</div>
                                    <div class="stat-number"><?= $total_entries ?></div>
                                </div>

                                <div class="stat-card">
                                    <div class="stat-title">BLOCKED总数</div>
                                    <div class="stat-number"><?= $total_blocked ?></div>
                                </div>

                                <div class="stat-card">
                                    <div class="stat-title">攻击最多的方式</div>
                                    <div class="stat-number" style="font-size: 20px;"><?= htmlspecialchars($top_attack_method) ?></div>
                                </div>

                                <div class="stat-card">
                                    <div class="stat-title">访问最多的IP</div>
                                    <div class="stat-number" style="font-size: 20px;"><?= htmlspecialchars($top_attack_ip) ?></div>
                                </div>
                            </div>
                        </div>

                        <div class="content-card">
                            <h3>防护规则状态(点击方块即可开关)</h3>
                            <div class="rules-grid">
                                <?php
                                $rules = array(
                                    'check_sql' => 'SQL注入防护',
                                    'check_rce' => '远程代码执行防护',
                                    'check_lfi' => '本地文件包含防护',
                                    'check_deserialization' => '反序列化攻击防护',
                                    'check_xss' => 'XSS攻击防护',
                                    'check_xxe' => 'XXE攻击防护',
                                    'check_ssrf' => 'SSRF攻击防护',
                                    'check_flag_file' => 'flag文件访问防护',
                                    'check_upload' => '上传检测防护'
                                );

                                foreach ($rules as $key => $name) {
                                    $status = $this->config['general'][$key] ? 'on' : 'off';
                                    ?>
                                    <div class="rule-item <?= $status ?>" onclick="updateRuleStatus('<?= $key ?>', '<?= $status ?>')">
                                        <div class="rule-title"><?= htmlspecialchars($name) ?></div>
                                    </div>
                                    <?php
                                }
                                ?>
                            </div>

                            <!-- 隐藏的表单用于提交状态更新（仅保留一份） -->
                            <form id="ruleStatusForm" method="POST" style="display: none;">
                                <input type="hidden" name="<?= $tokenParam ?>" value="<?= $token ?>">
                                <input type="hidden" name="update_rule_status" value="1">
                                <input type="hidden" name="rule_key" id="ruleKeyInput">
                                <input type="hidden" name="new_status" id="newStatusInput">
                            </form>
                        </div>

                    <?php elseif ($activePage == 'ip'): ?>
                        <div class="content-card">
                            <h3>IP管理</h3>
                            <form method="POST" class="form-group">
                                <input type="hidden" name="<?= $tokenParam ?>" value="<?= $token ?>">
                                <div class="form-group" style="display: flex; align-items: center; gap: 10px;">
                                    <div style="flex: 1; max-width: 300px;">
                                        <label>封禁IP</label>
                                        <input type="text" name="ban_ip" class="form-control" placeholder="仅支持封禁精确ip，如: 192.168.1.1" required style="width: 100%;">
                                    </div>
                                    <div style="margin-top: 24px;">
                                        <button type="submit" class="btn btn-primary">封禁</button>
                                    </div>
                                </div>
                            </form>
                        </div>

                        <div class="content-card">
                            <h3>已封禁IP列表 <span style="font-size: 14px; color: #666;">(<?= count($banned_ips) ?>个)</span></h3>
                            <div class="banned-ips-list">
                                <?php if (!empty($banned_ips)): ?>
                                    <form method="POST">
                                        <input type="hidden" name="<?= $tokenParam ?>" value="<?= $token ?>">
                                        <table style="width: 100%; border-collapse: collapse;">
                                            <thead>
                                                <tr style="background: #f8f9fa;">
                                                    <th style="padding: 8px; text-align: left; border-bottom: 1px solid #dee2e6;">IP地址</th>
                                                    <th style="padding: 8px; text-align: center; border-bottom: 1px solid #dee2e6; width: 100px;">操作</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($banned_ips as $index => $ip): ?>
                                                    <tr style="border-bottom: 1px solid #eee;">
                                                        <td style="padding: 8px;"><?= htmlspecialchars($ip) ?></td>
                                                        <td style="padding: 8px; text-align: center;">
                                                            <button type="submit" name="remove_ip" value="<?= htmlspecialchars($ip) ?>" class="btn btn-danger" style="padding: 4px 8px; font-size: 12px;" onclick="return confirm('确定要移除 <?= htmlspecialchars($ip) ?> 的封禁吗？')">移除</button>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </form>
                                <?php else: ?>
                                    <p style="margin: 0; color: #666; padding: 10px;">暂无封禁IP</p>
                                <?php endif; ?>
                            </div>
                        </div>

                    <?php elseif ($activePage == 'logs'): ?>
                        <div class="content-card">
                            <h3>日志筛选</h3>
                            <form method="GET" class="filter-form">
                                <input type="hidden" name="<?= $tokenParam ?>" value="<?= $token ?>">
                                <input type="hidden" name="<?= $dashboardParam ?>" value="1">
                                <input type="hidden" name="page" value="logs">
                                
                                <div style="display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap;">
                                    <div style="flex: 1; min-width: 280px;">
                                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                                            <label for="filter_query" style="font-weight: 500; color: #495057; font-size: 14px; margin: 0;">
                                                筛选条件 (支持: IP、BLOCKED/ALLOWED、请求方式、攻击方式、关键词搜索)
                                            </label>
                                            <?php if (!empty($filter_query)): ?>
                                                <span style="background: #e3f2fd; color: #1565c0; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 500; white-space: nowrap;">
                                                    当前筛选: "<?= htmlspecialchars($filter_query) ?>"
                                                </span>
                                            <?php endif; ?>
                                        </div>
                                        <input type="text" id="filter_query" name="filter_query" class="form-control" 
                                            value="<?= htmlspecialchars($filter_query) ?>" 
                                            placeholder="输入关键词筛选日志" 
                                            style="width: 100%; padding: 8px 12px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; height: 36px;">
                                    </div>
                                    
                                    <div style="margin-bottom: 2px;">
                                        <button type="submit" class="btn btn-primary" style="height: 36px; padding: 0 20px; font-size: 14px;">筛选</button>
                                    </div>
                                </div>
                            </form>
                        </div>

                        <div class="content-card">
                            <h3>安全日志 <span style="font-size: 14px; color: #666;">(共 <?= $total_entries ?> 条，第 <?= $log_page ?> 页)</span></h3>
                            
                            <div class="log-container">
                                <?php if ($total_entries > 0): ?>
                                    <?php foreach ($paged_entries as $index => $entry): 
                                        $logNumber = $total_entries - $offset - $index;
                                        $statusClass = ($entry['action'] === 'BLOCKED' || strpos($entry['action'], 'BLOCKED') !== false) ? 'status-blocked' : 'status-allowed';
                                    ?>
                                        <div class="log-item" onclick="toggleDetails('<?= $entry['id'] ?>')">
                                            <span class="log-number">#<?= $logNumber ?></span>
                                            <div class="log-info">
                                                [<?= $entry['time'] ?>] <?= $entry['ip'] ?> - <?= $entry['method'] ?> <?= htmlspecialchars(mb_strlen($entry['uri']) > 50 ? mb_substr($entry['uri'], 0, 50) . '...' : $entry['uri']) ?>
                                            </div>
                                            <span class="log-status <?= $statusClass ?>"><?= $entry['action'] ?></span>
                                        </div>
                                        <div id="details-<?= $entry['id'] ?>" class="log-details"><?= htmlspecialchars($entry['log']) ?></div>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <p>暂无日志</p>
                                <?php endif; ?>
                            </div>

                            <!-- 分页 -->
                            <?php if ($total_pages > 1): ?>
                                <div class="pagination">
                                    <?php if ($log_page > 1): ?>
                                        <a href="<?= $base_url ?>&page=logs&log_page=<?= $log_page - 1 ?>&filter_query=<?= urlencode($filter_query) ?>">&laquo; 上一页</a>
                                    <?php endif; ?>
                                    
                                    <?php if ($log_page > 3): ?>
                                        <a href="<?= $base_url ?>&page=logs&log_page=1&filter_query=<?= urlencode($filter_query) ?>">1</a>
                                        <?php if ($log_page > 4): ?>
                                            <span class="ellipsis">...</span>
                                        <?php endif; ?>
                                    <?php endif; ?>
                                    
                                    <?php for ($i = max(1, $log_page - 2); $i <= min($total_pages, $log_page + 2); $i++): ?>
                                        <?php if ($i == $log_page): ?>
                                            <span class="current"><?= $i ?></span>
                                        <?php else: ?>
                                            <a href="<?= $base_url ?>&page=logs&log_page=<?= $i ?>&filter_query=<?= urlencode($filter_query) ?>"><?= $i ?></a>
                                        <?php endif; ?>
                                    <?php endfor; ?>
                                    
                                    <?php if ($log_page < $total_pages - 2): ?>
                                        <?php if ($log_page < $total_pages - 3): ?>
                                            <span class="ellipsis">...</span>
                                        <?php endif; ?>
                                        <a href="<?= $base_url ?>&page=logs&log_page=<?= $total_pages ?>&filter_query=<?= urlencode($filter_query) ?>"><?= $total_pages ?></a>
                                    <?php endif; ?>
                                    
                                    <?php if ($log_page < $total_pages): ?>
                                        <a href="<?= $base_url ?>&page=logs&log_page=<?= $log_page + 1 ?>&filter_query=<?= urlencode($filter_query) ?>">下一页 &raquo;</a>
                                    <?php endif; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <script>
                let openDetailId = null;
                
                function toggleDetails(id) {
                    const el = document.getElementById('details-' + id);
                    
                    if (openDetailId === id) {
                        el.style.display = 'none';
                        openDetailId = null;
                        return;
                    }
                    
                    if (openDetailId !== null) {
                        const prevEl = document.getElementById('details-' + openDetailId);
                        if (prevEl) prevEl.style.display = 'none';
                    }
                    
                    el.style.display = 'block';
                    openDetailId = id;
                    el.scrollIntoView({behavior: 'smooth', block: 'nearest'});
                }

                window.onload = function() {
                    <?php if (isset($msg) && $msg): ?>
                    alert("<?= addslashes($msg) ?>");
                    <?php endif; ?>
                }

                function updateRuleStatus(ruleKey, currentStatus) {
                    var newStatus = currentStatus === 'on' ? 'off' : 'on';
                    document.getElementById('ruleKeyInput').value = ruleKey;
                    document.getElementById('newStatusInput').value = newStatus;
                    document.getElementById('ruleStatusForm').submit();
                }
            </script>
        </body>
        </html>
        <?php
        exit;
    }
}
new MiniWaf();