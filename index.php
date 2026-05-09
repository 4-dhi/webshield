<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: text/plain; charset=utf-8");

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$logFile = 'php_log.txt';

function logMessage($message) {
    global $logFile;
    $timestamp = date('Y-m-d H:i:s');
    file_put_contents($logFile, "[$timestamp] $message\n", FILE_APPEND);
}

// Check if this is a POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo "⚠️ Please send POST data with key 'url'. Example: url=https://example.com";
    exit;
}

// Check if URL is provided
if (!isset($_POST['url']) || empty(trim($_POST['url']))) {
    logMessage("ERROR: Missing URL parameter");
    echo "⚠️ Missing URL parameter";
    exit;
}

$url = trim($_POST['url']);
logMessage("Analyzing URL: $url");

// Validate URL format
if (!filter_var($url, FILTER_VALIDATE_URL)) {
    logMessage("ERROR: Invalid URL format: $url");
    echo "⚠️ Invalid URL format";
    exit;
}

// Get HTML content
$html = '';
if (isset($_POST['html']) && !empty($_POST['html'])) {
    // HTML provided by extension
    $html = $_POST['html'];
    logMessage("Using HTML from extension (" . strlen($html) . " bytes)");
} else {
    // Fetch HTML if not provided
    logMessage("Fetching HTML from URL");
    $context = stream_context_create([
        'http' => [
            'timeout' => 10,
            'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        ]
    ]);
    $html = @file_get_contents($url, false, $context);
    
    if ($html === false) {
        logMessage("ERROR: Failed to fetch content from URL: $url");
        echo "⚠️ Failed to fetch website content";
        exit;
    }
}

// Save HTML to file for Python script
$markupFile = 'markup.txt';
if (file_put_contents($markupFile, $html) === false) {
    logMessage("ERROR: Failed to save HTML to $markupFile");
    echo "⚠️ Failed to save content";
    exit;
}

logMessage("HTML saved to $markupFile (" . strlen($html) . " bytes)");

// Run Python analysis script
$escapedUrl = $url;
$command = "bash run_python.sh checkphish.py $escapedUrl 2>&1";
logMessage("Executing: $command");

$output = shell_exec($command);

if ($output === null || empty(trim($output))) {
    logMessage("ERROR: No response from Python script");
    echo "⚠️ Analysis failed - check Python script";
    exit;
}

logMessage("Python output: " . trim($output));

// Return result
$output = trim($output);
if (stripos($output, 'LEGITIMATE') !== false) {
    echo "SAFE";
} elseif (stripos($output, 'PHISHING DETECTED') !== false) {
    echo "PHISHING";
} else {
    echo "⚠️ Analysis error: " . $output;
}

logMessage("Analysis complete");
?>