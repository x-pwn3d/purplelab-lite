rule Logs_and_Webshells {
  meta:
    author = "x-pwned"
    description = "Detect suspicious strings in logs (webshell filename, UA) or direct webshell code"
    date = "2025-10-27"
  strings:
    $s1 = "uploads/shell.php"
    $s2 = "evil-scanner"
    $php_cmd = "<?php system(" nocase
  condition:
    any of ($s1, $s2, $php_cmd)
}
