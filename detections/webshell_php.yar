rule Webshell_PHP_Poc {
  meta:
    author = "xpwned"
    description = "Detects simple PHP webshell patterns"
    date = "2025-10-27"
  strings:
    $php_cmd = "<?php system("
    $php_eval = "eval("
    $php_exec = "passthru("
  condition:
    any of ($php_*)
}
