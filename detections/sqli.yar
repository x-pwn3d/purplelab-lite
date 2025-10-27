rule SQLi
{
    meta:
        author = "x-pwned"
        description = "Detect suspicious SQLi-like patterns in logs"
        date = "2025-10-27"

    strings:
        $s1 = "-- -"        // SQL comment style
        $s2 = "1=1"         // tautology
        $s3 = "OR"          // logical OR
        $s4 = "UNION"       // UNION-based injection
        $s5 = "SLEEP"       // time-based
        $s6 = "DROP TABLE"  // destructive pattern

    condition:
        any of them
}



rule SQLi_HighConfidence {
  meta:
    author      = "x-pwned"
    description = "High-confidence SQLi indicators (tautology, UNION, time-based, comment context)"
    date        = "2025-10-27"
  strings:
    $taut1 = /OR\s+1\s*=\s*1/i
    $taut2 = /1\s*=\s*1/i
    $union = /UNION\s+SELECT/i
    $timebased = /(SLEEP|BENCHMARK)\s*\(/i
    $quote_comment = /['"][^'"]{0,50}['"]\s*--/i
  condition:
    filesize < 2000000 and (
      (any of ($taut1, $taut2, $timebased) and any of ($quote_comment)) 
      or $union
    )
}
