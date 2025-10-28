rule SQLi_Generic {
  meta:
    author = "x-pwned"
    description = "Generic SQLi indicators (case-insensitive)"
    date = "2025-10-28"
  strings:
    $taut = /(\bOR\s+1\s*=\s*1\b|\b1\s*=\s*1\b)/i
    $union = /UNION\s+SELECT/i
    $time = /(SLEEP|BENCHMARK)\s*\(/i
    $comment = /--\s/        /* standard SQL comment */
    $drop = /DROP\s+TABLE/i
    $sql_keywords = /(\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)/i
  condition:
    any of ($taut, $union, $time, $comment, $drop) or 2 of ($sql_keywords, $taut, $union)
}

rule SQLi_HighConfidence {
  meta:
    author = "x-pwned"
    description = "High-confidence SQLi (UNION or tautology patterns)"
    date = "2025-10-28"
  strings:
    $union_sel = /UNION\s+SELECT/i
    $taut = /OR\s+1\s*=\s*1/i
  condition:
    filesize < 2000000 and ( $union_sel or $taut )
}
