# Operation Shadow Ledger

# Official Room Walkthrough

## Task Overview

This task guides the user through analyzing a suspicious binary (`shadowledger.bin`). It covers writing regular expressions, utilizing text modifiers, implementing performance controls, configuring advanced condition matching, and identifying file signatures.

### Question 1

**Question:** Create a regex that detects all strings beginning with `SLG:` followed by one or more alphanumeric characters.

**Answer:** `/SLG:[A-Za-z0-9]+/`

### Explanation

In YARA, regular expressions are enclosed within forward slashes `/`.

- `SLG:` matches the literal prefix text.
- `[A-Za-z0-9]` defines a character class containing all uppercase letters, lowercase letters, and numbers.
- The `+` quantifier dictates that the pattern must match *one or more* repetitions of these alphanumeric characters.

### Question 2

**Question:** How many SLG identifiers are present in the sample?

**Answer:** `3`

### Solution Rule

Code snippet

```
rule Count_SLG_Identifiers {
    strings:
        $slg = /SLG:[A-Za-z0-9]+/
    condition:
        $slg
}
```

### Execution

Run the rule using the `-s` flag to print all matched strings:

Bash :

```
yara -s slg_count.yar shadowledger.bin
```

Running the rule with the `-s` option displays all matched strings. In the sample, three SLG identifiers are returned, giving the answer `3`.

### Question 3

**Question:** The malware's primary module name is written in lowercase (`shadowledger_core`). What YARA modifier must be appended to the string definition so it matches the module name even if the threat actors change it to uppercase (`SHADOWLEDGER_CORE`) in a future sample?

**Answer:** `nocase`

### Explanation

YARA treats uppercase and lowercase characters differently by default. Adding the `nocase` modifier allows the string to match regardless of capitalization, which is useful when malware authors change the casing of strings between samples.

Code snippet

```
$module = "shadowledger_core" nocase
```

### Question 4

**Question:** To optimize performance, security analysts often restrict YARA rules so they only scan files below a certain size. What exact YARA condition syntax is used to evaluate if the total size of the file is less than 10KB?

**Answer:** `filesize < 10KB` 

### Explanation

`filesize` is a built-in YARA variable that represents the size of the file being scanned in bytes.

### Question 5

**Question:** Examine the YARA rule below:

Code snippet

```
rule OperatorDetection
{
    strings:
        $operator_ghost = "operator_ghost"
        $operator_viper = "operator_viper"
        $operator_raven = "operator_raven"

    condition:
        ???
}
```

What condition should replace `???` to ensure the rule matches only when at least two of the operator strings are present in the file?

**Answer:** `2 of ($operator*)`

### Explanation

YARA allows us to set tracking thresholds using the `X of (sets)` syntax. Because all three variables share the identical prefix `$operator`, we can group them collectively using an asterisk wildcard (`$operator*`). Requiring `2 of` ensures the rule matches only when at least two variables from that set are present.

### Question 6

**Question:** If `shadowledger.bin` is actually a compiled Windows executable disguised as a data bin file, what hexadecimal byte sequence must your YARA rule look for at the very beginning (at 0) of the file?

**Answer:** `4D 5A` *(Also accepts: `4d 5a`)*  

### Explanation

Windows Portable Executable (PE) files begin with the magic bytes `MZ` in ASCII, which translates to `4D 5A` in hexadecimal representation. In a production YARA rule, this is written as:

Code snippet

```
condition:
    uint16(0) == 0x5A4D  // Checks for MZ header at offset 0 
```

Or utilizing a hex string:

Code snippet

```
strings:
    $mz = { 4D 5A }
condition:
    $mz at 0
```

### Question 7

**Question:** You suspect the malware loops its execution or contains multiple decoy entry points. What symbol is prepended to a string variable name in the YARA condition block to count the total number of times that string appears in the binary?

**Answer:** `#`

### Explanation

Replacing the `$` prefix with a `#` symbol changes the variable from a boolean value (did it match or not) into a numeric counter representing its total match frequency. For example, checking if a string appears more than five times would look like: `#string > 5`.