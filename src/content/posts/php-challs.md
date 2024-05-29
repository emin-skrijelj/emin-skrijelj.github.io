---
title: Php Challenges
published: 2024-05-29
description: 'In this blog I will cover a few fun but useful php tricks'
image: ''
tags: []
category: ''
draft: false 
---

# Overview

In this blog we will do some small php source code reviews in which you will hopefully learn something new and someday apply it. While writing the challenge soultions I will try to write out also some of my thinking process. We will start out first with the easiest (in my oppinion) challenge and end with the hardest one. Taking notes can be really helpful when doing anything, if you want you can take notes while reading this blog. Also my recommendation is to first try out the challenges and then read the blog post. Enjoy!

## Challenge 1

In this challenge we were supposed to bypass waf which detects all bad characters which could help us in SQL Injection. At first sight it seemed immposible to bypass...

```php
 <?php error_reporting(0);
require 'config.php';

class db extends Connection {
    public function waf($s) {
        if (preg_match_all('/'. implode('|', array(
            '[' . preg_quote("(*<=>|'&-@") . ']',
            'select', 'and', 'or', 'if', 'by', 'from', 
            'where', 'as', 'is', 'in', 'not', 'having'
        )) . '/i', $s, $matches)) die(var_dump($matches[0]));
        return json_decode($s);
    }

    public function query($sql) {
        $args = func_get_args();
        unset($args[0]);
        return parent::query(vsprintf($sql, $args));
    }
}

$db = new db();

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $obj = $db->waf(file_get_contents('php://input'));
    $db->query("SELECT note FROM notes WHERE assignee = '%s'", $obj->user);
} else {
    die(highlight_file(__FILE__, 1));
}
?> 
```
My first thought was maybe there was some regex misconfig, no luck on that one. What I like to do when doing a php challenge is that I research every php method that is being used and read its research. In this particular challenge I could figure out why json_decode() was being used, after doing some research I found out that json_decode() can also decode unicode. Nice! The bypass is fairly simple. I just unicoded my payload (simple sqli) and passed it to the php app. It worked first try :) . 


## Challenge 2

Next challenge is a little bit harder than the last one, but can still be solved just by doing some basic research.

```php
<?php

function runme() {
    if (isset($_GET['formula'])) {
        $formula = $_GET['formula'];
        if (strlen($formula) >= 150 || preg_match('/[a-z\'"]+/i', $formula)) {
            return 'Try Harder !';
        }
        try {
            eval('$calc = ' . $formula . ';');
            return isset($calc) ? $calc : '?';
        } catch (ParseError $err) {
            return 'Error';
        }
    }
}

$result = runme();
echo "Result: " . $result;

?>
``` 
The code here being short kinda makes it easy to read, but not as easy to solve... I honestly was just kinda banging my head around on using this eval() function to somehow get RCE but the regex was stoping me everytime. After reading out on some of my notes on HTB retired challenges I found out a similar challenge called __pcalc__ on hackthebox that I solved recently. Where I bypassed the same regex as here (the challenge was actually pretty much the same, even the eval sink). The bypass was to use the other way to delimit strings in php called [**Heredoc**](https://www.php.net/manual/en/language.types.string.php#language.types.string.syntax.heredoc) and [**Nowdoc**](https://www.php.net/manual/en/language.types.string.php#language.types.string.syntax.nowdoc). Also in the same docs you can see that you can use octal notation for characters which is exactly what we need so we can use letters without actually using them :) . I solved this using a script but you can do it manually.

```python
command = "yourCmdHere"
octal_bytes = [format(ord(char), 'o') for char in command]
octal_bytes_string = '\\'.join(octal_bytes)
print(f'`\\{octal_bytes_string}`')
```
This script converts your command to octal notation, now all that is left to do is add <<<_ on the start of your quoted string and finish it with _>>>. For example 

```php
<<<_\145\170\145\143_>>>(<<<_\154\163_>>>)
```

After the php does its decoding behind the scene the passed payload will look like : exec("ls") 

# Challenge 3
This challenge was on Serbian Cybersecurity Challenge finals in Belgrade. It was a pretty tough one that I did not solve on the ctf and I spent most of the time on it but sadly it was a mistake and I didn't really get to do much of the other challenges...

```php

<?php
require_once _DIR_ '/flag.php';
require_once _DIR__ . '/test.php';

$secret trim($_REQUEST['secret'] ?? 'test1');
$secrets = trim($_REQUEST['secrets'] ?? 'picture');
function picture() 
{ echo "<img src=\"source.png\" alt=\"sourceofallproblems\" />";}

$secretCheck = strcasecmp(hash('sha512', $secret), '1811d2105f3bbf78946a730955772056e472fa2737a28f840f822c2ca167f99e'); $comparisonResult = $secretCheck? 'match': 'no_match';
switch ($comparisonResult) {
    case 'match':
        function getsecret(){
            echo TEST;
        }
        function getsecret(){
            echo TEST;
            echo SECRET;
        }
        break;
    case 'no_match':
    function getsecret(){ 
        echo TEST;
    }
    break;
}

$secrets();

?>
```
Most of the time I was focusing on the $secretCheck variable and trying to bypass somehow the hash check etc... I even cracked the hash but the problem was it was comparing 512 byte hash with 256 hash. The solution was in the core of compiling and executing PHP scripts. Php uses Zend Virtual machine to compile the instructions and execute them. When PHP compiles the function that in this case is defined by a user, it uses  `zend_compile_func_decl` method:

```php
void zend_compile_func_decl(znode *result, zend_ast *ast, zend_bool toplevel) /* {{{ */
{
    ...
    zend_ast_decl *decl = (zend_ast_decl *) ast;
    zend_bool is_method = decl->kind == ZEND_AST_METHOD;
    if (is_method) {
        zend_bool has_body = stmt_ast != NULL;
        zend_begin_method_decl(op_array, decl->name, has_body);
    } else {
        zend_begin_func_decl(result, op_array, decl, toplevel);
        if (decl->kind == ZEND_AST_ARROW_FUNC) {
            find_implicit_binds(&info, params_ast, stmt_ast);
            compile_implicit_lexical_binds(&info, result, op_array);
        } else if (uses_ast) {
            zend_compile_closure_binding(result, op_array, uses_ast);
        }
    }
}
```
- Invocation of `zendparse` to execute lexical analysis, syntax analysis, and construct the Abstract Syntax Tree (AST). This step is like breaking down a sentence into individual words and understanding their meanings. So, it's breaking down the code into smaller parts and figuring out what each part does. It's like understanding the structure of a sentence.

- Utilization of `init_op_array` for `zend_compile_top_stmt` to finalize the conversion of AST into the opline array. Think of this as organizing those individual words into a meaningful order, just like arranging words into a proper sentence. Here, we're taking the smaller parts of the code and putting them together in a way that the computer can understand and execute efficiently.

- Application of `pass_two` to conclude the translation of compile-time details to runtime data and to designate the appropriate handler for each opcode. Once we have the sentence (or code) structured properly, this step is like adding extra information to make sure everything works smoothly when the code runs. It's like adding punctuation marks and instructions for how each part of the sentence should be spoken or acted upon. 

(I hope I explained it so even if you are totally new you can understand :D)





