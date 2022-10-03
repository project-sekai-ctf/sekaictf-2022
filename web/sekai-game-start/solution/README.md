# Writeup

PhP variable can't use `.` but this variable name is special: `sekai_game.run`. It has both `_` and `.`.

With some research, you can search sth just like use `[ .` will turn into `_`. But in older PhP version(earlier than 8), if `[` and`.` appear together, the `.` will not turn, `?sekai[game.run` is valid.

And the second step is to bypass `__wakeup`

Search it on PhP bugs

https://bugs.php.net/bug.php?id=81151

So thats the final exp `?sekai[game.run=C:10:"Sekai_Game":0:{}`