---
layout: post
title: N00bzCTF writeups
author: wizarddos
category: writeups
excerpt_separator: <!--more-->
---

Hello World!
This weekend (03.08.2024-04.08.2024) I took part in [N00bzCTF](https://ctftime.org/event/2378)

It was another event like this, that I participated in (After L3ak, OS-CTF, ECSC Quals and I guess something else)
To be honest, I enjoyed it the most out of other CTFs. 
Some challenges were pretty straight forward, some weren't, but that's how CTFs are

All right, end of my opinions
Here are my solves - I hope you'll enjoy and learn something off of them!
<!--more-->
## 1. Passwordless - Web

- Flag: `n00bz{1337-13371337-1337-133713371337-1337}`

**Solution:**
For a flag, we need to go to a directory named with UID of auser `admin123`

Yet trying to log in as admin gives us error

Why? Answer lies in the code we got from an excersise
```py
#!/usr/bin/env python3
from flask import Flask, request, redirect, render_template, render_template_string
import subprocess
import urllib
import uuid
global leet

app = Flask(__name__)
flag = open('/flag.txt').read()
leet=uuid.UUID('13371337-1337-1337-1337-133713371337')

@app.route('/',methods=['GET','POST'])
def main():
    global username
    if request.method == 'GET':
        return render_template('index.html')
    elif request.method == 'POST':
        username = request.values['username']
        if username == 'admin123':
            return 'Stop trying to act like you are the admin!'
        uid = uuid.uuid5(leet,username) # super secure!
        return redirect(f'/{uid}')

@app.route('/<uid>')
def user_page(uid):
    if uid != str(uuid.uuid5(leet,'admin123')):
        return f'Welcome! No flag for you :('
    else:
        return flag

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337)
```
We also learn that this code runs UUID in version 5, as well as it has static leet - `13371337-1337-1337-1337-133713371337`

Quick google serach lead me to [this website](https://www.uuidtools.com/v5).
I put in there username (`admin123`) and leet (`13371337-1337-1337-1337-133713371337`) - It spit out`3c68e6cc-15a7-59d4-823c-e7563bbb326c`

As I mentioned before, we need to head to `http://24.199.110.35:40150/3c68e6cc-15a7-59d4-823c-e7563bbb326c` (`/uid5`) and flag is there


## 2. Vinegar - Crypto
- Flag: `n00bz{vigenerecipherisfun}`

**Solution:**

Task Provides us with this file
```
Encrypted flag: nmivrxbiaatjvvbcjsf
Key: secretkey
```

As challenge name suggests - It's simple Vigenère cypher
With these cyphers, I always go to [CyberChef](https://gchq.github.io/CyberChef/#recipe=Vigen%C3%A8re_Decode('secretkey')&input=bm1pdnJ4YmlhYXRqdnZiY2pzZg)

I picked, Vigenère, then passed an encrypted flag, a key

And I got the second flag!

## 3. Vacation - Rev

- Flag: `n00bz{from_paris_wth_xor}`

Here, task gives us Powershell script
```ps
$bytes = [System.Text.Encoding]::ASCII.GetBytes((cat .\flag.txt))
[System.Collections.Generic.List[byte]]$newBytes = @()
$bytes.ForEach({
    $newBytes.Add($_ -bxor 3)
    })
$newString =  [System.Text.Encoding]::ASCII.GetString($newBytes)
echo $newString | Out-File -Encoding ascii .\output.txt
```
And this encoded string
```
m33ayxeqln\sbqjp\twk\{lq~
```

That script converts all characters of the flag to bytes, then performs `XOR` operation on each byte with 3 and spits out encrypted text

Another quick research -> all we need to do is perform XOR one more time, now on ciphered text and 3 (Since the inverse of `XOR` is `XOR` as well)

I wrote this simple python code to give us a flag

```py
encoded_text = "m33ayxeqln\\sbqjp\\twk\\{lq~"
encoded_bytes = encoded_text.encode('ascii')


decoded_bytes = bytes([b ^ 3 for b in encoded_bytes])
decoded_string = decoded_bytes.decode('ascii')

print(decoded_string)
```

We first convert text to ASCII then do `XOR` for each ASCII value with 3 and in the end we turn it back to UTF-8

## 4. Sanity Check - Misc

- Flag: `n00bz{w3lc0m3_t0_n00bzCTF2024!}`

I just serached for the pharse `n00bz` in N00bzCTF Discord on `#general` and there it was - as a message from mod

## 5. Agreee - Misc

- Flag: `n00bz{Terms_0f_Serv1c3s_4nd_pr1v4cy_p0l1cy_6f3a4d}`

This challange says:

```
I hope you like our Terms of Service and Privacy Policy of our website!
```

So, I head to [ToS](https://ctf.n00bzunit3d.xyz/tos) and found this - `n00bz{Terms_0f_Serv1c3s_`
And then to [privacy policy](https://ctf.n00bzunit3d.xyz/privacy) and found this - `4nd_pr1v4cy_p0l1cy_6f3a4d}`

Combining both gives us  another flag

## Conclusion

Thanks for reading this little mess. I hope you enjoyed it.

Sadly, I didn't solve any more challenges (Better luck for me next year i guess) but I'm still satisfied

I'm really looking forward to next year's edition

See you in next articles