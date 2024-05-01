## Challenge Name: Slicky Tips 
Category: PPC 
Points: ~880
Solves: ~20

Challenge Description: 
(insert some russian text i don't remember lmao)

Artifact Files:
* [src] (src/)

### Observations

This challenge gives us a remote website and it's sources. Let's look at the 
website first.

The website requires an authentication at first. We can register an account
and connect to the website.

Now we are presented with some... Disturbing sentences and an interesting
"Base64" looking text. Out of this we don't really get a great idea of what
the goal in this challenge is. Maybe getting some admin accounts ???

Now let's look at the source code to clarify all that.

The server is running through Flask and has some pretty interesting endpoints !
```py
@app.route('/submit', methods=['POST','GET'])
def submit():
    global counter
    if request.method == 'GET':
        if counter >= 100:
            return render_template('submit.html', flag=FLAG)
        else:
            return render_template('submit.html', remain=100-counter)
    
    data = request.get_json()
    part_flag = data['flag']
    exist = User.query.filter(User.main_tip == part_flag).count()
    usr = User.query.filter(User.main_tip == part_flag).first()

    if exist != 0:
        usr.main_tip = "Expired"
        db.session.commit()
        counter += 1
        return jsonify({"message":"Success submit"})
    return jsonify({"message":"Invalid flag"}), 400
```

This endpoint seems like our main target since it displays the flag if 
the counter variable is higher than 100 with a GET request !

Now if we do a post request we can submit a "flag" parameter
that will be checked by querying if it's one of the users "main tip"
if it is then it sets the main tip in question to "Expired" and increments
counter by 1.

Alright so we need to find out how to get these flags ! Luckily for us
the challenge is about loading tips and we can find them in a [tips.txt](./src/app/tips.txt)
file. These are some of the sentences that are stored on your profile
when you create an account ! But only one of them still stands out and that's
the **Base64** looking values from earlier.

So I got the idea of trying to submit those as the flag and guess what ? 
It worked :D 

But as we saw in the source code, it replaces our main tip "flag" with an "Expired" text.
Now we have a pretty straight forward task. 

We need to make a script to create a 100 accounts and submit each of their flags.
After that is done we can make a GET request and obtain our flag !

### Exploitation

This is the script I made to do this exact plan : 

```py
#!/usr/bin/env python3

import requests
from tqdm import trange
import re

target = "http://24a97844-fbf1-4fd1-bd38-6fa80b7ce334.spring.mireactf.ru"

def register(username: str, password: str):
    headers = {"Content-Type": "application/json"}
    data = {"username": username, "password": password}
    req = requests.post(target + '/api/register', headers=headers, json=data)

def get_info_tip(username: str, password: str):
    s = requests.Session()
    headers = {"Content-Type": "application/json"}
    data = {"username": username, "password": password}
    req = s.post(target + '/api/login', headers=headers, json=data)
    req = s.get(target + '/api/user')
    flag = req.json()['tips'].split('\n')[-1]
    return flag

def submit(flag: str):
    headers = {"Content-Type": "application/json"}
    data = {"flag": flag}
    requests.post(target + '/submit', headers=headers, json=data)

def get_flag():
    req = requests.get(target + '/submit')
    #found = re.search(r"mireactf{[a-z0-9\-]+}", req.text).group()
    found = re.search(r"flag{[a-z0-9\-]+}", req.text).group()
    return found

for i in trange(100):
    register(str(i), str(i))
    flag = get_info_tip(str(i), str(i))
    submit(flag)

flag = get_flag()
print("[+] Flag: " + flag)
```

Running this (it takes quite a while but we have a nice loading bar for that)
We end up getting the flag and we can submit our finding !

---
[Back to home](../../README.md)
